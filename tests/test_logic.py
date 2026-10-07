"""Тесты логики без сети: PMTU, traceroute, анализ DNS, правила диагноза, discovery.

Запуск:  python -m unittest discover -s tests -v
"""
import socket
import unittest
from unittest import mock

from netcheck import icmp
from netcheck.diagnosis import diagnose
from netcheck.discovery import discover, json_strings
from netcheck.dnscheck import Answer, DnsOutcome, _to_checks
from netcheck.model import Check, Report, Status
from netcheck.proxysettings import ProxySettings, bypassed, pac_candidates, wininet_route


def fake_echo_factory(mtu=1400, icmp_ok=True, path=("10.0.0.1", "10.0.1.1", "192.0.2.1"), dest="192.0.2.1"):
    def echo(ip, timeout_ms=1500, size=32, ttl=128, df=False):
        if not icmp_ok:
            return icmp.EchoReply("timeout", None, None)
        if df and size + 28 > mtu:
            return icmp.EchoReply("timeout", None, None)  # black hole: ответа нет вообще
        if ttl < len(path):
            return icmp.EchoReply("ttl_expired", 1.0 * ttl, path[ttl - 1])
        return icmp.EchoReply("success", 5.0, dest)
    return echo


class IcmpLogic(unittest.TestCase):
    def test_pmtu_binary_search(self):
        for mtu in (1500, 1492, 1400, 1280, 576):
            with mock.patch.object(icmp, "echo", fake_echo_factory(mtu=mtu)):
                got, _ = icmp.path_mtu_v4("192.0.2.1")
                self.assertEqual(got, mtu if mtu < 1500 else 1500, mtu)

    def test_pmtu_no_icmp(self):
        with mock.patch.object(icmp, "echo", fake_echo_factory(icmp_ok=False)):
            got, note = icmp.path_mtu_v4("192.0.2.1")
            self.assertIsNone(got)
            self.assertIn("ICMP", note)

    def test_traceroute_stops_at_destination(self):
        with mock.patch.object(icmp, "echo", fake_echo_factory()):
            hops = icmp.traceroute("192.0.2.1", max_hops=30)
        self.assertEqual([h[1] for h in hops], ["10.0.0.1", "10.0.1.1", "192.0.2.1"])
        self.assertTrue(hops[-1][3])

    def test_ping_stats(self):
        seq = iter([icmp.EchoReply("success", 10, "x"), icmp.EchoReply("timeout", None, None),
                    icmp.EchoReply("success", 20, "x"), icmp.EchoReply("success", 30, "x")])
        with mock.patch.object(icmp, "echo", lambda *a, **k: next(seq)):
            st = icmp.ping("192.0.2.1", count=4)
        self.assertEqual(st.loss_pct, 25.0)
        self.assertEqual(st.avg, 20.0)
        self.assertEqual(st.jitter, 10.0)


def dns_outcome(sys_ips, doh_ips, doh_status="ok", sys_status="ok"):
    o = DnsOutcome("example.org")
    o.answers = [Answer("Системный резолвер", "system", "A", sys_status, sys_ips),
                 Answer("Системный резолвер", "system", "AAAA", "noanswer"),
                 Answer("DoH Google", "doh", "A", doh_status, doh_ips),
                 Answer("Google (8.8.8.8)", "public", "A", "timeout")]
    _to_checks(o)
    return o


def tags(o):
    return {t for c in o.checks for t in c.tags}


class DnsAnalysis(unittest.TestCase):
    def test_consistent(self):
        self.assertIn("dns_consistent", tags(dns_outcome(["93.184.216.34"], ["93.184.216.34"])))

    def test_bogus(self):
        self.assertIn("dns_bogus", tags(dns_outcome(["0.0.0.0"], ["93.184.216.34"])))

    def test_split_horizon(self):
        self.assertIn("dns_private_vs_public", tags(dns_outcome(["10.1.2.3"], ["93.184.216.34"])))

    def test_internal_only(self):
        self.assertIn("dns_internal", tags(dns_outcome(["10.1.2.3"], [], doh_status="nxdomain")))

    def test_system_broken(self):
        self.assertIn("dns_system_broken", tags(dns_outcome([], ["93.184.216.34"], sys_status="nxdomain")))

    def test_cdn_mismatch_is_info(self):
        o = dns_outcome(["93.184.216.34"], ["93.184.216.35"])
        c = [c for c in o.checks if "dns_mismatch" in c.tags][0]
        self.assertEqual(c.status, Status.INFO)


def report(*checks, hosts=()):
    r = Report("https://x/", "ad-hoc", {})
    r.checks = list(checks)
    r.hosts = list(hosts)
    return r


def titles(r):
    return [d.title for d in diagnose(r)]


class Diagnosis(unittest.TestCase):
    def test_port_filtered_when_icmp_ok(self):
        r = report(Check("icmp", "Ping", "ip", Status.OK, tags=["icmp_ok"]),
                   Check("tcp", "TCP 443", "ip", Status.FAIL, tags=["tcp_timeout", "tcp_main_timeout"]))
        self.assertIn("TCP/443 фильтруется по пути", titles(r))

    def test_port_closed(self):
        r = report(Check("tcp", "TCP 443", "ip", Status.FAIL, tags=["tcp_refused", "tcp_main_refused"]))
        self.assertIn("Порт 443 закрыт", titles(r))

    def test_sni(self):
        r = report(Check("tcp", "TCP 443", "ip", Status.OK, tags=["tcp_ok", "tcp_main_ok"]),
                   Check("tls", "TLS", "ip", Status.FAIL, tags=["tls_net_reset", "tls_fail", "tls_sni_filtered"]))
        self.assertEqual(titles(r)[0], "Фильтрация по SNI (DPI)")

    def test_16k_stall(self):
        r = report(Check("tcp", "TCP 443", "ip", Status.OK, tags=["tcp_main_ok"]),
                   Check("content", "obj", "u", Status.FAIL, tags=["content_stall", "stall_at_16384"]))
        self.assertIn("Передача замирает после ~16 KiB", titles(r))

    def test_mtu_blackhole(self):
        r = report(Check("path", "PMTU", "ip", Status.WARN, {"MTU": 1400}, tags=["pmtu_low"]),
                   Check("content", "obj", "u", Status.FAIL, tags=["content_stall", "stall_at_16384"]))
        self.assertIn("Обрыв передачи + пониженный MTU", titles(r))

    def test_ipv6_broken(self):
        r = report(Check("tcp", "TCP 443", "a", Status.OK, family="IPv4", tags=["tcp_main_ok"]),
                   Check("tcp", "TCP 443", "b", Status.FAIL, family="IPv6", tags=["tcp_main_timeout"]))
        self.assertIn("Сломан IPv6, IPv4 работает", titles(r))

    def test_all_ok(self):
        r = report(Check("http", "GET", "u", Status.OK, tags=["http_ok"]))
        self.assertEqual(titles(r), ["Все проверенные слои в норме"])

    def test_unexplained_fail_not_lost(self):
        r = report(Check("http", "GET", "u", Status.FAIL, "странное", tags=["something_new"]))
        self.assertIn("Есть сбойные проверки", titles(r))

    def test_cancelled_run_has_no_ok_verdict(self):
        r = report(Check("dns", "A", "h", Status.OK, tags=["dns_consistent"]))
        r.cancelled = True
        t = titles(r)
        self.assertEqual(t[0], "Проверка прервана")
        self.assertNotIn("Все проверенные слои в норме", t)

    def test_icmp_blocked_is_harmless(self):
        r = report(Check("icmp", "Ping", "ip", Status.WARN, tags=["icmp_blocked"]),
                   Check("tcp", "TCP 443", "ip", Status.OK, tags=["tcp_main_ok"]),
                   Check("http", "GET", "u", Status.OK, tags=["http_ok"]))
        self.assertIn("ICMP фильтруется — это не проблема", titles(r))


class Discovery(unittest.TestCase):
    def test_resources_not_links(self):
        html = """<base href="https://e.com/app/"><script src="a.js"></script><link rel="stylesheet" href="/s.css">
        <link rel="canonical" href="https://e.com/"><a href="https://twitter.com/x">t</a>
        <img srcset="i1.png 1x, //cdn.e.com/i2.png 2x"><link rel="preconnect" href="https://fonts.e.com">"""
        res, pre = discover(html, "https://e.com/")
        urls = [u for u, _ in res]
        self.assertIn("https://e.com/app/a.js", urls)       # относительный от <base>, не от корня
        self.assertIn("https://e.com/s.css", urls)
        self.assertIn("https://cdn.e.com/i2.png", urls)
        self.assertNotIn("https://twitter.com/x", urls)
        self.assertNotIn("https://e.com/", urls)
        self.assertEqual(pre, ["fonts.e.com"])

    def test_json_strings(self):
        d = {"domains": {"website": ["a.com", "*.b.com"], "x": {"y": ["c.com"]}}, "other": ["z"]}
        self.assertEqual(sorted(json_strings(d, "domains")), ["*.b.com", "a.com", "c.com"])


class Proxy(unittest.TestCase):
    def test_wininet_protocol_specific(self):
        s = ProxySettings(wininet_enabled=True, wininet_server="http=p1:3128;https=p2:8080")
        r = wininet_route(s)
        self.assertEqual((r.proxy_host, r.proxy_port), ("p2", 8080))

    def test_bypass(self):
        self.assertTrue(bypassed("intranet", "<local>"))
        self.assertTrue(bypassed("git.corp.ru", "*.corp.ru;10.*"))
        self.assertFalse(bypassed("github.com", "*.corp.ru;<local>"))

    def test_pac(self):
        pac = 'function FindProxyForURL(u,h){ if(isPlainHostName(h)) return "DIRECT"; return "PROXY proxy.corp:3128; PROXY 10.0.0.5:8080"; }'
        self.assertEqual(pac_candidates(pac), ["proxy.corp:3128", "10.0.0.5:8080"])


if __name__ == "__main__":
    unittest.main()
