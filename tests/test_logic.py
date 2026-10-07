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


class ExternalIp(unittest.TestCase):
    def test_ipinfo(self):
        from netcheck.extip import parse_ipinfo
        e = parse_ipinfo({"ip": "198.51.100.7", "city": "Amsterdam", "country": "NL", "org": "AS3292 TDC Holding A/S"})
        self.assertEqual((e.asn, e.operator), ("AS3292", "TDC Holding A/S"))
        self.assertEqual(e.summary, "198.51.100.7 · AS3292 TDC Holding A/S · Amsterdam, NL")

    def test_org_without_asn_and_empty(self):
        from netcheck.extip import parse_ipify, parse_ipinfo, split_org
        self.assertEqual(split_org("Some ISP"), ("", "Some ISP"))
        self.assertIsNone(parse_ipinfo({"error": "rate limit"}))
        self.assertEqual(parse_ipify({"ip": "198.51.100.7"}).summary, "198.51.100.7")

    def test_differs_diagnosis(self):
        r = report(Check("proxy", "x", "y", Status.INFO, details={"Напрямую": "A", "Через прокси": "B"},
                         tags=["extip_differs"]),
                   Check("http", "GET", "u", Status.OK, tags=["http_ok", "direct"]))
        self.assertIn("Браузер и прямое подключение выходят в интернет по-разному", titles(r))


class Udp(unittest.TestCase):
    def test_stun_xor_mapped(self):
        import struct
        from netcheck.udp import MAGIC, build_request, parse_response
        req, txid = build_request(b"0123456789ab")
        self.assertEqual(len(req), 20)
        port = 54321 ^ (MAGIC >> 16)
        ip = bytes(a ^ b for a, b in zip(socket.inet_aton("203.0.113.9"), struct.pack("!I", MAGIC)))
        attr = struct.pack("!HHBBH", 0x0020, 8, 0, 1, port) + ip
        resp = struct.pack("!HHI", 0x0101, len(attr), MAGIC) + txid + attr
        self.assertEqual(parse_response(resp, txid), ("203.0.113.9", 54321))
        self.assertIsNone(parse_response(resp, b"x" * 12))          # чужой transaction id

    def test_stun_probe_against_local_server(self):
        import struct
        import threading
        from netcheck.udp import MAGIC, probe
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(3)

        def serve():
            data, addr = srv.recvfrom(2048)
            ip = bytes(a ^ b for a, b in zip(socket.inet_aton(addr[0]), struct.pack("!I", MAGIC)))
            attr = struct.pack("!HHBBH", 0x0020, 8, 0, 1, addr[1] ^ (MAGIC >> 16)) + ip
            srv.sendto(struct.pack("!HHI", 0x0101, len(attr), MAGIC) + data[8:20] + attr, addr)

        th = threading.Thread(target=serve)
        th.start()
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # занят, но молчит
        dead.bind(("127.0.0.1", 0))
        try:
            got = probe((("127.0.0.1", srv.getsockname()[1]), ("127.0.0.1", dead.getsockname()[1])),
                        timeout=0.4, attempts=1)
        finally:
            th.join()
            srv.close()
            dead.close()
        self.assertTrue(got[0].ok)
        self.assertEqual(got[0].mapped_ip, "127.0.0.1")
        self.assertFalse(got[1].ok)
        self.assertEqual(got[1].error, "timeout")


class Quic(unittest.TestCase):
    DCID = bytes.fromhex("8394c8f03e515708")       # RFC 9001, приложение A

    def test_initial_keys_rfc9001(self):
        from netcheck.quic import initial_keys
        c, s = initial_keys(self.DCID, "client"), initial_keys(self.DCID, "server")
        self.assertEqual(c.key.hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(c.iv.hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(c.hp.hex(), "9f50449e04a0e810283a1e9933adedd2")
        self.assertEqual(s.key.hex(), "cf3a5331653c364c88f0f379b6067e37")
        self.assertEqual(s.iv.hex(), "0ac1493ca1905853b0bba03e")
        self.assertEqual(s.hp.hex(), "c206b8d9b9f0f37644430b490eeaa314")

    def test_initial_roundtrip_carries_sni(self):
        from netcheck import quic
        scid = b"\x01" * 8
        pkt = quic.build_initial(self.DCID, scid, "discord.com")
        self.assertGreaterEqual(len(pkt), 1200)                   # RFC 9000 §14.1
        self.assertNotIn(b"discord.com", pkt)                     # имя зашифровано, но ключ выводится из DCID
        p = quic.parse_packet(pkt, quic.initial_keys(self.DCID, "client"))
        self.assertEqual((p.kind, p.dcid, p.scid), ("initial", self.DCID, scid))
        self.assertEqual(p.payload[0], 0x06)                      # CRYPTO
        n, pos = quic.read_varint(p.payload, 2)
        self.assertEqual(quic.sni_of(p.payload[pos:pos + n]), "discord.com")

    def test_server_frames(self):
        from netcheck.quic import describe_frames, parse_packet, varint
        self.assertEqual(describe_frames(b"\x02\x00\x00\x00\x00" + b"\x06\x00\x01\x02")[0], "handshake")
        close = b"\x1c" + varint(0x100 + 112) + b"\x06" + varint(2) + b"no"
        kind, text = describe_frames(close)
        self.assertEqual(kind, "close")
        self.assertIn("unrecognized_name", text)
        self.assertEqual(parse_packet(b"\x00garbage").kind, "garbage")
        vn = b"\x80\x00\x00\x00\x00\x01\xaa\x01\xbb\x00\x00\x00\x01\x6b\x33\x43\xcf"
        self.assertEqual(parse_packet(vn).versions, (1, 0x6B3343CF))

    def test_varint(self):
        from netcheck.quic import read_varint, varint
        for n in (0, 63, 64, 16383, 16384, 2 ** 30 - 1, 2 ** 30):
            self.assertEqual(read_varint(varint(n), 0)[0], n)


class Speed(unittest.TestCase):
    def _r(self, **kw):
        from netcheck.speedtest import SpeedResult
        base = dict(url="u", status=200, received=4 << 20, seconds=2.0, kbps=2048.0)
        base.update(kw)
        return SpeedResult(**base)

    def test_verdicts(self):
        from netcheck.speedtest import verdict
        self.assertEqual(verdict(self._r(), self._r(kbps=1900.0))[0], "ok")
        self.assertEqual(verdict(self._r(), self._r(kbps=60.0, received=480 << 10))[0], "throttled")
        self.assertEqual(verdict(self._r(), self._r(kbps=2.0, received=16384, stalled=True))[0], "throttled")
        self.assertEqual(verdict(self._r(), self._r(status=None, received=0, kbps=None, error="reset",
                                                    error_text="tls: reset"))[0], "blocked")
        # контроль не удался — вывода нет, даже если тест «медленный»
        self.assertEqual(verdict(self._r(status=404, received=100), self._r(kbps=1.0))[0], "inconclusive")
        self.assertEqual(verdict(self._r(received=1000), self._r(kbps=1.0))[0], "inconclusive")

    def test_measure_local_http(self):
        import http.server
        import threading
        from netcheck.speedtest import measure

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/r":
                    self.send_response(302)
                    self.send_header("Location", "/blob")
                    self.end_headers()
                    return
                body = b"x" * 300_000
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = measure(f"http://localhost:{srv.server_port}/r", ip="127.0.0.1", timeout=3)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertTrue(r.ok)
        self.assertEqual((r.received, r.complete, len(r.redirects)), (300_000, True, 1))


class BlockDiagnosis(unittest.TestCase):
    def test_ip_block_when_control_ok(self):
        r = report(Check("tcp", "TCP 443", "ip", Status.FAIL, tags=["tcp_timeout", "tcp_main_timeout"]),
                   Check("tcp", "Контроль", "x", Status.INFO, tags=["control_ok"]))
        self.assertIn("Адреса сервиса недоступны, интернет работает", titles(r))

    def test_quic_filtered_but_tcp_ok(self):
        r = report(Check("tls", "TLS", "ip", Status.OK, tags=["tls_ok", "direct"]),
                   Check("udp", "QUIC", "www.youtube.com", Status.FAIL, tags=["quic_sni_filtered"]))
        self.assertIn("QUIC (HTTP/3) не проходит, TCP — проходит", titles(r))

    def test_throttling(self):
        r = report(Check("content", "Скорость", "test.googlevideo.com", Status.FAIL, "60 против 2000",
                         tags=["speed_throttled", "direct"]))
        self.assertEqual(titles(r)[0], "Замедление по имени (SNI)")

    def test_voice_bypasses_proxy(self):
        udp = Check("udp", "UDP", "интернет", Status.OK,
                    details={"В этом сервисе по UDP": "голосовые каналы", "Внешний адрес по UDP": "A",
                             "Внешний адрес через прокси (TCP)": "B"},
                    tags=["udp_needed", "udp_ok", "udp_bypasses_proxy"])
        calm = report(udp, Check("http", "GET", "u", Status.OK, tags=["http_ok", "direct"]))
        d = [x for x in diagnose(calm) if x.title == "UDP идёт мимо прокси"][0]
        self.assertEqual(d.severity, Status.INFO)                 # прямой путь свободен — не проблема
        blocked = report(udp, Check("tls", "TLS", "ip", Status.INFO, tags=["tls_fail", "tls_sni_filtered", "direct"]),
                         Check("http", "GET", "u", Status.OK, tags=["http_ok", "via_proxy"]))
        d = [x for x in diagnose(blocked) if x.title == "UDP идёт мимо прокси"][0]
        self.assertEqual(d.severity, Status.WARN)

    def test_udp_blocked(self):
        r = report(Check("udp", "UDP", "интернет", Status.WARN, tags=["udp_blocked"]))
        self.assertIn("UDP наружу не проходит", titles(r))

    def test_geo_block_by_service(self):
        r = report(Check("http", "GET", "u", Status.WARN, tags=["http_403", "direct"]),
                   Check("http", "GET", "u", Status.OK, tags=["http_ok", "via_proxy"]))
        self.assertIn("Сервис не пускает с вашего адреса", titles(r))


class Profiles(unittest.TestCase):
    def test_builtin_profiles_load(self):
        from netcheck.profiles import load_all
        ps = load_all()
        for key in ("discord", "youtube", "instagram", "github", "ya", "zai"):
            self.assertIn(key, ps)
            self.assertNotIn("ошибка", ps[key].name)
        self.assertTrue(ps["discord"].udp_needed)
        tests = ps["youtube"].speed_tests
        self.assertEqual(len(tests), 2)
        self.assertEqual({st.sni for st in tests}, {"test.googlevideo.com"})


if __name__ == "__main__":
    unittest.main()
