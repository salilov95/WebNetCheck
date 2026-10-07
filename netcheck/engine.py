"""Оркестратор: прогоняет все слои по порядку, шлёт события в GUI/CLI, строит отчёт."""
from __future__ import annotations

import json
import platform
import random
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from . import __version__
from . import icmp as icmpmod
from .diagnosis import diagnose
from .discovery import discover, hosts_of, json_strings
from .dnscheck import investigate
from .httpclient import HttpResult, Resolver, decode_body, parse_url, request
from .model import AssetRow, Check, HostRow, Hop, Report, Status
from .profiles import ApiProbe, Profile, expand_env, load_all
from .proxysettings import (bypassed, env_route, pac_candidates, parse_manual, read_settings,
                            wininet_route)
from .transport import DIRECT, NetError, Route, interception_marker, open_stream, tls_wrap
from .util import ERROR_TEXT, fmt_ms, human_bytes, ip_kind, is_ip_literal

ALL_CHECKS = ("proxy", "dns", "icmp", "trace", "pmtu", "tcp", "tls", "http", "hosts", "api", "content")


@dataclass
class Options:
    target: str = ""                   # URL или хост; если пусто — base_url профиля
    profile: str | None = None
    family: str = "auto"               # auto | v4 | v6
    route: str = "direct"              # direct | system | manual | both
    proxy: str = ""                    # host:port для route=manual (или both, если задан)
    forced_ip: str = ""                # подменить DNS для основного хоста
    ports: list[int] = field(default_factory=lambda: [443, 80])
    checks: list[str] = field(default_factory=lambda: list(ALL_CHECKS))
    public_dns: bool = True
    doh: bool = True
    asset_count: int | None = None
    min_asset_size: int | None = None
    max_asset_size: int = 25 * 1024 * 1024
    range_size: int | None = None
    timeout: float = 8.0
    stall_timeout: float = 15.0
    download_timeout: float = 90.0
    max_hosts: int = 80
    ca_file: str | None = None
    ping_count: int = 4

    def enabled(self, name: str) -> bool:
        return name in self.checks


def normalize_target(t: str) -> str:
    t = t.strip()
    if not t:
        return ""
    if not re.match(r"^[a-z]+://", t, re.I):
        t = "https://" + t
    u = urlsplit(t)
    if not u.path:
        t += "/"
    return t


class Engine:
    """Один прогон диагностики. Запускать run() в фоновом потоке."""

    STAGES = ["Среда и прокси", "DNS", "ICMP и маршрут", "TCP", "TLS", "HTTP", "Зависимости",
              "API-пробы", "Целостность контента", "Диагноз"]

    def __init__(self, opts: Options, on_event=None, profiles: dict[str, Profile] | None = None):
        self.o = opts
        self.emit = on_event or (lambda kind, payload: None)
        self.cancel = threading.Event()
        self.profiles = profiles if profiles is not None else load_all()
        self.profile: Profile | None = self.profiles.get(opts.profile) if opts.profile else None
        self.report: Report | None = None
        self._lock = threading.Lock()

    # --- события -----------------------------------------------------------
    def _check(self, c: Check) -> Check:
        with self._lock:
            self.report.checks.append(c)
        self.emit("check", c)
        return c

    def _log(self, msg: str):
        self.emit("log", msg)

    def _stage(self, idx: int):
        self.emit("stage", (idx, len(self.STAGES), self.STAGES[idx]))

    def stop(self):
        self.cancel.set()

    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()

    # --- основной сценарий -------------------------------------------------
    def run(self) -> Report:
        o = self.o
        p = self.profile
        base_url = normalize_target(o.target) or (p.base_url if p else "")
        opts_dump = asdict(o)
        self.report = Report(target=base_url, profile=p.name if p else "ad-hoc", options=opts_dump)
        try:
            if not base_url:
                raise ValueError("не задан адрес: укажите URL/хост или выберите профиль")
            self.t = parse_url(base_url)
            self.base_url = base_url
            self.overrides = {self.t.host.lower(): o.forced_ip.strip()} if o.forced_ip.strip() else {}
            self._run_all()
        except Exception as e:  # noqa: BLE001
            self._check(Check("http", "Запуск проверки", base_url or "-", Status.FAIL,
                              f"не удалось начать: {e}", tags=["fatal"]))
        self.report.cancelled = self.cancelled
        self._stage(9)
        try:
            self.report.diagnosis = diagnose(self.report)
        except Exception as e:  # noqa: BLE001
            self._log(f"ошибка построения диагноза: {e}")
        self.report.finished = time.time()
        self.emit("done", self.report)
        return self.report

    def _run_all(self):
        o, t = self.o, self.t
        self._stage(0)
        self._environment()
        self.routes = self._routes()
        self.primary = self.routes[0]
        if self.cancelled:
            return

        # DNS
        self._stage(1)
        want_v6 = o.family in ("auto", "v6")
        if o.enabled("dns"):
            dns_out = investigate(t.host, want_v6=want_v6, route=self.primary, public=o.public_dns, doh=o.doh,
                                  ca_file=o.ca_file, cancel=self.cancel, overrides=self.overrides)
            for c in dns_out.checks:
                self._check(c)
            v4, v6 = dns_out.system_v4, dns_out.system_v6
        else:
            v4, v6 = self._quick_resolve(t.host)
        self.addrs = {"IPv4": v4 if o.family in ("auto", "v4") else [],
                      "IPv6": v6 if o.family in ("auto", "v6") else []}
        if o.family == "v6" and not v6:
            self._check(Check("dns", "Адреса IPv6", t.host, Status.FAIL, "нет AAAA — проверка по IPv6 невозможна",
                              tags=["no_aaaa"]))
        self.local = {"IPv4": self._has_route("IPv4"), "IPv6": self._has_route("IPv6")}
        if self.addrs["IPv6"] and not self.local["IPv6"]:
            self._check(Check("path", "IPv6 на этом компьютере", "локально", Status.INFO,
                              "нет маршрута IPv6 — проверки по IPv6 пропущены", tags=["local_no_ipv6"]))
            self.addrs["IPv6"] = []
        if self.cancelled:
            return

        # ICMP / traceroute / PMTU — всегда напрямую
        self._stage(2)
        self._icmp_layer()
        if self.cancelled:
            return

        self._stage(3)
        if o.enabled("tcp"):
            self._tcp_layer()
        if self.cancelled:
            return

        self._stage(4)
        if o.enabled("tls") and t.is_https:
            self._tls_layer()
        if self.cancelled:
            return

        self._stage(5)
        self.main_page: HttpResult | None = None
        if o.enabled("http") or o.enabled("hosts") or o.enabled("content"):
            self._http_layer()
        if self.cancelled:
            return

        self._stage(6)
        self.resources: list[tuple[str, str]] = []
        if self.main_page is not None and self.main_page.body:
            self._discover()
        if o.enabled("hosts"):
            self._hosts_layer()
        if self.cancelled:
            return

        self._stage(7)
        if o.enabled("api"):
            self._api_layer()
        if self.cancelled:
            return

        self._stage(8)
        if o.enabled("content"):
            self._content_layer()

    # --- среда ------------------------------------------------------------
    def _environment(self):
        env = {
            "WebNetCheck": __version__,
            "Компьютер": socket.gethostname(),
            "ОС": f"{platform.system()} {platform.release()} ({platform.version()})",
            "Python": platform.python_version(),
        }
        for fam, probe in (("IPv4", "8.8.8.8"), ("IPv6", "2001:4860:4860::8888")):
            env[f"Исходящий {fam}"] = self._source_ip(fam, probe) or "нет маршрута"
        try:
            from .dnscheck import configured_servers
            env["DNS-серверы"] = ", ".join(configured_servers()) or "-"
        except Exception:  # noqa: BLE001
            pass
        self.report.environment = env
        self._log("Среда: " + "; ".join(f"{k}={v}" for k, v in env.items()))

    @staticmethod
    def _source_ip(fam: str, probe: str) -> str | None:
        af = socket.AF_INET6 if fam == "IPv6" else socket.AF_INET
        try:
            s = socket.socket(af, socket.SOCK_DGRAM)
            s.connect((probe, 53))  # UDP connect не шлёт пакетов — только выбирает маршрут
            ip = s.getsockname()[0]
            s.close()
            if ip_kind(ip) == "linklocal":
                return None
            return ip
        except OSError:
            return None

    def _has_route(self, fam: str) -> bool:
        return bool(self._source_ip(fam, "8.8.8.8" if fam == "IPv4" else "2001:4860:4860::8888"))

    def _routes(self) -> list[Route]:
        o = self.o
        settings = read_settings()
        self.proxy_settings = settings
        system = wininet_route(settings)
        if settings.pac_url:
            r = request(settings.pac_url, timeout=5, total_timeout=8, read_limit=512 * 1024, ca_file=o.ca_file)
            if r.ok and r.status == 200:
                settings.pac_candidates = pac_candidates(decode_body(r))
            else:
                settings.notes.append(f"PAC не загрузился: {r.error_text or r.status}")
        if o.enabled("proxy"):
            d = {"WinINET включён": settings.wininet_enabled, "WinINET сервер": settings.wininet_server or "-",
                 "Исключения": settings.wininet_bypass or "-", "PAC (AutoConfigURL)": settings.pac_url or "-",
                 "Автоопределение (WPAD)": settings.auto_detect,
                 "Прокси из PAC": ", ".join(settings.pac_candidates) or "-",
                 "WinHTTP": settings.winhttp_text or "-",
                 "Переменные окружения": settings.env or "-"}
            if settings.pac_url:
                summary = f"PAC: {settings.pac_url}"
            elif system:
                summary = f"системный прокси {system.proxy_host}:{system.proxy_port}"
            else:
                summary = "прокси не настроен — прямое подключение"
            if system and bypassed(self.t.host, settings.wininet_bypass):
                summary += f" (но {self.t.host} в исключениях)"
            self._check(Check("proxy", "Системные настройки прокси", "Windows", Status.INFO, summary, d))
            if settings.pac_url:
                self._check(Check("proxy", "Логика PAC", settings.pac_url, Status.INFO,
                                  "PAC-скрипт не исполняется; для «Через системный» берётся первый PROXY из файла",
                                  {"Найдено": settings.pac_candidates or "ничего"}))
        manual = parse_manual(o.proxy) if o.proxy.strip() else None
        sysroute = system
        if not sysroute and settings.pac_candidates:
            pr = parse_manual(settings.pac_candidates[0])
            if pr:
                pr.origin = "pac"
                sysroute = pr
        if not sysroute:
            sysroute = env_route(settings)

        def need(r: Route | None, what: str) -> Route:
            if r is None:
                self._check(Check("proxy", "Маршрут проверки", what, Status.WARN,
                                  f"{what}: прокси не найден/не задан — проверяю напрямую", tags=["proxy_missing"]))
                return DIRECT
            return r

        if o.route == "system":
            routes = [need(sysroute, "системный прокси")]
        elif o.route == "manual":
            routes = [need(manual, "ручной прокси")]
        elif o.route == "both":
            pr = manual or sysroute
            routes = [need(pr, "прокси для сравнения"), DIRECT] if pr else [DIRECT]
        else:
            routes = [DIRECT]
        uniq: list[Route] = []
        for r in routes:
            if r not in uniq:
                uniq.append(r)
        if uniq[0].is_proxy:
            self._log(f"Основной маршрут: {uniq[0].label} ({uniq[0].origin})")
        return uniq

    def _quick_resolve(self, host: str) -> tuple[list[str], list[str]]:
        if host.lower() in self.overrides:
            ip = self.overrides[host.lower()]
            return ([ip], []) if ":" not in ip else ([], [ip])
        if is_ip_literal(host):
            h = host.strip("[]")
            return ([h], []) if ":" not in h else ([], [h])
        v4, v6 = [], []
        for fam, lst in ((socket.AF_INET, v4), (socket.AF_INET6, v6)):
            try:
                for i in socket.getaddrinfo(host, 443, fam, socket.SOCK_STREAM):
                    if i[4][0] not in lst:
                        lst.append(i[4][0])
            except OSError:
                pass
        return v4, v6

    @property
    def _direct_optional(self) -> bool:
        """Работаем только через прокси — прямой доступ не обязателен."""
        return self.primary.is_proxy and len(self.routes) == 1

    def _families(self):
        for fam in ("IPv4", "IPv6"):
            if self.addrs.get(fam):
                yield fam, self.addrs[fam]

    def _soft(self, st: Status) -> Status:
        """Сбой прямой проверки при работе через прокси — не ошибка, а факт."""
        return Status.INFO if (self._direct_optional and st == Status.FAIL) else st

    # --- ICMP / маршрут -----------------------------------------------------
    def _icmp_layer(self):
        o = self.o
        for fam, ips in self._families():
            ip = ips[0]
            if o.enabled("icmp"):
                try:
                    st = icmpmod.ping(ip, count=o.ping_count, cancel=self.cancel)
                except icmpmod.IcmpUnavailable as e:
                    self._check(Check("icmp", f"Ping {fam}", ip, Status.SKIP, f"ICMP недоступен: {e}", family=fam))
                    continue
                d = {"Отправлено": st.sent, "Получено": st.received, "Потери": f"{st.loss_pct:.0f}%",
                     "RTT avg": fmt_ms(st.avg), "RTT min/max": f"{fmt_ms(min(st.rtts))} / {fmt_ms(max(st.rtts))}"
                     if st.rtts else "-", "Джиттер": fmt_ms(st.jitter),
                     "Статусы": ", ".join(icmpmod.STATUS_TEXT.get(s, s) for s in dict.fromkeys(st.statuses))}
                if st.received == st.sent:
                    status, summ, tags = Status.OK, f"0% потерь, avg {fmt_ms(st.avg)}", ["icmp_ok"]
                elif st.received:
                    status, summ, tags = Status.WARN, f"потери {st.loss_pct:.0f}%, avg {fmt_ms(st.avg)}", ["icmp_loss"]
                else:
                    status = Status.WARN
                    tags = ["icmp_blocked"]
                    summ = "нет ответов — ICMP фильтруется или хост недоступен"
                    if any(s in ("host_unreachable", "net_unreachable") for s in st.statuses):
                        tags.append("icmp_unreachable")
                        summ = "ICMP unreachable — нет маршрута до хоста"
                self._check(Check("icmp", f"Ping {fam}", ip, status, summ, d, st.avg, fam, tags))
            if self.cancelled:
                return
            if o.enabled("trace"):
                self._trace(fam, ip)
            if self.cancelled:
                return
            if o.enabled("pmtu"):
                if fam == "IPv4":
                    try:
                        mtu, note = icmpmod.path_mtu_v4(ip, cancel=self.cancel)
                    except icmpmod.IcmpUnavailable as e:
                        self._check(Check("path", "Path MTU", ip, Status.SKIP, str(e), family=fam))
                        continue
                    if mtu is None:
                        self._check(Check("path", "Path MTU (DF)", ip, Status.SKIP, note, family=fam,
                                          tags=["pmtu_unknown"]))
                    elif mtu >= 1500:
                        self._check(Check("path", "Path MTU (DF)", ip, Status.OK, f"{mtu} байт", {"Пояснение": note},
                                          family=fam, tags=["pmtu_ok"]))
                    else:
                        self._check(Check("path", "Path MTU (DF)", ip, Status.WARN,
                                          f"{mtu} байт < 1500 — туннель/PPPoE/VPN на пути",
                                          {"Пояснение": note, "MTU": mtu}, family=fam, tags=["pmtu_low"]))
                else:
                    self._check(Check("path", "Path MTU (DF)", ip, Status.SKIP,
                                      "для IPv6 ОС фрагментирует сама — поиск через ICMP недостоверен", family=fam))

    def _trace(self, fam: str, ip: str):
        try:
            raw = icmpmod.traceroute(ip, cancel=self.cancel)
        except icmpmod.IcmpUnavailable as e:
            self._check(Check("path", f"Traceroute {fam}", ip, Status.SKIP, f"ICMP недоступен: {e}", family=fam))
            return
        names: dict[str, str | None] = {}
        hop_ips = sorted({h[1] for h in raw if h[1]})

        def rdns(a):
            try:
                return a, socket.gethostbyaddr(a)[0]
            except OSError:
                return a, None

        if hop_ips and not self.cancelled:
            with ThreadPoolExecutor(max_workers=8) as ex:
                futs = [ex.submit(rdns, a) for a in hop_ips]
                for f in futs:
                    try:
                        a, n = f.result(timeout=3)
                        names[a] = n
                    except Exception:  # noqa: BLE001
                        pass
        hops = []
        for ttl, hip, rtt, reached in raw:
            h = Hop(fam, ttl, hip, rtt, names.get(hip) if hip else None, reached)
            hops.append(h)
            self.report.hops.append(h)
            self.emit("hop", h)
        reached = any(h.reached for h in hops)
        answered = [h for h in hops if h.ip]
        last = answered[-1] if answered else None
        d = {"Хопов": len(hops), "Ответили": len(answered),
             "Последний ответивший": f"#{last.ttl} {last.ip} {last.name or ''}".strip() if last else "-"}
        if reached:
            self._check(Check("path", f"Traceroute {fam}", ip, Status.OK, f"цель достигнута за {len(hops)} хоп(ов)",
                              d, family=fam, tags=["trace_ok"]))
        else:
            self._check(Check("path", f"Traceroute {fam}", ip, Status.INFO,
                              f"цель не ответила; последний хоп #{last.ttl} {last.ip}" if last else
                              "ни один хоп не ответил (ICMP закрыт)", d, family=fam,
                              tags=["trace_incomplete"]))

    # --- TCP ----------------------------------------------------------------
    def _tcp_layer(self):
        o, t = self.o, self.t
        ports = list(dict.fromkeys([t.port] + (self.profile.tcp_ports if self.profile and self.profile.tcp_ports
                                               else o.ports)))
        jobs = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            for fam, ips in self._families():
                for ip in ips[:2]:
                    for port in ports:
                        jobs.append((fam, ip, port, ex.submit(self._tcp_one, ip, port)))
            for fam, ip, port, f in jobs:
                ms, code, text = f.result()
                main = port == t.port
                if code is None:
                    self._check(Check("tcp", f"TCP {port}", ip, Status.OK, f"соединение за {fmt_ms(ms)}",
                                      {"Адрес": f"{ip}:{port}"}, ms, fam, ["tcp_ok"] + (["tcp_main_ok"] if main else [])))
                else:
                    st = Status.FAIL if main else Status.WARN
                    if code == "refused":
                        hint = "хост жив и отвечает RST: порт закрыт или отклонён фильтром"
                    elif code == "timeout":
                        hint = "SYN без ответа: пакеты отбрасываются (firewall/DROP) или хост лежит"
                    else:
                        hint = ERROR_TEXT.get(code, text)
                    self._check(Check("tcp", f"TCP {port}", ip, self._soft(st), hint,
                                      {"Адрес": f"{ip}:{port}", "Ошибка": text, "Код": code}, ms, fam,
                                      [f"tcp_{code}"] + ([f"tcp_main_{code}"] if main else [])))

    def _tcp_one(self, ip, port):
        t0 = time.perf_counter()
        try:
            s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.o.timeout)
            s.connect((ip, port))
            ms = (time.perf_counter() - t0) * 1000
            s.close()
            return ms, None, ""
        except OSError as e:
            from .util import classify_error
            return (time.perf_counter() - t0) * 1000, classify_error(e), str(e)

    # --- TLS ----------------------------------------------------------------
    def _tls_layer(self):
        t = self.t
        sni = None if is_ip_literal(t.host) else t.host
        targets: list[tuple[str | None, Route, str | None]] = []
        for r in self.routes:
            if r.is_proxy:
                targets.append((None, r, None))
            else:
                for fam, ips in self._families():
                    targets.append((fam, r, ips[0]))
        for fam, route, ip in targets:
            if self.cancelled:
                return
            self._tls_one(fam, route, ip, sni)

    def _tls_session(self, route, ip, sni, verify=True, only=None):
        sock, _ = open_stream(route, self.t.host, self.t.port, ip, self.o.timeout)
        ss, info = tls_wrap(sock, sni, self.o.timeout, verify=verify, only=only, ca_file=self.o.ca_file)
        try:
            ss.close()
        except OSError:
            pass
        return info

    def _tls_one(self, fam, route, ip, sni):
        t = self.t
        label = f"TLS {fam or ''} {'· ' + route.label if route.is_proxy else ''}".replace("  ", " ").strip()
        target = ip or t.host
        tags_route = ["via_proxy"] if route.is_proxy else ["direct"]
        try:
            info = self._tls_session(route, ip, sni)
        except NetError as e:
            if e.phase in ("tcp", "proxy"):
                self._check(Check("tls", label, target, self._soft(Status.FAIL) if not route.is_proxy else Status.FAIL,
                                  f"до TLS не дошли: {e.phase} — {ERROR_TEXT.get(e.code, e.text)}",
                                  {"Ошибка": e.text}, family=fam, tags=[f"tls_pre_{e.code}", f"{e.phase}_fail"] + tags_route))
                return
            if e.code == "tls_verify":
                self._tls_verify_failed(fam, route, ip, sni, label, target, e, tags_route)
                return
            # сетевой обрыв на рукопожатии — проверяем фильтрацию по SNI
            d = {"Ошибка": e.text, "Код": e.code}
            sni_tag = []
            if sni and e.code in ("reset", "timeout", "eof", "tls_proto", "aborted"):
                alt = self._sni_probe(route, ip)
                d["Рукопожатие с нейтральным SNI"] = alt
                if alt.startswith("OK"):
                    sni_tag = ["tls_sni_filtered"]
            self._check(Check("tls", label, target, self._soft(Status.FAIL) if not route.is_proxy else Status.FAIL,
                              f"рукопожатие сорвано: {ERROR_TEXT.get(e.code, e.text)}"
                              + (" — похоже на фильтрацию по SNI" if sni_tag else ""),
                              d, family=fam, tags=[f"tls_net_{e.code}", "tls_fail"] + sni_tag + tags_route))
            return
        self._tls_report(fam, route, ip, label, target, info, tags_route)
        # Матрица версий — ловит DPI, ломающие только TLS 1.3 (или наоборот)
        for ver in ("1.2", "1.3"):
            try:
                vinfo = self._tls_session(route, ip, sni, verify=False, only=ver)
                vlabel = f"Только TLS {ver}" + (f" · {route.label}" if route.is_proxy else "")
                self._check(Check("tls", vlabel, target, Status.OK,
                                  f"{vinfo.cipher} за {fmt_ms(vinfo.handshake_ms)}", {"Шифр": vinfo.cipher},
                                  vinfo.handshake_ms, fam, [f"tls{ver.replace('.', '')}_ok"] + tags_route))
            except NetError as e:
                proto = e.code == "tls_proto" and any(w in e.text.lower() for w in ("version", "protocol"))
                st = Status.INFO if proto else Status.WARN
                why = "сервер не поддерживает эту версию" if proto else ERROR_TEXT.get(e.code, e.text)
                vlabel = f"Только TLS {ver}" + (f" · {route.label}" if route.is_proxy else "")
                self._check(Check("tls", vlabel, target, st, why, {"Ошибка": e.text}, family=fam,
                                  tags=[f"tls{ver.replace('.', '')}_{'unsupported' if proto else 'fail'}"] + tags_route))

    def _sni_probe(self, route, ip) -> str:
        results = []
        for alt in ("www.example.com", None):
            try:
                info = self._tls_session(route, ip, alt, verify=False)
                return f"OK с SNI={alt or 'без SNI'} ({info.version}) — путь до сервера жив, режется именно имя"
            except NetError as e:
                results.append(f"SNI={alt or 'без SNI'}: {ERROR_TEXT.get(e.code, e.code)}")
        return "тоже не работает: " + "; ".join(results)

    def _tls_verify_failed(self, fam, route, ip, sni, label, target, e, tags_route):
        d = {"Ошибка проверки": e.text}
        tags = ["tls_verify"] + tags_route
        reason = "сертификат не прошёл проверку"
        try:
            info = self._tls_session(route, ip, sni, verify=False)
            c = info.cert
            d.update(self._cert_details(info))
            if c.get("days_left", 1) < 0:
                reason, tags = f"сертификат истёк {c.get('not_after')}", tags + ["tls_expired"]
            elif c.get("name_match") is False:
                reason, tags = f"сертификат выдан не на {sni}", tags + ["tls_name_mismatch"]
            elif c.get("self_signed"):
                reason, tags = "самоподписанный сертификат", tags + ["tls_untrusted"]
            else:
                reason, tags = f"недоверенный издатель: {c.get('issuer')}", tags + ["tls_untrusted"]
            m = interception_marker(c.get("issuer", ""))
            if m:
                tags.append("tls_intercept")
                reason += f" — трафик перехватывает {m}"
        except NetError:
            pass
        self._check(Check("tls", label, target, Status.FAIL, reason, d, family=fam, tags=tags))

    @staticmethod
    def _cert_details(info) -> dict:
        c = info.cert
        d = {"Версия": info.version, "Шифр": info.cipher, "ALPN": info.alpn or "-", "SNI": info.sni or "-",
             "Субъект": c.get("subject", "-"), "Издатель": c.get("issuer", "-"),
             "Действителен": f"{c.get('not_before', '?')} — {c.get('not_after', '?')} "
                             f"(осталось {c.get('days_left', '?')} дн.)",
             "Ключ / подпись": f"{c.get('key', '?')} / {c.get('signature', '?')}",
             "SAN": ", ".join(c.get("san", [])[:12]) + (f" … всего {c.get('san_count')}" if c.get("san_count", 0) > 12 else "")}
        if info.chain:
            d["Цепочка"] = info.chain
        if c.get("note"):
            d["Примечание"] = c["note"]
        return d

    def _tls_report(self, fam, route, ip, label, target, info, tags_route):
        c = info.cert
        d = self._cert_details(info)
        tags = ["tls_ok"] + tags_route
        status = Status.OK
        summ = f"{info.version}, {info.cipher}, ALPN {info.alpn or '-'}, {fmt_ms(info.handshake_ms)}"
        days = c.get("days_left")
        if isinstance(days, int) and days < 14:
            status = Status.WARN
            tags.append("tls_expiring")
            summ += f" · сертификат истекает через {days} дн."
        m = interception_marker(c.get("issuer", ""))
        if m:
            status = Status.WARN
            tags.append("tls_intercept")
            summ += f" · сертификат выдан {c.get('issuer')} — TLS перехватывается ({m})"
        if info.version in ("TLSv1", "TLSv1.1"):
            status = Status.WARN
            summ += " · устаревшая версия TLS"
        self._check(Check("tls", label, target, status, summ, d, info.handshake_ms, fam, tags))

    # --- HTTP ---------------------------------------------------------------
    def _http_layer(self):
        o = self.o
        variants: list[tuple[str | None, Route, str | None]] = []
        for r in self.routes:
            if r.is_proxy:
                variants.append((None, r, None))
            else:
                for fam, ips in self._families():
                    variants.append((fam, r, ips[0]))
        if not variants:
            self._check(Check("http", "HTTP", self.base_url, Status.FAIL, "нет адресов для подключения",
                              tags=["http_no_addr"]))
            return
        for fam, route, ip in variants:
            if self.cancelled:
                return
            fam_af = socket.AF_INET6 if fam == "IPv6" else (socket.AF_INET if fam == "IPv4" else 0)
            r = request(self.base_url, route=route, ip=ip, resolver=Resolver(fam_af, self.overrides),
                        timeout=o.timeout, total_timeout=o.timeout * 3, stall_timeout=o.stall_timeout,
                        ca_file=o.ca_file, cancel=self.cancel)
            self._http_check(r, fam, route)
            if self.main_page is None and r.ok and r.body:
                self.main_page = r

    def _http_check(self, r: HttpResult, fam, route):
        label = f"GET {fam or ''} {'· ' + route.label if route.is_proxy else ''}".replace("  ", " ").strip()
        tags = ["via_proxy"] if route.is_proxy else ["direct"]
        ph = r.phases
        d = {"URL": r.url, "Итоговый URL": r.final_url, "IP": r.ip or "-", "Маршрут": r.route,
             "Фазы": " · ".join(f"{k} {fmt_ms(v)}" for k, v in ph.items() if k != "total"),
             "Всего": fmt_ms(ph.get("total"))}
        if r.redirects:
            d["Редиректы"] = [f"{c} → {u}" for c, u in r.redirects]
        if r.status is not None:
            d["Ответ"] = f"{r.http_version} {r.status} {r.reason}"
            d["Тело"] = f"{human_bytes(r.body_len)}" + (f" из {human_bytes(r.content_length)}" if r.content_length else "")
            for h in ("server", "content-type", "via", "x-cache", "cf-ray", "x-served-by", "alt-svc", "location"):
                if r.header(h):
                    d[f"H: {h}"] = r.header(h)
        if r.error_code:
            d["Ошибка"] = f"{r.error_phase}: {r.error_text}"
            st = Status.FAIL
            summ = f"сбой на фазе {r.error_phase}: {ERROR_TEXT.get(r.error_code, r.error_text)}"
            tags += [f"http_err_{r.error_code}", f"http_phase_{r.error_phase}"]
            if r.status is not None:
                summ = f"HTTP {r.status}, но тело оборвано: {r.error_text}"
                tags.append("http_body_broken")
            self._check(Check("http", label, r.url, self._soft(st) if not route.is_proxy else st, summ, d,
                              ph.get("total"), fam, tags))
            return
        code = r.status
        if code >= 500:
            st, summ = Status.FAIL, f"HTTP {code} {r.reason} — ошибка на стороне сервиса"
            tags.append("http_5xx")
        elif code == 451:
            st, summ = Status.FAIL, "HTTP 451 — недоступно по юридическим причинам (блокировка)"
            tags.append("http_451")
        elif code in (401, 403, 407, 429):
            st, summ = Status.WARN, f"HTTP {code} {r.reason} — сервис отвечает, но не пускает"
            tags.append(f"http_{code}")
        elif code >= 400:
            st, summ = Status.WARN, f"HTTP {code} {r.reason}"
            tags.append("http_4xx")
        else:
            st, summ = Status.OK, f"HTTP {code} за {fmt_ms(ph.get('total'))} (TTFB {fmt_ms(ph.get('ttfb'))})"
            tags.append("http_ok")
        if r.redirects:
            summ += f", редиректов: {len(r.redirects)}"
        self._check(Check("http", label, r.url, st, summ, d, ph.get("total"), fam, tags))
        alt = r.header("alt-svc") or ""
        if "h3" in alt and not any("quic_advertised" in c.tags for c in self.report.checks):
            self._check(Check("http", "HTTP/3 (QUIC)", r.final_url, Status.INFO,
                              "сервер анонсирует HTTP/3: браузер может пойти по UDP/443 — здесь проверяется TCP",
                              {"Alt-Svc": alt}, tags=["quic_advertised"]))

    # --- зависимости ----------------------------------------------------------
    def _discover(self):
        page = self.main_page
        html = decode_body(page)
        self.resources, preconnect = discover(html, page.final_url or self.base_url)
        self.preconnect_hosts = preconnect
        self._log(f"Найдено ресурсов: {len(self.resources)}, хостов: {len(hosts_of(u for u, _ in self.resources))}")

    def _hosts_layer(self):
        o, p = self.o, self.profile
        main = self.t.host.lower()
        src: dict[str, str] = {main: "основной"}
        for h in (p.static_hosts if p else []):
            src.setdefault(h.lower(), "профиль")
        if (p is None or p.discover_html) and self.resources:
            for h in hosts_of(u for u, _ in self.resources):
                src.setdefault(h, "страница")
            for h in getattr(self, "preconnect_hosts", []):
                src.setdefault(h.lower(), "preconnect")
        if p and p.metadata_url:
            r = request(p.metadata_url, route=self.primary, timeout=o.timeout, total_timeout=o.timeout * 2,
                        ca_file=o.ca_file, resolver=Resolver(overrides=self.overrides))
            meta_hosts = []
            if r.ok and r.status == 200:
                try:
                    vals = json_strings(json.loads(decode_body(r)), p.metadata_path)
                    meta_hosts = sorted({v.lstrip(".").lower() for v in vals
                                         if "*" not in v and re.fullmatch(r"[A-Za-z0-9._-]+", v.lstrip("."))})
                    self._check(Check("hosts", "Метаданные сервиса", p.metadata_url, Status.OK,
                                      f"получено {len(meta_hosts)} хостов", {"Хосты": meta_hosts[:60]}))
                except ValueError as e:
                    self._check(Check("hosts", "Метаданные сервиса", p.metadata_url, Status.WARN, f"не JSON: {e}"))
            else:
                self._check(Check("hosts", "Метаданные сервиса", p.metadata_url, Status.WARN,
                                  f"не получены: {r.error_text or r.status}", tags=["meta_fail"]))
            for h in meta_hosts:
                src.setdefault(h, "метаданные")
        if len(src) == 1 and not (p and p.static_hosts):
            pass  # только основной хост — всё равно проверим строкой таблицы
        hosts = list(src.items())[: o.max_hosts]
        if len(src) > o.max_hosts:
            self._log(f"Хостов {len(src)}, проверяю первые {o.max_hosts}")
        fam_af = {"v4": socket.AF_INET, "v6": socket.AF_INET6}.get(o.family, 0)
        resolver = Resolver(fam_af, self.overrides)

        def one(host, source):
            url = f"https://{host}/"
            if host == main:
                url = f"{self.t.scheme}://{self.t.hostport}/"
            return host, source, request(url, route=self.primary, resolver=resolver, timeout=o.timeout,
                                         total_timeout=o.timeout * 2, read_limit=16 * 1024, keep_body=False,
                                         follow_redirects=False, ca_file=o.ca_file, cancel=self.cancel)

        fails = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(one, h, s) for h, s in hosts]
            for f in as_completed(futs):
                host, source, r = f.result()
                row = self._host_row(host, source, r)
                self.report.hosts.append(row)
                self.emit("host", row)
                if row.status == Status.FAIL:
                    fails.append(host)
        total = len(hosts)
        bad = [h for h in self.report.hosts if h.status == Status.FAIL]
        warn = [h for h in self.report.hosts if h.status == Status.WARN]
        d = {"Проверено": total, "Сбоев": len(bad), "Предупреждений": len(warn)}
        if bad:
            d["Недоступны"] = [f"{h.host} — {h.note}" for h in bad]
        if warn:
            d["С замечаниями"] = [f"{h.host} — {h.note}" for h in warn]
        st = Status.FAIL if any(h.source in ("профиль", "основной") for h in bad) else \
            (Status.WARN if bad or warn else Status.OK)
        tags = ["hosts_ok"] if not bad else ["hosts_fail"]
        if bad and not any(h.source == "основной" for h in bad):
            tags.append("deps_fail_main_ok")
        okn = total - len(bad) - len(warn)
        summ = f"в норме {okn} из {total}"
        if bad:
            summ += f"; сбой: {', '.join(h.host for h in bad[:4])}" + (" …" if len(bad) > 4 else "")
        if warn:
            summ += f"; с замечаниями: {', '.join(h.host for h in warn[:4])}" + (" …" if len(warn) > 4 else "")
        self._check(Check("hosts", "Хосты сервиса", self.t.host, st, summ, d, tags=tags))

    def _host_row(self, host, source, r: HttpResult) -> HostRow:
        ph = r.phases
        row = HostRow(host=host, source=source, ip=r.ip or "-", dns_ms=ph.get("dns"), tcp_ms=ph.get("tcp"),
                      tls_ms=ph.get("tls"), total_ms=ph.get("total"))
        row.family = "IPv6" if ":" in (r.ip or "") and not r.ip.startswith("proxy") else (
            "IPv4" if r.ip and not r.ip.startswith("proxy") else "-")
        if r.tls:
            row.tls = r.tls.version.replace("TLSv", "")
        mandatory = source in ("основной", "профиль")
        if r.error_code and r.status is None:
            row.status = Status.FAIL if mandatory else Status.WARN
            row.note = f"{r.error_phase}: {ERROR_TEXT.get(r.error_code, r.error_text)}"
            if r.error_code == "proxy":
                row.note = "proxy: " + r.error_text[:120]
            if r.error_code == "tls_verify":
                row.note = "TLS: " + r.error_text[:120]
            if not mandatory and r.error_phase == "dns":
                row.note += " (сторонний хост — часто режется блокировщиком/DNS-фильтром)"
        elif r.error_code:
            # заголовки пришли, оборвалось тело — для корня хоста достаточно факта ответа
            row.http = str(r.status)
            row.status = Status.OK
            row.note = f"ответ есть, тело оборвано: {r.error_text[:80]}"
        else:
            row.http = str(r.status)
            if r.status >= 500:
                row.status = Status.FAIL if mandatory else Status.WARN
                row.note = f"HTTP {r.status} — ошибка сервиса"
            else:
                row.status = Status.OK
                row.note = "" if r.status < 400 else "отвечает (корень хоста не обязан отдавать 200)"
        return row

    # --- API ------------------------------------------------------------------
    def _api_layer(self):
        o, p = self.o, self.profile
        if p:
            for url in p.probe_urls:
                if self.cancelled:
                    return
                r = request(url, route=self.primary, resolver=Resolver(overrides=self.overrides), timeout=o.timeout,
                            total_timeout=o.timeout * 2, read_limit=64 * 1024, ca_file=o.ca_file, cancel=self.cancel,
                            follow_redirects=False)
                self._api_result(f"GET {urlsplit(url).path or '/'}", url, r, "non5xx", {})
            for ap in p.api_probes:
                if self.cancelled:
                    return
                self._api_probe(ap)

    def _api_probe(self, ap: ApiProbe):
        import os
        if ap.require_env and not all(os.environ.get(v) for v in ap.require_env):
            self._check(Check("api", ap.name, ap.url, Status.SKIP,
                              f"нужна переменная окружения {', '.join(ap.require_env)}"))
            return
        if ap.skip_if_env and any(os.environ.get(v) for v in ap.skip_if_env):
            return
        url = expand_env(ap.url)
        headers = {k: expand_env(v) for k, v in ap.headers.items()}
        body = expand_env(ap.body).encode() if ap.body is not None else None
        r = request(url, method=ap.method, route=self.primary, resolver=Resolver(overrides=self.overrides),
                    headers=headers, body=body, timeout=self.o.timeout, total_timeout=self.o.timeout * 3,
                    read_limit=64 * 1024, ca_file=self.o.ca_file, cancel=self.cancel, follow_redirects=False)
        masked = {k: ("***" if any(s in k.lower() for s in ("key", "auth", "token", "secret", "cookie")) else v)
                  for k, v in headers.items()}
        self._api_result(f"{ap.method} · {ap.name}", url, r, ap.expect, masked)

    def _api_result(self, title, url, r: HttpResult, expect, headers):
        d = {"URL": url, "Ожидание": expect, "Фазы": " · ".join(f"{k} {fmt_ms(v)}" for k, v in r.phases.items())}
        if headers:
            d["Заголовки"] = headers
        if r.error_code:
            d["Ошибка"] = f"{r.error_phase}: {r.error_text}"
            self._check(Check("api", title, url, Status.FAIL, f"нет ответа: {r.error_phase} — "
                              f"{ERROR_TEXT.get(r.error_code, r.error_text)}", d, r.phases.get("total"),
                              tags=["api_net_fail"]))
            return
        code = r.status
        body_preview = r.body[:400].decode("utf-8", "replace").replace("\n", " ")
        if body_preview:
            d["Ответ (начало)"] = body_preview
        if expect == "2xx":
            ok = 200 <= code < 300
        elif expect == "non5xx":
            ok = code < 500
        elif expect == "any":
            ok = True
        else:
            ok = str(code) == expect
        st = Status.OK if ok else Status.FAIL
        tags = ["api_ok"] if ok else (["api_5xx"] if code >= 500 else ["api_unexpected"])
        note = "маршрут до бэкенда жив" if ok and expect == "non5xx" and code >= 400 else ""
        self._check(Check("api", title, url, st, f"HTTP {code} {r.reason}" + (f" — {note}" if note else ""), d,
                          r.phases.get("total"), tags=tags))

    # --- целостность контента --------------------------------------------------
    def _content_layer(self):
        o, p = self.o, self.profile
        if p and not p.check_assets:
            self._check(Check("content", "Целостность контента", self.t.host, Status.SKIP,
                              "в профиле отключено (сервис — API, не веб-страница)"))
            return
        if not self.resources:
            why = "главная страница не загрузилась" if self.main_page is None else "на странице нет ресурсов"
            self._check(Check("content", "Целостность контента", self.t.host, Status.WARN if self.main_page is None
                              else Status.SKIP, f"нечего проверять: {why}", tags=["content_nothing"]))
            return
        count = o.asset_count or (p.asset_count if p else 3)
        min_size = o.min_asset_size or (p.min_asset_size if p else 32 * 1024)
        rsize = o.range_size or (p.range_size if p else 4096)
        rx = re.compile(p.asset_url_regex if p else r"^https?://")
        cands = [u for u, tag in self.resources if rx.search(u) and not tag.startswith("iframe")]
        random.shuffle(cands)
        cands = cands[:40]
        self._log(f"Кандидатов для проверки целостности: {len(cands)}")
        sizes: list[tuple[str, int]] = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            for url, size in ex.map(self._probe_size, cands):
                if size is not None:
                    sizes.append((url, size))
        fit = [(u, s) for u, s in sizes if min_size <= s <= o.max_asset_size]
        fit.sort(key=lambda x: -x[1])
        chosen = fit[:count]
        info = {"Кандидатов": len(cands), "С известным размером": len(sizes),
                "Подходят (≥ мин. размера)": len(fit), "Минимальный размер": human_bytes(min_size)}
        if not chosen:
            self._check(Check("content", "Выбор объектов", self.t.host, Status.WARN,
                              f"нет объектов ≥ {human_bytes(min_size)} — тест обрыва передачи невозможен",
                              info, tags=["content_none_big"]))
            return
        st = Status.OK if len(chosen) >= count else Status.WARN
        self._check(Check("content", "Выбор объектов", self.t.host, st,
                          f"выбрано {len(chosen)}/{count} (крупнейшие из найденных)", info))
        for i, (url, size) in enumerate(chosen, 1):
            if self.cancelled:
                return
            self._asset(i, url, size, rsize)

    def _probe_size(self, url) -> tuple[str, int | None]:
        o = self.o
        r = request(url, method="HEAD", route=self.primary, resolver=Resolver(overrides=self.overrides),
                    timeout=o.timeout, total_timeout=o.timeout * 2, ca_file=o.ca_file, cancel=self.cancel)
        if r.ok and r.status == 200 and r.content_length and not r.header("content-encoding"):
            return r.final_url or url, r.content_length
        r = request(url, route=self.primary, resolver=Resolver(overrides=self.overrides), range_=(0, 0),
                    timeout=o.timeout, total_timeout=o.timeout * 2, read_limit=4096, ca_file=o.ca_file,
                    cancel=self.cancel)
        cr = r.header("content-range") or ""
        m = re.match(r"bytes\s+\d+-\d+/(\d+)", cr)
        if r.status == 206 and m:
            return r.final_url or url, int(m.group(1))
        return url, None

    def _asset(self, idx: int, url: str, expected: int, rsize: int):
        o = self.o
        row = AssetRow(url=url, expected=expected)
        last_emit = [0.0]

        def progress(got, total):
            now = time.perf_counter()
            if now - last_emit[0] > 0.25:
                last_emit[0] = now
                self.emit("asset_progress", (idx, url, got, expected))

        full = request(url, route=self.primary, resolver=Resolver(overrides=self.overrides), keep_body=False,
                       hash_body=True, tail_size=rsize, read_limit=None, timeout=o.timeout,
                       total_timeout=o.download_timeout, stall_timeout=o.stall_timeout, ca_file=o.ca_file,
                       cancel=self.cancel, progress=progress)
        row.received, row.http, row.sha256 = full.body_len, str(full.status or "-"), full.sha256
        row.speed_kbps = full.speed_kbps
        d = {"URL": url, "Ожидалось": f"{expected} байт ({human_bytes(expected)})",
             "Получено": f"{full.body_len} байт ({human_bytes(full.body_len)})", "HTTP": full.status,
             "SHA-256": full.sha256 or "-", "Скорость": f"{full.speed_kbps:.0f} KiB/s" if full.speed_kbps else "-",
             "Фазы": " · ".join(f"{k} {fmt_ms(v)}" for k, v in full.phases.items())}
        title = f"Объект #{idx} · {human_bytes(expected)}"
        tags: list[str] = []
        if full.error_code or full.status is None or not (200 <= full.status < 300):
            row.full = "FAIL"
            if full.stalled:
                tags += ["content_stall", f"stall_at_{full.body_len}"]
                why = f"передача зависла после {human_bytes(full.body_len)} из {human_bytes(expected)}"
            elif full.truncated:
                tags += ["content_trunc", f"trunc_at_{full.body_len}"]
                why = f"соединение оборвано после {human_bytes(full.body_len)} из {human_bytes(expected)}"
            elif full.status is not None and not (200 <= full.status < 300):
                tags.append("content_http")
                why = f"HTTP {full.status} при загрузке объекта"
            else:
                tags.append("content_net")
                why = f"{full.error_phase}: {ERROR_TEXT.get(full.error_code, full.error_text)}"
            d["Ошибка"] = full.error_text
            row.status, row.note = Status.FAIL, why
            self._finish_asset(row, Check("content", title, url, Status.FAIL, why, d, full.phases.get("total"),
                                          tags=tags))
            return
        if full.body_len != expected:
            row.full = "SIZE"
            tags.append("content_size_mismatch")
            why = f"размер {full.body_len} ≠ заявленного {expected}"
            row.status, row.note = Status.FAIL, why
            self._finish_asset(row, Check("content", title, url, Status.FAIL, why, d, tags=tags))
            return
        row.full = "OK"
        # Независимый Range-запрос хвоста
        rsz = min(rsize, expected)
        start, end = expected - rsz, expected - 1
        tail = request(url, route=self.primary, resolver=Resolver(overrides=self.overrides), range_=(start, end),
                       keep_body=True, hash_body=True, read_limit=rsz + 1024, timeout=o.timeout,
                       total_timeout=o.download_timeout, stall_timeout=o.stall_timeout, ca_file=o.ca_file,
                       cancel=self.cancel)
        d["Range-запрос"] = f"bytes={start}-{end} → HTTP {tail.status} {tail.header('content-range') or ''}".strip()
        if tail.error_code:
            row.tail, row.status, row.note = "FAIL", Status.FAIL, f"Range-запрос сорвался: {tail.error_text}"
            tags.append("content_tail_net")
        elif tail.status == 206:
            want_cr = f"bytes {start}-{end}/{expected}"
            cr = (tail.header("content-range") or "").strip()
            if len(tail.body) != rsz:
                row.tail, row.status = "FAIL", Status.FAIL
                row.note = f"хвост {len(tail.body)} байт вместо {rsz}"
                tags.append("content_tail_mismatch")
            elif cr and cr != want_cr:
                row.tail, row.status = "FAIL", Status.FAIL
                row.note = f"Content-Range «{cr}», ожидался «{want_cr}»"
                tags.append("content_tail_mismatch")
            elif tail.body != full.tail:
                row.tail, row.status = "FAIL", Status.FAIL
                row.note = "последние байты отличаются — объект менялся или повреждён в пути"
                tags.append("content_tail_mismatch")
            else:
                row.tail, row.status = "OK", Status.OK
                row.note = f"последние {human_bytes(rsz)} совпадают с независимым Range-ответом"
                tags.append("content_ok")
        elif tail.status == 200:
            if tail.body_len == expected and tail.sha256 == full.sha256:
                row.tail, row.status = "NO-RANGE", Status.OK
                row.note = "сервер игнорирует Range; повторная полная загрузка совпала побайтно"
                tags += ["content_ok", "range_unsupported"]
            else:
                row.tail, row.status = "FAIL", Status.FAIL
                row.note = "сервер игнорирует Range, повторная загрузка отличается"
                tags.append("content_tail_mismatch")
        else:
            row.tail, row.status = "FAIL", Status.FAIL
            row.note = f"Range-запрос вернул HTTP {tail.status}"
            tags.append("content_tail_http")
        self._finish_asset(row, Check("content", title, url, row.status, row.note, d, full.phases.get("total"),
                                      tags=tags))

    def _finish_asset(self, row: AssetRow, check: Check):
        self.report.assets.append(row)
        self.emit("asset", row)
        self._check(check)
