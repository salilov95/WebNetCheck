"""DNS: системный резолвер vs настроенные DNS vs публичные (UDP/53) vs DoH.

Сравнение ответов ловит подмену/блокировку на резолвере, поломанный
корпоративный DNS, закрытый UDP/53 и «внутренние» имена.
"""
from __future__ import annotations

import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .httpclient import request
from .model import Check, Status
from .transport import DIRECT, Route
from .util import Timer, error_text, ip_kind, is_ip_literal

try:
    import dns.exception
    import dns.rdatatype
    import dns.resolver
    HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover
    HAVE_DNSPYTHON = False

PUBLIC_RESOLVERS = [("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1"), ("Яндекс", "77.88.8.8")]
DOH_RESOLVERS = [
    ("DoH Google", "https://dns.google/resolve?name={name}&type={type}"),
    ("DoH Cloudflare", "https://cloudflare-dns.com/dns-query?name={name}&type={type}"),
]


@dataclass
class Answer:
    resolver: str          # человекочитаемо
    kind: str              # system / configured / public / doh
    rrtype: str            # A / AAAA
    status: str            # ok / nxdomain / noanswer / timeout / error / servfail
    ips: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    ms: float | None = None
    error: str = ""


@dataclass
class DnsOutcome:
    host: str
    answers: list[Answer] = field(default_factory=list)
    system_v4: list[str] = field(default_factory=list)
    system_v6: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    configured: list[str] = field(default_factory=list)

    def addresses(self, family: int) -> list[str]:
        return self.system_v6 if family == socket.AF_INET6 else self.system_v4


def _system(host: str, family: int) -> Answer:
    rr = "AAAA" if family == socket.AF_INET6 else "A"
    t = Timer()
    try:
        infos = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
        ips = []
        for i in infos:
            ip = i[4][0]
            if ip not in ips:
                ips.append(ip)
        return Answer("Системный резолвер", "system", rr, "ok", ips, ms=t.ms())
    except socket.gaierror as e:
        # EAI_NONAME — нет такого имени ИЛИ нет записей этого типа; различить без DNS-пакета нельзя
        # Windows: 11001 WSAHOST_NOT_FOUND, 11004 WSANO_DATA (имя есть, записей этого типа нет);
        # для AAAA 11004 приходит и тогда, когда на компьютере просто нет IPv6
        if e.errno in (11004, getattr(socket, "EAI_NODATA", -5), -5):
            st = "noanswer"
        elif e.errno in (socket.EAI_NONAME, 11001, -2):
            st = "noanswer" if family == socket.AF_INET6 else "nxdomain"
        else:
            st = "error"
        return Answer("Системный резолвер", "system", rr, st, ms=t.ms(), error=str(e))
    except OSError as e:
        return Answer("Системный резолвер", "system", rr, "error", ms=t.ms(), error=str(e))


def _udp(name: str, server: str, host: str, rr: str, kind: str, timeout: float) -> Answer:
    label = f"{name} ({server})"
    if not HAVE_DNSPYTHON:
        return Answer(label, kind, rr, "error", error="модуль dnspython не установлен")
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.timeout = timeout
    r.lifetime = timeout
    r.cache = None
    t = Timer()
    try:
        ans = r.resolve(host, rr, raise_on_no_answer=False, search=False)
        ips = [x.to_text() for x in ans.rrset] if ans.rrset is not None else []
        cname = []
        for rrset in ans.response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                cname += [x.to_text().rstrip(".") for x in rrset]
        return Answer(label, kind, rr, "ok" if ips else "noanswer", ips, cname, t.ms())
    except dns.resolver.NXDOMAIN:
        return Answer(label, kind, rr, "nxdomain", ms=t.ms())
    except dns.exception.Timeout:
        return Answer(label, kind, rr, "timeout", ms=t.ms(), error=f"нет ответа за {timeout:.0f} s")
    except dns.resolver.NoNameservers as e:
        return Answer(label, kind, rr, "servfail", ms=t.ms(), error=str(e)[:200])
    except Exception as e:  # noqa: BLE001
        return Answer(label, kind, rr, "error", ms=t.ms(), error=f"{e.__class__.__name__}: {e}"[:200])


def _doh(name: str, tmpl: str, host: str, rr: str, route: Route, timeout: float, ca_file) -> Answer:
    url = tmpl.format(name=host, type=rr)
    r = request(url, route=route, headers={"Accept": "application/dns-json"}, timeout=timeout,
                total_timeout=timeout * 2, read_limit=256 * 1024, ca_file=ca_file, follow_redirects=False)
    ms = r.phases.get("total")
    if r.error_code:
        return Answer(name, "doh", rr, "timeout" if r.error_code == "timeout" else "error", ms=ms,
                      error=f"{r.error_phase}: {r.error_text}"[:200])
    if r.status != 200:
        return Answer(name, "doh", rr, "error", ms=ms, error=f"HTTP {r.status}")
    try:
        data = json.loads(r.body.decode("utf-8", "replace"))
    except ValueError:
        return Answer(name, "doh", rr, "error", ms=ms, error="ответ не JSON")
    code = data.get("Status", 0)
    want = 28 if rr == "AAAA" else 1
    ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == want]
    cname = [a["data"].rstrip(".") for a in data.get("Answer", []) if a.get("type") == 5]
    if code == 3:
        return Answer(name, "doh", rr, "nxdomain", ms=ms)
    if code != 0:
        return Answer(name, "doh", rr, "servfail", ms=ms, error=f"RCODE {code}")
    return Answer(name, "doh", rr, "ok" if ips else "noanswer", ips, cname, ms)


def configured_servers() -> list[str]:
    if not HAVE_DNSPYTHON:
        return []
    try:
        return [str(s) for s in dns.resolver.Resolver(configure=True).nameservers][:3]
    except Exception:  # noqa: BLE001
        return []


def investigate(host: str, *, want_v6: bool, route: Route = DIRECT, public: bool = True, doh: bool = True,
                timeout: float = 3.0, ca_file: str | None = None,
                cancel: threading.Event | None = None, overrides: dict | None = None) -> DnsOutcome:
    out = DnsOutcome(host)
    if is_ip_literal(host):
        ip = host.strip("[]")
        (out.system_v6 if ":" in ip else out.system_v4).append(ip)
        out.checks.append(Check("dns", "IP-адрес вместо имени", host, Status.INFO, "DNS не используется"))
        return out
    if overrides and host.lower() in overrides:
        ip = overrides[host.lower()]
        (out.system_v6 if ":" in ip else out.system_v4).append(ip)
        out.checks.append(Check("dns", "Принудительный адрес", host, Status.INFO,
                                f"{host} → {ip} (задан вручную, DNS пропущен)"))
        return out

    rrtypes = ["A", "AAAA"] if want_v6 else ["A"]
    out.configured = configured_servers()
    jobs = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        jobs.append(ex.submit(_system, host, socket.AF_INET))
        jobs.append(ex.submit(_system, host, socket.AF_INET6))  # AAAA смотрим всегда — для диагноза
        for rr in rrtypes:
            for i, srv in enumerate(out.configured):
                jobs.append(ex.submit(_udp, f"Настроенный DNS #{i + 1}", srv, host, rr, "configured", timeout))
            if public:
                for name, srv in PUBLIC_RESOLVERS:
                    jobs.append(ex.submit(_udp, name, srv, host, rr, "public", timeout))
            if doh:
                for name, tmpl in DOH_RESOLVERS:
                    jobs.append(ex.submit(_doh, name, tmpl, host, rr, route, timeout + 2, ca_file))
        out.answers = [j.result() for j in jobs]

    for a in out.answers:
        if a.kind == "system" and a.status == "ok":
            if a.rrtype == "A":
                out.system_v4 = [ip for ip in a.ips if ":" not in ip]
            else:
                out.system_v6 = [ip for ip in a.ips if ":" in ip]

    _to_checks(out)
    return out


def _to_checks(out: DnsOutcome) -> None:
    host = out.host
    st_map = {"ok": Status.OK, "noanswer": Status.INFO, "nxdomain": Status.FAIL,
              "timeout": Status.WARN, "servfail": Status.WARN, "error": Status.WARN}
    for a in out.answers:
        if a.kind == "system" and a.rrtype == "AAAA" and a.status != "ok":
            st = Status.INFO
        else:
            st = st_map.get(a.status, Status.WARN)
        if a.kind != "system" and a.status != "ok":
            # ответ стороннего резолвера — не приговор: итог считается ниже по всей картине
            st = Status.INFO
        summary = {
            "ok": ", ".join(a.ips[:6]) + (f" … (+{len(a.ips) - 6})" if len(a.ips) > 6 else ""),
            "noanswer": f"нет записей {a.rrtype}",
            "nxdomain": "NXDOMAIN — имя не существует",
            "timeout": "нет ответа" + (" (UDP/53 закрыт?)" if a.kind == "public" else ""),
            "servfail": "SERVFAIL",
            "error": a.error or "ошибка",
        }[a.status]
        tags = [f"dns_{a.kind}_{a.status}"]
        kinds = {ip_kind(ip) for ip in a.ips}
        if a.status == "ok" and kinds - {"public"}:
            tags.append(f"dns_{a.kind}_nonpublic")
        details = {"Резолвер": a.resolver, "Тип": a.rrtype, "Ответ": a.ips or a.status,
                   "Время": f"{a.ms:.0f} ms" if a.ms is not None else "-"}
        if a.cname:
            details["CNAME"] = " → ".join(a.cname)
        if a.error:
            details["Ошибка"] = a.error
        if a.status == "ok":
            details["Типы адресов"] = ", ".join(sorted(kinds))
        out.checks.append(Check("dns", f"{a.rrtype} · {a.resolver}", host, st, summary, details, a.ms, tags=tags))

    # --- Сводный анализ --------------------------------------------------
    sysA = next((a for a in out.answers if a.kind == "system" and a.rrtype == "A"), None)
    sys6 = next((a for a in out.answers if a.kind == "system" and a.rrtype == "AAAA"), None)
    trusted = [a for a in out.answers if a.kind in ("doh", "public") and a.rrtype == "A"]
    trusted_ok = [a for a in trusted if a.status == "ok"]
    trusted_ips = {ip for a in trusted_ok for ip in a.ips}
    sys_ips = set(sysA.ips) if sysA and sysA.status == "ok" else set()
    sys_kinds = {ip_kind(ip) for ip in sys_ips}

    def add(status, title, summary, tags, details=None):
        out.checks.append(Check("dns", title, host, status, summary, details or {}, tags=tags))

    any_ok = (sysA and sysA.status == "ok") or (sys6 and sys6.status == "ok") or bool(trusted_ok)
    if not any_ok:
        nx = [a for a in out.answers if a.status == "nxdomain"]
        if nx and len(nx) >= len([a for a in out.answers if a.status != "timeout"]) - 1:
            add(Status.FAIL, "Итог DNS", "имя не существует ни в одном резолвере", ["dns_nx_everywhere"])
        else:
            add(Status.FAIL, "Итог DNS", "ни один резолвер не вернул адрес", ["dns_all_fail"])
        return

    if not sys_ips and not (sys6 and sys6.status == "ok"):
        add(Status.FAIL, "Итог DNS", "системный резолвер не разрешает имя, а публичные/DoH — разрешают",
            ["dns_system_broken"],
            {"Публичные ответы": sorted(trusted_ips)[:10], "Ошибка системы": sysA.error if sysA else ""})
        return

    bogus = sys_kinds & {"unspecified", "loopback"}
    if bogus or (sys_kinds - {"public"} and trusted_ips and
                 all(ip_kind(ip) == "public" for ip in trusted_ips)):
        if bogus:
            add(Status.FAIL, "Итог DNS", f"система получает служебный адрес ({', '.join(sorted(sys_ips))}) — "
                f"типичный признак DNS-блокировки", ["dns_bogus"],
                {"Системный ответ": sorted(sys_ips), "DoH/публичные": sorted(trusted_ips)[:10]})
            return
        # приватный ответ системы при публичном у DoH: split-horizon или подмена
        add(Status.WARN, "Итог DNS", "система получает приватный адрес, публичные резолверы — публичный "
            "(split-horizon DNS или подмена)", ["dns_private_vs_public"],
            {"Системный ответ": sorted(sys_ips), "DoH/публичные": sorted(trusted_ips)[:10]})
        return

    if sys_ips and not trusted_ok and any(a.status == "nxdomain" for a in trusted):
        add(Status.INFO, "Итог DNS", "имя существует только во внутреннем DNS — внутренний ресурс",
            ["dns_internal"], {"Системный ответ": sorted(sys_ips)})
        return

    if sys_ips and trusted_ips and not (sys_ips & trusted_ips):
        add(Status.INFO, "Итог DNS", "адреса системы и DoH не пересекаются — для CDN/GeoDNS это норма, "
            "для одиночного сервера подозрительно", ["dns_mismatch"],
            {"Системный ответ": sorted(sys_ips), "DoH/публичные": sorted(trusted_ips)[:10]})
    else:
        add(Status.OK, "Итог DNS", f"согласовано: {', '.join(sorted(sys_ips)[:4]) or 'только AAAA'}",
            ["dns_consistent"])

    dead = sorted({a.resolver for a in out.answers if a.kind == "configured" and a.status == "timeout"})
    alive = any(a.kind == "configured" and a.status in ("ok", "noanswer", "nxdomain") for a in out.answers)
    if dead:
        add(Status.INFO if alive else Status.WARN, "DNS-серверы из настроек адаптеров",
            "не отвечает: " + ", ".join(dead), ["dns_configured_dead"], {"Не отвечают": dead})
    doh = [a for a in out.answers if a.kind == "doh"]
    if doh and not any(a.status in ("ok", "noanswer", "nxdomain") for a in doh):
        add(Status.INFO, "DNS-over-HTTPS", "DoH-резолверы недоступны (заблокированы фильтром/прокси) — "
            "сверка с «чистым» DNS невозможна", ["dns_doh_blocked"],
            {"Ошибки": [f"{a.resolver}: {a.error}" for a in doh][:4]})
    if any(a.kind == "public" and a.status == "timeout" for a in out.answers) and \
            not any(a.kind == "public" and a.status == "ok" for a in out.answers):
        add(Status.INFO, "Внешний DNS по UDP/53", "все публичные резолверы молчат — исходящий UDP/53 "
            "закрыт (норма для корпоративной сети)", ["dns_udp53_blocked"])
