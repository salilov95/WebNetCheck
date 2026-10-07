"""Внешний IP и оператор (ASN): каким адресом компьютер выходит в интернет.

Спрашиваем публичные сервисы по очереди, пока один не ответит. Запрос идёт тем же
HTTP-клиентом, что и остальные проверки, поэтому можно сравнить выход «напрямую»
и «через системный прокси»: при VPN или прокси это разные адреса и операторы.
"""
from __future__ import annotations

import json
import socket
from dataclasses import dataclass

from .httpclient import Resolver, request
from .transport import DIRECT, Route


@dataclass
class ExternalIP:
    ip: str
    asn: str = ""        # "AS3292"
    operator: str = ""   # "TDC Holding A/S"
    city: str = ""
    country: str = ""    # двухбуквенный код или название — как отдал сервис
    source: str = ""

    @property
    def summary(self) -> str:
        parts = [self.ip]
        op = " ".join(x for x in (self.asn, self.operator) if x)
        if op:
            parts.append(op)
        place = ", ".join(x for x in (self.city, self.country) if x)
        if place:
            parts.append(place)
        return " · ".join(parts)


def split_org(org: str) -> tuple[str, str]:
    """'AS3292 TDC Holding A/S' → ('AS3292', 'TDC Holding A/S')."""
    org = (org or "").strip()
    head, _, rest = org.partition(" ")
    if head[:2].upper() == "AS" and head[2:].isdigit():
        return head.upper(), rest.strip()
    return "", org


def parse_ipinfo(d: dict) -> ExternalIP | None:
    if not d.get("ip"):
        return None
    asn, op = split_org(d.get("org", ""))
    return ExternalIP(d["ip"], asn, op, d.get("city", ""), d.get("country", ""), "ipinfo.io")


def parse_ifconfig(d: dict) -> ExternalIP | None:
    if not d.get("ip"):
        return None
    return ExternalIP(d["ip"], str(d.get("asn", "") or ""), d.get("asn_org", "") or "",
                      d.get("city", "") or "", d.get("country_iso", "") or d.get("country", "") or "",
                      "ifconfig.co")


def parse_ipify(d: dict) -> ExternalIP | None:
    return ExternalIP(d["ip"], source="ipify.org") if d.get("ip") else None


SERVICES = [
    ("ipinfo.io", "https://ipinfo.io/json", parse_ipinfo),
    ("ifconfig.co", "https://ifconfig.co/json", parse_ifconfig),
    ("ipify.org", "https://api.ipify.org/?format=json", parse_ipify),
]


def _get_json(url, route, timeout, ca_file, cancel):
    r = request(url, route=route, resolver=Resolver(socket.AF_INET), headers={"Accept": "application/json"},
                timeout=timeout, total_timeout=timeout * 2, read_limit=64 * 1024, ca_file=ca_file, cancel=cancel)
    if r.error_code:
        return None, f"{r.error_phase}: {r.error_text}"[:160]
    if r.status != 200:
        return None, f"HTTP {r.status}"
    try:
        data = json.loads(r.body.decode("utf-8", "replace"))
    except ValueError:
        return None, "ответ не JSON"
    return (data, "") if isinstance(data, dict) else (None, "неожиданный формат")


def _ripe_fill(ext: ExternalIP, route, timeout, ca_file, cancel) -> None:
    """Добрать ASN и владельца из RIPEstat, если сервис отдал только адрес."""
    d, _ = _get_json(f"https://stat.ripe.net/data/network-info/data.json?resource={ext.ip}",
                     route, timeout, ca_file, cancel)
    asns = ((d or {}).get("data") or {}).get("asns") or []
    if not asns:
        return
    ext.asn = f"AS{asns[0]}"
    d, _ = _get_json(f"https://stat.ripe.net/data/as-overview/data.json?resource={ext.asn}",
                     route, timeout, ca_file, cancel)
    ext.operator = ((d or {}).get("data") or {}).get("holder", "") or ""
    ext.source += " + RIPEstat"


def lookup(route: Route = DIRECT, timeout: float = 5.0, ca_file: str | None = None,
           cancel=None) -> tuple[ExternalIP | None, list[str]]:
    """→ (результат или None, список ошибок по сервисам)."""
    errors: list[str] = []
    for name, url, parse in SERVICES:
        if cancel is not None and cancel.is_set():
            break
        data, err = _get_json(url, route, timeout, ca_file, cancel)
        if data is None:
            errors.append(f"{name}: {err}")
            continue
        ext = parse(data)
        if ext is None:
            errors.append(f"{name}: в ответе нет адреса")
            continue
        if not ext.asn:
            _ripe_fill(ext, route, timeout, ca_file, cancel)
        return ext, errors
    return None, errors
