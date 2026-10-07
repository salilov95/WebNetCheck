"""Консольный режим: для скриптов, планировщика задач и проверки без GUI.

    python cli.py github
    python cli.py https://example.com --family v4 --json report.json
    python cli.py --list-profiles

Коды выхода: 0 — проверки пройдены, 1 — есть сбой, 2 — неверные аргументы.
"""
from __future__ import annotations

import argparse
import os
import sys

from netcheck import __version__
from netcheck.engine import ALL_CHECKS, Engine, Options
from netcheck.model import LAYERS, Status
from netcheck.profiles import load_all
from netcheck.report import save_html, save_json
from netcheck.util import fmt_ms

COL = {"OK": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m", "INFO": "\033[36m", "SKIP": "\033[90m"}
RST = "\033[0m"


def main(argv=None) -> int:
    if sys.platform == "win32":
        os.system("")  # включить ANSI-цвета в консоли Windows 10+
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass
    profiles = load_all()
    ap = argparse.ArgumentParser(prog="webnetcheck", description="Послойная диагностика доступности веб-ресурса")
    ap.add_argument("target", nargs="?", help="URL, хост или имя профиля (" + ", ".join(profiles) + ")")
    ap.add_argument("--profile", help="профиль; target тогда переопределяет base_url")
    ap.add_argument("--family", choices=["auto", "v4", "v6"], default="auto")
    ap.add_argument("--route", choices=["direct", "system", "manual", "both"], default="direct")
    ap.add_argument("--proxy", default="", help="host:port для --route manual/both")
    ap.add_argument("--ip", default="", help="подключаться к этому IP вместо DNS (как curl --resolve)")
    ap.add_argument("--ports", default="443,80")
    ap.add_argument("--only", default="", help="через запятую: " + ",".join(ALL_CHECKS))
    ap.add_argument("--skip", default="", help="исключить проверки (через запятую)")
    ap.add_argument("--no-public-dns", action="store_true")
    ap.add_argument("--no-doh", action="store_true")
    ap.add_argument("-n", "--assets", type=int)
    ap.add_argument("--min-size", type=int)
    ap.add_argument("--range-size", type=int)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--stall", type=float, default=15.0, help="сколько секунд без данных считать зависанием")
    ap.add_argument("--ca-file", help="дополнительный CA-бандл (PEM)")
    ap.add_argument("--json", metavar="FILE")
    ap.add_argument("--html", metavar="FILE")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--list-profiles", action="store_true")
    ap.add_argument("--version", action="version", version=f"WebNetCheck {__version__}")
    a = ap.parse_args(argv)

    if a.list_profiles:
        for k, p in profiles.items():
            print(f"{k:10} {p.name:14} {p.description}  [{p.path}]")
        return 0
    profile = a.profile
    target = a.target or ""
    if not profile and target in profiles:
        profile, target = target, ""
    if not profile and not target:
        ap.print_usage()
        print("ошибка: укажите URL/хост или профиль", file=sys.stderr)
        return 2
    checks = [c for c in (a.only.split(",") if a.only else ALL_CHECKS) if c]
    bad = [c for c in checks + [s for s in a.skip.split(",") if s] if c not in ALL_CHECKS]
    if bad:
        print(f"ошибка: неизвестные проверки: {bad}", file=sys.stderr)
        return 2
    checks = [c for c in checks if c not in a.skip.split(",")]
    try:
        ports = [int(p) for p in a.ports.split(",") if p.strip()]
    except ValueError:
        print("ошибка: --ports", file=sys.stderr)
        return 2

    o = Options(target=target, profile=profile, family=a.family, route=a.route, proxy=a.proxy, forced_ip=a.ip,
                ports=ports, checks=checks, public_dns=not a.no_public_dns, doh=not a.no_doh,
                asset_count=a.assets, min_asset_size=a.min_size, range_size=a.range_size, timeout=a.timeout,
                stall_timeout=a.stall, ca_file=a.ca_file)
    tty = sys.stdout.isatty()

    def color(s: str, st: str) -> str:
        return f"{COL[st]}{s}{RST}" if tty else s

    def on_event(kind, payload):
        if kind == "stage":
            i, n, title = payload
            print(f"\n== [{i + 1}/{n}] {title} " + "=" * max(0, 60 - len(title)))
        elif kind == "check":
            c = payload
            fam = f" [{c.family}]" if c.family else ""
            t = f" ({fmt_ms(c.duration_ms)})" if c.duration_ms is not None else ""
            print(f"  {color(c.status.value.ljust(4), c.status.value)}  {c.title}{fam} · {c.target}: {c.summary}{t}")
            if a.verbose:
                for k, v in c.details.items():
                    print(f"          {k}: {v}")
        elif kind == "hop" and a.verbose:
            h = payload
            print(f"        {h.ttl:>2}  {h.ip or '*':<40} {fmt_ms(h.rtt_ms):>8}  {h.name or ''}")
        elif kind == "host":
            h = payload
            print(f"  {color(h.status.value.ljust(4), h.status.value)}  {h.host:<45} {h.source:<10} "
                  f"{h.ip:<16} TLS {h.tls:<4} HTTP {h.http:<4} {fmt_ms(h.total_ms):>8}  {h.note}")
        elif kind == "log" and a.verbose:
            print(f"  ..    {payload}")

    eng = Engine(o, on_event, profiles)
    try:
        rep = eng.run()
    except KeyboardInterrupt:
        eng.stop()
        print("\nпрервано")
        return 2

    print("\n== Диагноз " + "=" * 55)
    for d in rep.diagnosis:
        print(f"  {color(d.severity.value.ljust(4), d.severity.value)}  {d.title}")
        print(f"        {d.explanation}")
        for s in d.next_steps:
            print(f"        → {s}")
    print()
    for key, title in LAYERS:
        st = rep.layer_status(key)
        if st != Status.SKIP:
            print(f"RESULT {key}={st.value}")
    print(f"RESULT overall={rep.overall.value}")
    if a.json:
        save_json(rep, a.json)
        print(f"JSON: {a.json}")
    if a.html:
        save_html(rep, a.html)
        print(f"HTML: {a.html}")
    return 1 if rep.overall == Status.FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
