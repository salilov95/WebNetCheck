"""Экспорт отчёта: JSON (для автоматики) и самодостаточный HTML (переслать коллеге)."""
from __future__ import annotations

import datetime as dt
import html
import json

from .model import LAYERS, Report, Status
from .util import fmt_ms, human_bytes


def save_json(r: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(r.to_dict(), f, ensure_ascii=False, indent=2, default=str)


def _e(v) -> str:
    return html.escape(str(v))


def _val(v) -> str:
    if isinstance(v, (list, tuple)):
        return "<br>".join(_e(x) for x in v) or "-"
    if isinstance(v, dict):
        return "<br>".join(f"<b>{_e(k)}</b>: {_e(x)}" for k, x in v.items()) or "-"
    return _e(v)


def _pill(st: Status | str) -> str:
    s = st.value if isinstance(st, Status) else st
    return f'<span class="pill {s.lower()}">{s}</span>'


def to_html(r: Report) -> str:
    when = dt.datetime.fromtimestamp(r.started).strftime("%Y-%m-%d %H:%M:%S")
    dur = f"{(r.finished or r.started) - r.started:.1f} s"
    ov = r.overall
    parts: list[str] = []
    a = parts.append
    a(f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebNetCheck — {_e(r.target)}</title><style>
:root{{--bg:#f6f7f9;--panel:#fff;--text:#1d2129;--muted:#667085;--line:#e4e7ec;--ok:#1a7f37;--warn:#9a6700;
--fail:#cf222e;--info:#0969da;--skip:#8c959f;--okbg:#dafbe1;--warnbg:#fff8c5;--failbg:#ffebe9;--infobg:#ddf4ff;--skipbg:#f0f1f3}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#8b949e;--line:#30363d;
--ok:#3fb950;--warn:#d29922;--fail:#f85149;--info:#58a6ff;--skip:#6e7681;--okbg:#12261a;--warnbg:#2b2210;--failbg:#2d1215;
--infobg:#0d2239;--skipbg:#1c2128}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,sans-serif}}
.wrap{{max-width:1180px;margin:0 auto;padding:24px 16px 60px}}h1{{font-size:22px;margin:0 0 4px}}
h2{{font-size:16px;margin:28px 0 10px}}.muted{{color:var(--muted)}}
.hero{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}}
.big{{font-size:28px;font-weight:700;padding:8px 18px;border-radius:10px}}
.pill{{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:99px}}
.ok{{color:var(--ok);background:var(--okbg)}}.warn{{color:var(--warn);background:var(--warnbg)}}
.fail{{color:var(--fail);background:var(--failbg)}}.info{{color:var(--info);background:var(--infobg)}}.skip{{color:var(--skip);background:var(--skipbg)}}
.layers{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;margin-top:14px}}
.layer{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px;border-left:4px solid var(--skip)}}
.layer.st-ok{{border-left-color:var(--ok)}}.layer.st-warn{{border-left-color:var(--warn)}}.layer.st-fail{{border-left-color:var(--fail)}}.layer.st-info{{border-left-color:var(--info)}}
.diag{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:8px}}
.diag h3{{margin:0 0 6px;font-size:15px;display:flex;gap:8px;align-items:center}}.diag ul{{margin:6px 0 0;padding-left:20px}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{font-size:12px;color:var(--muted);font-weight:600;background:var(--bg)}}td.mono,.mono{{font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px}}
details{{margin-top:4px}}summary{{cursor:pointer;color:var(--muted);font-size:12px}}
.kv td:first-child{{color:var(--muted);width:200px}}.scroll{{overflow-x:auto}}
</style></head><body><div class="wrap">""")
    a(f"""<div class="hero"><div class="big {ov.value.lower()}">{ov.value}</div><div>
<h1>{_e(r.target)}</h1><div class="muted">Профиль: {_e(r.profile)} · {when} · длительность {dur}
{' · <b>прервано</b>' if r.cancelled else ''}</div></div></div>""")
    a('<div class="layers">')
    for key, title in LAYERS:
        cs = [c for c in r.checks if c.layer == key]
        if not cs:
            continue
        st = r.layer_status(key)
        cnt = {s: sum(1 for c in cs if c.status == s) for s in (Status.OK, Status.WARN, Status.FAIL)}
        a(f'<div class="layer st-{st.value.lower()}"><b>{_e(title)}</b> {_pill(st)}<div class="muted">'
          f'{cnt[Status.OK]} ok · {cnt[Status.WARN]} warn · {cnt[Status.FAIL]} fail</div></div>')
    a("</div><h2>Диагноз</h2>")
    for d in r.diagnosis:
        steps = "".join(f"<li>{_e(s)}</li>" for s in d.next_steps)
        a(f'<div class="diag"><h3>{_pill(d.severity)} {_e(d.title)}</h3><div>{_e(d.explanation)}</div>'
          f'{"<ul>" + steps + "</ul>" if steps else ""}</div>')

    a("<h2>Проверки по слоям</h2><div class='scroll'><table><tr><th>Статус</th><th>Слой</th><th>Проверка</th>"
      "<th>Цель</th><th>Результат</th><th>Время</th></tr>")
    titles = dict(LAYERS)
    order = {k: i for i, (k, _) in enumerate(LAYERS)}
    for c in sorted(r.checks, key=lambda c: order.get(c.layer, 99)):
        det = ""
        if c.details:
            rows = "".join(f"<tr><td>{_e(k)}</td><td class='mono'>{_val(v)}</td></tr>" for k, v in c.details.items())
            det = f"<details><summary>подробности</summary><table class='kv'>{rows}</table></details>"
        fam = f" <span class='muted'>{_e(c.family)}</span>" if c.family else ""
        a(f"<tr><td>{_pill(c.status)}</td><td>{_e(titles.get(c.layer, c.layer))}</td><td>{_e(c.title)}{fam}</td>"
          f"<td class='mono'>{_e(c.target)}</td><td>{_e(c.summary)}{det}</td><td>{fmt_ms(c.duration_ms)}</td></tr>")
    a("</table></div>")

    if r.hosts:
        a("<h2>Хосты</h2><div class='scroll'><table><tr><th>Статус</th><th>Хост</th><th>Источник</th><th>IP</th>"
          "<th>DNS</th><th>TCP</th><th>TLS</th><th>HTTP</th><th>Всего</th><th>Примечание</th></tr>")
        for h in sorted(r.hosts, key=lambda h: (-h.status.rank, h.host)):
            a(f"<tr><td>{_pill(h.status)}</td><td class='mono'>{_e(h.host)}</td><td>{_e(h.source)}</td>"
              f"<td class='mono'>{_e(h.ip)}</td><td>{fmt_ms(h.dns_ms)}</td><td>{fmt_ms(h.tcp_ms)}</td>"
              f"<td>{_e(h.tls)} {fmt_ms(h.tls_ms) if h.tls_ms else ''}</td><td>{_e(h.http)}</td>"
              f"<td>{fmt_ms(h.total_ms)}</td><td>{_e(h.note)}</td></tr>")
        a("</table></div>")
    if r.hops:
        a("<h2>Маршрут</h2><div class='scroll'><table><tr><th>Семейство</th><th>TTL</th><th>Адрес</th><th>Имя</th>"
          "<th>RTT</th></tr>")
        for h in r.hops:
            a(f"<tr><td>{_e(h.family)}</td><td>{h.ttl}</td><td class='mono'>{_e(h.ip or '*')}</td>"
              f"<td class='mono'>{_e(h.name or '')}</td><td>{fmt_ms(h.rtt_ms)}{' ✓' if h.reached else ''}</td></tr>")
        a("</table></div>")
    if r.assets:
        a("<h2>Целостность объектов</h2><div class='scroll'><table><tr><th>Статус</th><th>URL</th><th>Ожидалось</th>"
          "<th>Получено</th><th>Полная</th><th>Хвост</th><th>SHA-256</th><th>Примечание</th></tr>")
        for x in r.assets:
            a(f"<tr><td>{_pill(x.status)}</td><td class='mono'>{_e(x.url)}</td><td>{human_bytes(x.expected)}</td>"
              f"<td>{human_bytes(x.received)}</td><td>{_e(x.full)}</td><td>{_e(x.tail)}</td>"
              f"<td class='mono'>{_e(x.sha256[:16])}…</td><td>{_e(x.note)}</td></tr>")
        a("</table></div>")
    a("<h2>Среда</h2><table class='kv'>")
    for k, v in r.environment.items():
        a(f"<tr><td>{_e(k)}</td><td class='mono'>{_val(v)}</td></tr>")
    a("</table><p class='muted'>Сформировано WebNetCheck</p></div></body></html>")
    return "".join(parts)


def save_html(r: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_html(r))


def summary_text(r: Report) -> str:
    """Короткая текстовая сводка — для «Копировать» в мессенджер/тикет."""
    lines = [f"WebNetCheck: {r.target} — {r.overall.value}"]
    for key, title in LAYERS:
        st = r.layer_status(key)
        if st != Status.SKIP:
            lines.append(f"  {title}: {st.value}")
    lines.append("Диагноз:")
    for d in r.diagnosis:
        lines.append(f"  [{d.severity.value}] {d.title} — {d.explanation}")
    bad = [c for c in r.checks if c.status == Status.FAIL]
    if bad:
        lines.append("Сбои:")
        for c in bad[:15]:
            lines.append(f"  - {c.title} ({c.target}): {c.summary}")
    return "\n".join(lines)
