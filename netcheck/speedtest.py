"""Замер скорости загрузки одного объекта с возможностью подменить SNI.

Идея теста на замедление по имени: один и тот же объект с одного и того же сервера
качаем дважды — с настоящим именем в SNI и с проверяемым (например, *.googlevideo.com).
Сервер, маршрут и объект одинаковы, отличается только имя, которое видит DPI.
Разница в скорости в разы = замедление по SNI.
"""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .transport import DIRECT, NetError, Route, open_stream, tls_wrap
from .util import classify_error

UA = "WebNetCheck (+diagnostics)"


@dataclass
class SpeedResult:
    url: str
    sni: str = ""
    status: int | None = None
    received: int = 0
    seconds: float = 0.0
    kbps: float | None = None      # KiB/s по телу ответа
    complete: bool = False         # тело дочитано до конца (а не до лимита/таймаута)
    stalled: bool = False
    error: str = ""                # код ошибки (classify_error) или пусто
    error_text: str = ""
    redirects: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300 and not self.error


def measure(url: str, *, route: Route = DIRECT, ip: str | None = None, connect_host: str | None = None,
            sni: str | None = None, timeout: float = 8.0, window: float = 10.0, stall: float = 5.0,
            max_bytes: int = 4 * 1024 * 1024, ca_file: str | None = None,
            cancel: threading.Event | None = None) -> SpeedResult:
    """GET url и замер скорости тела. connect_host/ip — куда подключаться, sni — имя в ClientHello.

    При подменённом SNI сертификат не проверяется: он заведомо выдан на другое имя.
    Редиректы идут в то же соединение-назначение (как curl --connect-to).
    """
    res = SpeedResult(url=url, sni=sni or "")
    current = url
    for _ in range(5):
        u = urlsplit(current)
        host = u.hostname or ""
        port = u.port or (443 if u.scheme == "https" else 80)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        sock = None
        try:
            sock, _info = open_stream(route, connect_host or host, port, ip, timeout)
            if u.scheme == "https":
                name = sni or host
                sock, _tls = tls_wrap(sock, name, timeout, verify=not sni and not connect_host, ca_file=ca_file,
                                      alpn=("http/1.1",))
            sock.settimeout(timeout)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nAccept: */*\r\n"
                   f"Accept-Encoding: identity\r\nConnection: close\r\n\r\n")
            sock.sendall(req.encode("latin-1"))
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(16384)
                if not chunk:
                    raise NetError("http", code="eof", text="сервер закрыл соединение до заголовков")
                buf += chunk
                if len(buf) > 256 * 1024:
                    raise NetError("http", code="http", text="слишком длинные заголовки")
            head, body = buf.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ", 2)
            res.status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            hdrs = {k.strip().lower(): v.strip() for k, v in (ln.split(":", 1) for ln in lines[1:] if ":" in ln)}
            if res.status in (301, 302, 303, 307, 308) and hdrs.get("location"):
                current = urljoin(current, hdrs["location"])
                res.redirects.append(current)
                continue
            if res.status is None or not 200 <= res.status < 300:
                return res
            length = int(hdrs["content-length"]) if hdrs.get("content-length", "").isdigit() else None
            res.received = len(body)
            t0 = time.perf_counter()
            sock.settimeout(stall)
            while True:
                if cancel is not None and cancel.is_set():
                    res.error, res.error_text = "cancel", "отменено"
                    break
                if res.received >= max_bytes or (length is not None and res.received >= length):
                    res.complete = length is not None and res.received >= length
                    break
                if time.perf_counter() - t0 >= window:
                    break
                try:
                    chunk = sock.recv(65536)
                except (socket.timeout, TimeoutError):
                    res.stalled = True
                    break
                if not chunk:
                    res.complete = length is None or res.received >= length
                    break
                res.received += len(chunk)
            res.seconds = time.perf_counter() - t0
            if res.seconds > 0:
                res.kbps = res.received / 1024 / res.seconds
            return res
        except NetError as e:
            res.error, res.error_text = e.code, f"{e.phase}: {e.text}"
            return res
        except (OSError, ValueError) as e:
            res.error, res.error_text = classify_error(e), str(e)
            return res
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    res.error, res.error_text = "http", "слишком много редиректов"
    return res


def verdict(control: SpeedResult, test: SpeedResult) -> tuple[str, str]:
    """('ok'|'throttled'|'blocked'|'inconclusive', пояснение) по паре замеров."""
    if not control.ok or control.received < 256 * 1024 or not control.kbps:
        why = control.error_text or (f"HTTP {control.status}" if control.status and not control.ok else
                                     f"получено всего {control.received} байт")
        return "inconclusive", f"контрольная загрузка не удалась ({why}) — сравнивать не с чем"
    if test.error and not test.received:
        return "blocked", f"с проверяемым именем соединение не устанавливается: {test.error_text}"
    if test.status is not None and not 200 <= test.status < 300:
        return "inconclusive", f"с проверяемым именем сервер ответил HTTP {test.status}"
    c, t = control.kbps, test.kbps or 0.0
    if test.stalled and test.received < control.received / 4:
        return "throttled", (f"передача замирает после {test.received // 1024} KiB "
                             f"(контроль: {control.received // 1024} KiB на {c:.0f} KiB/s)")
    if t < c * 0.25:
        return "throttled", f"{t:.0f} KiB/s против {c:.0f} KiB/s — в {c / max(t, 0.1):.0f} раз медленнее"
    return "ok", f"{t:.0f} KiB/s против {c:.0f} KiB/s — разницы нет"
