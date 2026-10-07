"""HTTP/1.1 поверх своего сокета: тайминги фаз, редиректы, потоковая загрузка
с детектором «зависания» передачи, Range-запросы.

Работаем через http.client, но соединение (TCP/CONNECT/TLS) открываем сами —
так видно, на каком IP и на какой фазе всё сломалось.
"""
from __future__ import annotations

import gzip
import hashlib
import http.client
import socket
import threading
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__
from .transport import DIRECT, NetError, Route, TlsInfo, open_stream, tls_wrap
from .util import Timer, classify_error, is_ip_literal

UA = f"WebNetCheck/{__version__} (+diagnostics)"
REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass
class Target:
    scheme: str
    host: str
    port: int
    path: str  # path + query

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def hostport(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.is_https else 80
        return h if self.port == default else f"{h}:{self.port}"


def parse_url(url: str) -> Target:
    u = urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise ValueError(f"поддерживаются только http/https: {url}")
    host = u.hostname or ""
    if not host:
        raise ValueError(f"в URL нет хоста: {url}")
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return Target(u.scheme, host, port, path)


@dataclass
class Resolver:
    """Как HTTP-клиент получает IP: системный резолв + принудительные адреса."""
    family: int = 0                       # 0 = любой, AF_INET, AF_INET6
    overrides: dict[str, str] = field(default_factory=dict)  # host -> ip

    def resolve(self, host: str, port: int) -> tuple[str, float]:
        if is_ip_literal(host):
            return host.strip("[]"), 0.0
        if host.lower() in self.overrides:
            return self.overrides[host.lower()], 0.0
        t = Timer()
        try:
            infos = socket.getaddrinfo(host, port, self.family, socket.SOCK_STREAM)
        except BaseException as e:
            raise NetError("dns", e, code="dns") from e
        return infos[0][4][0], t.ms()


@dataclass
class HttpResult:
    url: str
    final_url: str = ""
    method: str = "GET"
    status: int | None = None
    reason: str = ""
    http_version: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    ip: str = ""
    route: str = ""
    phases: dict[str, float] = field(default_factory=dict)  # dns,tcp,tls,ttfb,body,total
    tls: TlsInfo | None = None
    redirects: list[tuple[int, str]] = field(default_factory=list)
    body: bytes = b""
    body_len: int = 0
    content_length: int | None = None
    truncated: bool = False
    stalled: bool = False
    error_phase: str = ""
    error_code: str = ""
    error_text: str = ""
    sha256: str = ""
    tail: bytes = b""
    speed_kbps: float | None = None

    @property
    def ok(self) -> bool:
        return self.status is not None and not self.error_code

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def to_dict(self) -> dict:
        return {
            "url": self.url, "final_url": self.final_url, "method": self.method,
            "status": self.status, "reason": self.reason, "http_version": self.http_version,
            "ip": self.ip, "route": self.route,
            "phases_ms": {k: round(v, 1) for k, v in self.phases.items()},
            "redirects": self.redirects, "body_len": self.body_len,
            "content_length": self.content_length, "truncated": self.truncated,
            "stalled": self.stalled, "error": self.error_code and
            {"phase": self.error_phase, "code": self.error_code, "text": self.error_text},
            "tls": self.tls.to_dict() if self.tls else None,
            "headers": dict(self.headers[:40]),
        }


class Cancelled(Exception):
    pass


def request(url: str, *, method: str = "GET", route: Route = DIRECT, resolver: Resolver | None = None,
            ip: str | None = None, headers: dict | None = None, body: bytes | None = None,
            timeout: float = 10.0, total_timeout: float = 30.0, stall_timeout: float = 15.0,
            read_limit: int | None = 5 * 1024 * 1024, keep_body: bool = True,
            follow_redirects: bool = True, max_redirects: int = 8, verify: bool = True,
            ca_file: str | None = None, range_: tuple[int, int] | None = None,
            hash_body: bool = False, tail_size: int = 0,
            cancel: threading.Event | None = None, progress=None) -> HttpResult:
    """Один HTTP-запрос (с редиректами). Никогда не бросает исключений — ошибки в результате."""
    resolver = resolver or Resolver()
    res = HttpResult(url=url, method=method, route=route.label)
    total = Timer()
    current = url
    for _hop in range(max_redirects + 1):
        hop = _one(current, method=method, route=route, resolver=resolver, ip=ip if current == url else None,
                   headers=headers, body=body, timeout=timeout, total_timeout=total_timeout,
                   stall_timeout=stall_timeout, read_limit=read_limit, keep_body=keep_body, verify=verify,
                   ca_file=ca_file, range_=range_, hash_body=hash_body, tail_size=tail_size,
                   cancel=cancel, progress=progress, started=total)
        hop.redirects = res.redirects
        res = hop
        res.url = url
        if (follow_redirects and res.status in REDIRECT_CODES and res.header("location")):
            nxt = urljoin(current, res.header("location"))
            res.redirects.append((res.status, nxt))
            if res.status == 303:
                method, body = "GET", None
            current = nxt
            continue
        break
    res.final_url = current
    res.phases["total"] = total.ms()
    return res


def _one(url: str, *, method, route, resolver, ip, headers, body, timeout, total_timeout, stall_timeout,
         read_limit, keep_body, verify, ca_file, range_, hash_body, tail_size, cancel, progress,
         started: Timer) -> HttpResult:
    res = HttpResult(url=url, method=method, route=route.label)
    try:
        t = parse_url(url)
    except ValueError as e:
        res.error_phase, res.error_code, res.error_text = "url", "other", str(e)
        return res
    sock = None
    conn = None
    try:
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        # 1. DNS — только для прямого маршрута: через прокси имя резолвит прокси
        if not route.is_proxy:
            if ip:
                res.ip, res.phases["dns"] = ip, 0.0
            else:
                res.ip, res.phases["dns"] = resolver.resolve(t.host, t.port)
        # 2. TCP (или CONNECT-туннель; plain HTTP через прокси — абсолютный URI)
        if route.is_proxy and not t.is_https:
            pip = Resolver().resolve(route.proxy_host, route.proxy_port)[0]
            sock, info = open_stream(DIRECT, route.proxy_host, route.proxy_port, pip, timeout)
            res.ip = f"proxy {route.proxy_host}"
        else:
            sock, info = open_stream(route, t.host, t.port, res.ip, timeout)
            if route.is_proxy:
                res.ip = f"proxy {route.proxy_host}"
        res.phases["tcp"] = info["tcp_ms"]
        # 3. TLS
        if t.is_https:
            sni = None if is_ip_literal(t.host) else t.host
            sock, tls = tls_wrap(sock, sni, timeout, verify=verify, ca_file=ca_file, alpn=("http/1.1",))
            res.tls = tls
            res.phases["tls"] = tls.handshake_ms
        # 4. Запрос
        # Сокет уже открыт и (для https) обёрнут в TLS нами, поэтому хватает HTTPConnection:
        # HTTPSConnection на каждый запрос строил бы ещё один SSL-контекст с загрузкой хранилища Windows.
        conn = http.client.HTTPConnection(t.host, t.port, timeout=timeout)
        conn.sock = sock
        target_path = url if (route.is_proxy and not t.is_https) else t.path
        conn.putrequest(method, target_path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", t.hostport)
        hdrs = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"}
        if range_:
            hdrs["Range"] = f"bytes={range_[0]}-{range_[1]}"
        if headers:
            hdrs.update(headers)
        if body is not None:
            hdrs["Content-Length"] = str(len(body))
        for k, v in hdrs.items():
            conn.putheader(k, v)
        t_send = Timer()
        conn.endheaders(body)
        resp = conn.getresponse()
        res.phases["ttfb"] = t_send.ms()
        res.status, res.reason = resp.status, resp.reason
        res.http_version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(resp.version, str(resp.version))
        res.headers = resp.getheaders()
        cl = res.header("content-length")
        res.content_length = int(cl) if cl and cl.strip().isdigit() else None
        if method == "HEAD" or (res.status in REDIRECT_CODES and res.header("location")):
            return res
        # 5. Тело — потоково, с детектором зависания
        _read_body(res, resp, sock, stall_timeout=stall_timeout, total_timeout=total_timeout,
                   read_limit=read_limit, keep_body=keep_body, hash_body=hash_body, tail_size=tail_size,
                   cancel=cancel, progress=progress, started=started)
    except Cancelled:
        res.error_phase, res.error_code, res.error_text = "cancel", "cancel", "отменено пользователем"
    except NetError as e:
        res.error_phase, res.error_code, res.error_text = e.phase, e.code, e.text
    except http.client.HTTPException as e:
        res.error_phase, res.error_code, res.error_text = "http", classify_error(e) if isinstance(e, OSError) else "http", \
            f"{e.__class__.__name__}: {e}"
    except BaseException as e:  # noqa: BLE001 — диагностический инструмент не должен падать
        phase = "ttfb" if res.status is None else "body"
        res.error_phase, res.error_code, res.error_text = phase, classify_error(e), f"{e.__class__.__name__}: {e}"
    finally:
        try:
            if conn is not None:
                conn.close()
            elif sock is not None:
                sock.close()
        except OSError:
            pass
    return res


def _read_body(res: HttpResult, resp, sock, *, stall_timeout, total_timeout, read_limit, keep_body,
               hash_body, tail_size, cancel, progress, started: Timer):
    sock.settimeout(stall_timeout)
    h = hashlib.sha256() if hash_body else None
    chunks: list[bytes] = []
    kept = 0
    tail = b""
    t_body = Timer()
    received = 0
    try:
        while True:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            if started.ms() > total_timeout * 1000:
                res.error_phase, res.error_code = "body", "timeout"
                res.error_text = f"общий таймаут {total_timeout:.0f} s, получено {received} байт"
                break
            try:
                chunk = resp.read1(65536)  # read1: отдаёт то, что уже пришло, не ждёт заполнения буфера
            except (socket.timeout, TimeoutError):
                res.stalled = True
                res.error_phase, res.error_code = "body", "timeout"
                res.error_text = (f"передача зависла: нет данных {stall_timeout:.0f} s "
                                  f"после {received} байт")
                break
            except http.client.IncompleteRead as e:
                part = e.partial or b""
                received += len(part)
                if h:
                    h.update(part)
                res.truncated = True
                res.error_phase, res.error_code = "body", "reset"
                res.error_text = f"соединение закрыто посреди тела после {received} байт"
                break
            if not chunk:
                break
            received += len(chunk)
            if h:
                h.update(chunk)
            if tail_size:
                tail = (tail + chunk)[-tail_size:]
            if keep_body and (read_limit is None or kept < read_limit):
                chunks.append(chunk)
                kept += len(chunk)
            if progress:
                progress(received, res.content_length)
            if not keep_body and not hash_body and read_limit is not None and received >= read_limit:
                break  # нам достаточно факта ответа
            if keep_body and read_limit is not None and kept >= read_limit and not hash_body:
                break
    except (ConnectionError, OSError) as e:
        res.truncated = True
        res.error_phase, res.error_code = "body", classify_error(e)
        res.error_text = f"{e.__class__.__name__} после {received} байт: {e}"
    res.body_len = received
    res.phases["body"] = t_body.ms()
    if res.phases["body"] > 0:
        res.speed_kbps = received / 1024 / (res.phases["body"] / 1000)
    # Длина меньше заявленной без ошибки — сервер/путь молча оборвал тело
    if (not res.error_code and res.content_length is not None and received < res.content_length
            and (read_limit is None or received < read_limit or hash_body)):
        res.truncated = True
        res.error_phase, res.error_code = "body", "eof"
        res.error_text = f"получено {received} из {res.content_length} байт (Content-Length)"
    if h:
        res.sha256 = h.hexdigest()
    res.tail = tail
    if keep_body:
        res.body = b"".join(chunks)


def decode_body(res: HttpResult) -> str:
    """Тело как текст (с распаковкой gzip/deflate, если сервер проигнорировал identity)."""
    data = res.body
    enc = (res.header("content-encoding") or "").lower()
    try:
        if "gzip" in enc:
            data = gzip.decompress(data)
        elif "deflate" in enc:
            data = zlib.decompress(data)
    except Exception:
        pass
    ctype = res.header("content-type") or ""
    charset = "utf-8"
    if "charset=" in ctype:
        charset = ctype.split("charset=", 1)[1].split(";")[0].strip().strip('"') or "utf-8"
    try:
        return data.decode(charset, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def wait(seconds: float, cancel: threading.Event | None):
    if cancel is None:
        time.sleep(seconds)
    else:
        cancel.wait(seconds)
