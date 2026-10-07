"""Общие помощники: форматирование, классификация сетевых ошибок, IP-категории."""
from __future__ import annotations

import errno
import ipaddress
import socket
import ssl
import time


def human_bytes(n: int | float | None) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit, size in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= size:
            return f"{n / size:.2f} {unit}"
    return f"{int(n)} B"


def fmt_ms(ms: float | None) -> str:
    if ms is None:
        return "-"
    if ms >= 1000:
        return f"{ms / 1000:.2f} s"
    return f"{ms:.0f} ms" if ms >= 10 else f"{ms:.1f} ms"


class Timer:
    def __init__(self):
        self.t0 = time.perf_counter()

    def ms(self) -> float:
        return (time.perf_counter() - self.t0) * 1000


# Коды ошибок WinSock: на Windows socket-исключения приходят с ними, а не с errno.
_WSA = {
    10060: "timeout",       # WSAETIMEDOUT
    10061: "refused",       # WSAECONNREFUSED
    10054: "reset",         # WSAECONNRESET
    10053: "aborted",       # WSAECONNABORTED
    10065: "unreachable",   # WSAEHOSTUNREACH
    10051: "unreachable",   # WSAENETUNREACH
    10049: "badaddr",       # WSAEADDRNOTAVAIL
    10047: "nofamily",      # WSAEAFNOSUPPORT
}
_ERRNO = {
    errno.ETIMEDOUT: "timeout",
    errno.ECONNREFUSED: "refused",
    errno.ECONNRESET: "reset",
    errno.ECONNABORTED: "aborted",
    errno.EHOSTUNREACH: "unreachable",
    errno.ENETUNREACH: "unreachable",
    errno.EADDRNOTAVAIL: "badaddr",
    errno.EAFNOSUPPORT: "nofamily",
    errno.EPIPE: "reset",
}

ERROR_TEXT = {
    "timeout": "таймаут (пакеты отбрасываются молча)",
    "refused": "соединение отклонено (RST)",
    "reset": "соединение сброшено (RST посреди сессии)",
    "aborted": "соединение прервано локальным стеком",
    "unreachable": "сеть/хост недоступны (ICMP unreachable или нет маршрута)",
    "badaddr": "адрес недоступен локально",
    "nofamily": "семейство адресов не поддерживается (нет IPv6?)",
    "eof": "сервер закрыл соединение без ответа",
    "tls_verify": "сертификат не прошёл проверку",
    "tls_proto": "ошибка TLS-протокола",
    "proxy": "прокси отказал",
    "dns": "имя не разрешилось",
    "http": "некорректный HTTP-ответ",
    "cancel": "отменено",
    "other": "ошибка",
}


def classify_error(exc: BaseException) -> str:
    """Свести исключение к короткому коду — по нему строится диагноз."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls_verify"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ssl.SSLEOFError):
        return "eof"
    if isinstance(exc, ssl.SSLZeroReturnError):
        return "eof"
    if isinstance(exc, ssl.SSLError):
        reason = (getattr(exc, "reason", "") or "").upper()
        text = str(exc).upper()
        if "EOF" in reason or "EOF OCCURRED" in text:
            return "eof"
        if "RESET" in text:
            return "reset"
        return "tls_proto"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, ConnectionAbortedError):
        return "aborted"
    if isinstance(exc, OSError):
        code = getattr(exc, "winerror", None)
        if code in _WSA:
            return _WSA[code]
        if exc.errno in _WSA:
            return _WSA[exc.errno]
        if exc.errno in _ERRNO:
            return _ERRNO[exc.errno]
    return "other"


def error_text(exc: BaseException) -> str:
    code = classify_error(exc)
    base = ERROR_TEXT.get(code, "ошибка")
    msg = str(exc) or exc.__class__.__name__
    return f"{base}: {msg}" if code != "other" else msg


# --- IP-категории ---------------------------------------------------------

def ip_kind(ip: str) -> str:
    """public / private / loopback / unspecified / linklocal / cgnat / reserved."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if a.is_unspecified:
        return "unspecified"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "linklocal"
    if isinstance(a, ipaddress.IPv4Address) and a in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    if a.is_private:
        return "private"
    if a.is_reserved or a.is_multicast:
        return "reserved"
    return "public"


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def family_name(fam: int) -> str:
    return "IPv6" if fam == socket.AF_INET6 else "IPv4"


def family_of(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET
