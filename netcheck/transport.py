"""TCP, HTTP CONNECT через прокси, TLS-рукопожатие и разбор сертификата.

Всё сделано на «голых» сокетах, чтобы контролировать, на какой IP идёт
соединение (никакого повторного резолва внутри HTTP-библиотеки), и мерить
каждую фазу отдельно.
"""
from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from dataclasses import dataclass, field

from .util import Timer, classify_error, family_of

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID
except Exception:  # pragma: no cover - cryptography опциональна
    x509 = None


class NetError(Exception):
    """Ошибка с кодом фазы и кодом причины (timeout/refused/reset/...)."""

    def __init__(self, phase: str, exc: BaseException | None = None, code: str | None = None, text: str = ""):
        self.phase = phase
        self.exc = exc
        self.code = code or (classify_error(exc) if exc else "other")
        self.text = text or (str(exc) if exc else "")
        super().__init__(f"{phase}: {self.code}: {self.text}")


@dataclass
class Route:
    """Как ходим к цели: напрямую или через HTTP-прокси (CONNECT)."""
    kind: str = "direct"           # direct | proxy
    proxy_host: str = ""
    proxy_port: int = 0
    origin: str = ""               # откуда взят прокси: manual/registry/pac/env

    @property
    def label(self) -> str:
        if self.kind == "direct":
            return "напрямую"
        return f"через прокси {self.proxy_host}:{self.proxy_port}"

    @property
    def is_proxy(self) -> bool:
        return self.kind == "proxy"


DIRECT = Route()


# --- TCP -------------------------------------------------------------------

def tcp_connect(ip: str, port: int, timeout: float) -> tuple[socket.socket, float]:
    fam = family_of(ip)
    sock = socket.socket(fam, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t = Timer()
    try:
        sock.connect((ip, port))
    except BaseException as e:
        sock.close()
        raise NetError("tcp", e) from e
    return sock, t.ms()


def _resolve_first(host: str, port: int, family: int = 0) -> str:
    infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    return infos[0][4][0]


def proxy_connect(route: Route, host: str, port: int, timeout: float) -> tuple[socket.socket, dict]:
    """TCP до прокси + CONNECT host:port. Возвращает сокет-туннель и тайминги."""
    info: dict = {}
    try:
        pip = _resolve_first(route.proxy_host, route.proxy_port)
    except BaseException as e:
        raise NetError("proxy", e, code="dns", text=f"не разрешается имя прокси {route.proxy_host}") from e
    sock, tcp_ms = tcp_connect(pip, route.proxy_port, timeout)
    info["proxy_ip"] = pip
    info["proxy_tcp_ms"] = tcp_ms
    t = Timer()
    hostport = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    req = (f"CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n"
           f"User-Agent: WebNetCheck\r\nProxy-Connection: keep-alive\r\n\r\n").encode()
    try:
        sock.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise NetError("proxy", code="eof", text="прокси закрыл соединение на CONNECT")
            buf += chunk
            if len(buf) > 65536:
                raise NetError("proxy", code="http", text="слишком длинный ответ прокси")
    except NetError:
        sock.close()
        raise
    except BaseException as e:
        sock.close()
        raise NetError("proxy", e) from e
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    status_line = head.split("\r\n", 1)[0]
    parts = status_line.split(" ", 2)
    code = parts[1] if len(parts) > 1 else "?"
    info["connect_ms"] = t.ms()
    info["connect_status"] = status_line
    if code != "200":
        sock.close()
        hint = {"407": "нужна аутентификация на прокси",
                "403": "прокси запрещает этот адрес (политика)",
                "502": "прокси не смог подключиться к цели",
                "503": "прокси/цель недоступны",
                "504": "прокси не дождался цели"}.get(code, "")
        raise NetError("proxy", code="proxy", text=f"{status_line} {hint}".strip())
    return sock, info


def open_stream(route: Route, host: str, port: int, ip: str | None, timeout: float) -> tuple[socket.socket, dict]:
    """Открыть TCP-поток к host:port — напрямую на ip или туннелем через прокси."""
    if route.is_proxy:
        sock, info = proxy_connect(route, host, port, timeout)
        info["tcp_ms"] = info.get("proxy_tcp_ms", 0) + info.get("connect_ms", 0)
        info["remote"] = f"{route.proxy_host}:{route.proxy_port} → {host}:{port}"
        return sock, info
    if not ip:
        raise NetError("tcp", code="dns", text="нет IP для подключения")
    sock, ms = tcp_connect(ip, port, timeout)
    return sock, {"tcp_ms": ms, "remote": f"{ip}:{port}"}


# --- TLS -------------------------------------------------------------------

_TLS_VER = {
    "1.2": ssl.TLSVersion.TLSv1_2,
    "1.3": ssl.TLSVersion.TLSv1_3,
}


_CTX_CACHE: dict[tuple, ssl.SSLContext] = {}
_CTX_LOCK = threading.Lock()


def make_context(verify: bool = True, only: str | None = None, alpn=("h2", "http/1.1"),
                 ca_file: str | None = None, check_hostname: bool = True) -> ssl.SSLContext:
    """Контекст кэшируется: загрузка хранилища сертификатов Windows на каждое соединение
    стоит сотни миллисекунд, а при 80 хостах параллельно — секунды."""
    key = (verify, only, tuple(alpn or ()), ca_file, check_hostname)
    with _CTX_LOCK:
        ctx = _CTX_CACHE.get(key)
        if ctx is None:
            ctx = _build_context(verify, only, alpn, ca_file, check_hostname)
            _CTX_CACHE[key] = ctx
    return ctx


def _build_context(verify, only, alpn, ca_file, check_hostname) -> ssl.SSLContext:
    ctx = ssl.create_default_context()  # Windows: системное хранилище + SSL_CERT_FILE
    # Python 3.13 включил VERIFY_X509_STRICT: он отвергает, например, корпоративные CA без
    # Authority Key Identifier, которые браузеры и Windows принимают. Проверяем «как браузер».
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif not check_hostname:
        ctx.check_hostname = False
    if only:
        v = _TLS_VER[only]
        ctx.minimum_version = v
        ctx.maximum_version = v
    if alpn:
        try:
            ctx.set_alpn_protocols(list(alpn))
        except NotImplementedError:
            pass
    return ctx


@dataclass
class TlsInfo:
    version: str = ""
    cipher: str = ""
    alpn: str | None = None
    verified: bool = False
    verify_error: str = ""
    handshake_ms: float = 0.0
    sni: str | None = None
    cert: dict = field(default_factory=dict)
    chain: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": self.version, "cipher": self.cipher, "alpn": self.alpn,
            "verified": self.verified, "verify_error": self.verify_error,
            "handshake_ms": round(self.handshake_ms, 1), "sni": self.sni,
            "cert": self.cert, "chain": self.chain,
        }


def tls_wrap(sock: socket.socket, sni: str | None, timeout: float, verify: bool = True,
             only: str | None = None, ca_file: str | None = None,
             alpn=("h2", "http/1.1")) -> tuple[ssl.SSLSocket, TlsInfo]:
    try:
        ctx = make_context(verify=verify, only=only, alpn=alpn, ca_file=ca_file, check_hostname=sni is not None)
    except (OSError, ssl.SSLError) as e:
        sock.close()
        raise NetError("tls", e, code="other", text=f"не удалось подготовить TLS (файл CA?): {e}") from e
    sock.settimeout(timeout)
    t = Timer()
    try:
        ss = ctx.wrap_socket(sock, server_hostname=sni)
    except BaseException as e:
        try:
            sock.close()
        except OSError:
            pass
        raise NetError("tls", e) from e
    info = TlsInfo(handshake_ms=t.ms(), sni=sni)
    info.version = ss.version() or ""
    c = ss.cipher()
    info.cipher = c[0] if c else ""
    info.alpn = ss.selected_alpn_protocol()
    info.verified = verify
    der = ss.getpeercert(binary_form=True)
    if der:
        info.cert = parse_cert(der, sni)
    info.chain = _chain_subjects(ss)
    return ss, info


def _chain_subjects(ss: ssl.SSLSocket) -> list[str]:
    getter = getattr(ss, "get_unverified_chain", None)  # Python 3.13+
    if not getter:
        return []
    out = []
    try:
        for item in getter() or []:
            der = item.public_bytes(ssl._ssl.ENCODING_DER) if hasattr(item, "public_bytes") else item
            p = parse_cert(der, None)
            out.append(f"{p.get('subject', '?')}  ←  {p.get('issuer', '?')}")
    except Exception:
        return out
    return out


def _name(n) -> str:
    try:
        parts = []
        for oid, label in ((NameOID.COMMON_NAME, "CN"), (NameOID.ORGANIZATION_NAME, "O"),
                           (NameOID.COUNTRY_NAME, "C")):
            vals = n.get_attributes_for_oid(oid)
            if vals:
                parts.append(f"{label}={vals[0].value}")
        return ", ".join(parts) or n.rfc4514_string()
    except Exception:
        return str(n)


def parse_cert(der: bytes, hostname: str | None) -> dict:
    if x509 is None:
        return {"note": "модуль cryptography не установлен — детали сертификата недоступны"}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        return {"note": f"не удалось разобрать сертификат: {e}"}
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc)
    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)]
        san += [str(v) for v in ext.value.get_values_for_type(x509.IPAddress)]
    except Exception:
        pass
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_s = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_s = f"EC {key.curve.name}"
    else:
        key_s = key.__class__.__name__.replace("PublicKey", "")
    info = {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "san": san[:50],
        "san_count": len(san),
        "not_before": nb.strftime("%Y-%m-%d"),
        "not_after": na.strftime("%Y-%m-%d"),
        "days_left": (na - now).days,
        "serial": format(cert.serial_number, "x"),
        "key": key_s,
        "signature": getattr(cert.signature_hash_algorithm, "name", "?"),
        "self_signed": cert.issuer == cert.subject,
    }
    if hostname:
        info["name_match"] = _host_matches(hostname, san)
    return info


def _host_matches(host: str, san: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for name in san:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


# Продукты, которые перехватывают TLS (корпоративные шлюзы, антивирусы, DPI).
INTERCEPTION_MARKERS = [
    "kaspersky", "eset", "dr.web", "drweb", "avast", "avg ", "bitdefender", "sophos",
    "fortinet", "fortigate", "zscaler", "netskope", "palo alto", "paloalto", "check point",
    "checkpoint", "blue coat", "bluecoat", "symantec web", "cisco umbrella", "mcafee web",
    "forcepoint", "websense", "barracuda", "usergate", "ideco", "kerio", "traffic inspector",
    "squid", "mitmproxy", "interception", "intercept", "charles proxy", "fiddler", "burp", "proxy ca", "egress", "inspection",
]


def interception_marker(issuer: str) -> str | None:
    low = issuer.lower()
    for m in INTERCEPTION_MARKERS:
        if m in low:
            return m.strip()
    return None
