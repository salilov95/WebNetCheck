"""Системные настройки прокси Windows: WinINET (браузеры), PAC, WinHTTP, переменные окружения."""
from __future__ import annotations

import locale
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

from .transport import Route

IS_WINDOWS = sys.platform == "win32"


@dataclass
class ProxySettings:
    wininet_enabled: bool = False
    wininet_server: str = ""        # "host:port" или "http=h:p;https=h:p"
    wininet_bypass: str = ""
    pac_url: str = ""
    auto_detect: bool = False
    winhttp_text: str = ""
    env: dict[str, str] = field(default_factory=dict)
    pac_candidates: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _reg_read() -> dict:
    import winreg
    out = {}
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"):
                try:
                    out[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    pass
    except OSError:
        pass
    return out


def _winhttp() -> str:
    try:
        p = subprocess.run(["netsh", "winhttp", "show", "proxy"], capture_output=True, timeout=5,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        raw = p.stdout
    except Exception as e:  # noqa: BLE001
        return f"netsh недоступен: {e}"
    encodings = ["utf-8"]
    try:
        import ctypes
        encodings.append(f"cp{ctypes.windll.kernel32.GetOEMCP()}")
    except Exception:  # noqa: BLE001
        pass
    encodings += ["cp866", locale.getpreferredencoding(False)]
    for enc in encodings:
        try:
            text = raw.decode(enc)  # strict: UTF-8 не пройдёт на OEM-байтах, поэтому он первый
            return "\n".join(l.strip() for l in text.splitlines() if l.strip())
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def read_settings() -> ProxySettings:
    s = ProxySettings()
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        if os.environ.get(k):
            s.env[k] = os.environ[k]
    if IS_WINDOWS:
        r = _reg_read()
        s.wininet_enabled = bool(r.get("ProxyEnable", 0))
        s.wininet_server = str(r.get("ProxyServer", "") or "")
        s.wininet_bypass = str(r.get("ProxyOverride", "") or "")
        s.pac_url = str(r.get("AutoConfigURL", "") or "")
        s.auto_detect = bool(r.get("AutoDetect", 0))
        s.winhttp_text = _winhttp()
    return s


def _parse_hostport(spec: str) -> tuple[str, int] | None:
    spec = spec.strip()
    spec = re.sub(r"^[a-z]+://", "", spec, flags=re.I).rstrip("/")
    if "@" in spec:
        spec = spec.split("@", 1)[1]
    m = re.match(r"^\[?([^\]\s]+?)\]?:(\d+)$", spec)
    if m:
        return m.group(1), int(m.group(2))
    if spec:
        return spec, 8080
    return None


def parse_manual(spec: str) -> Route | None:
    hp = _parse_hostport(spec)
    if not hp:
        return None
    return Route("proxy", hp[0], hp[1], origin="manual")


def wininet_route(s: ProxySettings) -> Route | None:
    """Прокси из настроек «Параметры → Сеть → Прокси» (ручной сервер)."""
    if not (s.wininet_enabled and s.wininet_server):
        return None
    server = s.wininet_server
    if "=" in server:  # протокол-специфичный: http=..;https=..;socks=..
        parts = dict(p.split("=", 1) for p in server.split(";") if "=" in p)
        server = parts.get("https") or parts.get("http") or ""
        if not server:
            return None
    hp = _parse_hostport(server)
    return Route("proxy", hp[0], hp[1], origin="registry") if hp else None


def env_route(s: ProxySettings) -> Route | None:
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if s.env.get(k):
            hp = _parse_hostport(s.env[k])
            if hp:
                return Route("proxy", hp[0], hp[1], origin=f"env {k}")
    return None


_PAC_PROXY = re.compile(r"PROXY\s+([A-Za-z0-9.\-\[\]:]+:\d+)", re.I)


def pac_candidates(pac_text: str) -> list[str]:
    seen: list[str] = []
    for m in _PAC_PROXY.finditer(pac_text):
        if m.group(1) not in seen:
            seen.append(m.group(1))
    return seen


def bypassed(host: str, bypass: str) -> bool:
    """Попадает ли хост в исключения WinINET (ProxyOverride: '*.corp;10.*;<local>')."""
    host = host.lower()
    for raw in bypass.split(";"):
        pat = raw.strip().lower()
        if not pat:
            continue
        if pat == "<local>":
            if "." not in host:
                return True
            continue
        rx = "^" + re.escape(pat).replace(r"\*", ".*") + "$"
        if re.match(rx, host):
            return True
    return False
