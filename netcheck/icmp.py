"""ICMP echo, traceroute и поиск Path MTU.

Windows: прямые вызовы IcmpSendEcho / Icmp6SendEcho2 из iphlpapi.dll —
не нужны права администратора и не нужно парсить локализованный вывод ping.exe.
Другие ОС (только для разработки): ping из системы с LC_ALL=C.
"""
from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .util import family_of

IS_WINDOWS = sys.platform == "win32"

# Коды статуса IP_* из ipexport.h
IP_STATUS = {
    0: "success",
    11001: "buffer_too_small",
    11002: "net_unreachable",
    11003: "host_unreachable",
    11004: "protocol_unreachable",
    11005: "port_unreachable",
    11006: "no_resources",
    11007: "bad_option",
    11008: "hw_error",
    11009: "packet_too_big",
    11010: "timeout",
    11011: "bad_request",
    11012: "bad_route",
    11013: "ttl_expired",
    11014: "ttl_expired_reassembly",
    11015: "param_problem",
    11016: "source_quench",
    11017: "option_too_big",
    11018: "bad_destination",
    11032: "neg_advert",  # IPv6: ICMPv6 neighbor
    11050: "general_failure",
}
STATUS_TEXT = {
    "success": "ответ получен",
    "timeout": "нет ответа (таймаут)",
    "ttl_expired": "TTL истёк в пути",
    "net_unreachable": "сеть недоступна",
    "host_unreachable": "хост недоступен",
    "port_unreachable": "порт недоступен",
    "protocol_unreachable": "протокол недоступен",
    "packet_too_big": "пакет слишком велик (нужна фрагментация, DF)",
    "general_failure": "общая ошибка (часто — нет маршрута/адреса этого семейства)",
    "bad_destination": "неверный адрес назначения",
}


class IcmpUnavailable(Exception):
    pass


@dataclass
class EchoReply:
    status: str          # ключ из IP_STATUS
    rtt_ms: float | None
    from_ip: str | None

    @property
    def ok(self) -> bool:
        return self.status == "success"


# --- Windows -----------------------------------------------------------------

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _ip = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)

    class IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                    ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

    _ip.IcmpCreateFile.restype = wintypes.HANDLE
    _ip.IcmpCreateFile.argtypes = []
    _ip.Icmp6CreateFile.restype = wintypes.HANDLE
    _ip.Icmp6CreateFile.argtypes = []
    _ip.IcmpCloseHandle.restype = wintypes.BOOL
    _ip.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    _ip.IcmpSendEcho.restype = wintypes.DWORD
    _ip.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                                 ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD]
    _ip.Icmp6SendEcho2.restype = wintypes.DWORD
    _ip.Icmp6SendEcho2.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.WORD,
                                   ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
                                   wintypes.DWORD, wintypes.DWORD]
    _INVALID = ctypes.c_void_p(-1).value
    _IP_FLAG_DF = 0x02
    _AF_INET6_WIN = 23

    def _status_name(code: int) -> str:
        return IP_STATUS.get(code, f"status_{code}")

    def _echo_v4(ip: str, timeout_ms: int, size: int, ttl: int, df: bool) -> EchoReply:
        h = _ip.IcmpCreateFile()
        if not h or h == _INVALID:
            raise IcmpUnavailable(f"IcmpCreateFile: ошибка {ctypes.get_last_error()}")
        try:
            data = ctypes.create_string_buffer(b"a" * max(size, 1), max(size, 1))
            opts = IP_OPTION_INFORMATION(Ttl=ttl, Tos=0, Flags=_IP_FLAG_DF if df else 0,
                                         OptionsSize=0, OptionsData=None)
            rsize = max(size, 1) + 1024
            reply = ctypes.create_string_buffer(rsize)
            dst = int.from_bytes(socket.inet_aton(ip), "little")  # IPAddr — порядок байт сети в памяти
            n = _ip.IcmpSendEcho(h, dst, data, size, ctypes.byref(opts), reply, rsize, timeout_ms)
            if n == 0:
                return EchoReply(_status_name(ctypes.get_last_error()), None, None)
            raw = reply.raw
            # ICMP_ECHO_REPLY и ICMP_ECHO_REPLY32 совпадают по первым 16 байтам:
            # Address(4) Status(4) RoundTripTime(4) DataSize(2) Reserved(2)
            addr, status, rtt = struct.unpack_from("<4sII", raw, 0)
            return EchoReply(_status_name(status), float(rtt), socket.inet_ntoa(addr))
        finally:
            _ip.IcmpCloseHandle(h)

    def _echo_v6(ip: str, timeout_ms: int, size: int, ttl: int) -> EchoReply:
        h = _ip.Icmp6CreateFile()
        if not h or h == _INVALID:
            raise IcmpUnavailable(f"Icmp6CreateFile: ошибка {ctypes.get_last_error()}")
        try:
            scope = 0
            addr = ip
            if "%" in ip:
                addr, sc = ip.split("%", 1)
                scope = int(sc) if sc.isdigit() else 0
            src = ctypes.create_string_buffer(struct.pack("<hHI16sI", _AF_INET6_WIN, 0, 0, b"\0" * 16, 0), 28)
            dst = ctypes.create_string_buffer(
                struct.pack("<hHI16sI", _AF_INET6_WIN, 0, 0, socket.inet_pton(socket.AF_INET6, addr), scope), 28)
            data = ctypes.create_string_buffer(b"a" * max(size, 1), max(size, 1))
            opts = IP_OPTION_INFORMATION(Ttl=ttl, Tos=0, Flags=0, OptionsSize=0, OptionsData=None)
            rsize = max(size, 1) + 1024
            reply = ctypes.create_string_buffer(rsize)
            n = _ip.Icmp6SendEcho2(h, None, None, None, src, dst, data, size, ctypes.byref(opts),
                                   reply, rsize, timeout_ms)
            if n == 0:
                return EchoReply(_status_name(ctypes.get_last_error()), None, None)
            raw = reply.raw
            # ICMPV6_ECHO_REPLY: IPV6_ADDRESS_EX (packed, 26 байт: port, flowinfo, addr[16], scope),
            # затем Status и RoundTripTime, выровненные на 4 → смещения 28 и 32.
            status, rtt = struct.unpack_from("<II", raw, 28)
            if status not in IP_STATUS:          # на случай иной упаковки структуры
                st2, rtt2 = struct.unpack_from("<II", raw, 26)
                if st2 in IP_STATUS:
                    status, rtt = st2, rtt2
            from_ip = socket.inet_ntop(socket.AF_INET6, raw[6:22])
            return EchoReply(_status_name(status), float(rtt), from_ip)
        finally:
            _ip.IcmpCloseHandle(h)


# --- Не-Windows (только для разработки) --------------------------------------

_RTT_RE = re.compile(r"time[=<]([\d.]+)\s*ms")
_FROM_RE = re.compile(r"[Ff]rom ([0-9a-fA-F:.]+)")


def _echo_posix(ip: str, timeout_ms: int, size: int, ttl: int, df: bool) -> EchoReply:
    exe = "ping"
    args = [exe, "-n", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), "-s", str(size), "-t", str(ttl)]
    if ":" in ip:
        args.insert(1, "-6")
    elif df:
        args += ["-M", "do"]
    args.append(ip)
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout_ms / 1000 + 3,
                             env={**os.environ, "LC_ALL": "C"}).stdout
    except FileNotFoundError as e:
        raise IcmpUnavailable("утилита ping не найдена") from e
    except subprocess.TimeoutExpired:
        return EchoReply("timeout", None, None)
    if "Time to live exceeded" in out or "Time exceeded" in out:
        m = _FROM_RE.search(out)
        return EchoReply("ttl_expired", None, m.group(1) if m else None)
    if "too long" in out or "Frag needed" in out or "mtu" in out.lower():
        return EchoReply("packet_too_big", None, None)
    m = _RTT_RE.search(out)
    if m:
        f = re.search(r"bytes from ([0-9a-fA-F:.]+)", out)
        return EchoReply("success", float(m.group(1)), f.group(1) if f else ip)
    if "Unreachable" in out:
        return EchoReply("host_unreachable", None, None)
    return EchoReply("timeout", None, None)


# --- Публичный API -----------------------------------------------------------

def echo(ip: str, timeout_ms: int = 1500, size: int = 32, ttl: int = 128, df: bool = False) -> EchoReply:
    if IS_WINDOWS:
        if family_of(ip) == socket.AF_INET6:
            return _echo_v6(ip, timeout_ms, size, ttl)
        return _echo_v4(ip, timeout_ms, size, ttl, df)
    return _echo_posix(ip, timeout_ms, size, ttl, df)


@dataclass
class PingStats:
    sent: int
    received: int
    rtts: list[float]
    statuses: list[str]

    @property
    def loss_pct(self) -> float:
        return 100.0 * (self.sent - self.received) / self.sent if self.sent else 0.0

    @property
    def avg(self) -> float | None:
        return sum(self.rtts) / len(self.rtts) if self.rtts else None

    @property
    def jitter(self) -> float | None:
        if len(self.rtts) < 2:
            return None
        diffs = [abs(a - b) for a, b in zip(self.rtts, self.rtts[1:])]
        return sum(diffs) / len(diffs)


def ping(ip: str, count: int = 4, timeout_ms: int = 1500, size: int = 32,
         cancel: threading.Event | None = None) -> PingStats:
    st = PingStats(0, 0, [], [])
    for i in range(count):
        if cancel is not None and cancel.is_set():
            break
        r = echo(ip, timeout_ms, size)
        st.sent += 1
        st.statuses.append(r.status)
        if r.ok:
            st.received += 1
            st.rtts.append(r.rtt_ms or 0.0)
        if i < count - 1 and cancel is not None:
            cancel.wait(0.2)
    return st


def traceroute(ip: str, max_hops: int = 30, timeout_ms: int = 1500, probes: int = 2,
               cancel: threading.Event | None = None) -> list[tuple[int, str | None, float | None, bool]]:
    """Возвращает [(ttl, ip|None, rtt|None, достигнут_ли_адрес)] до цели включительно.

    TTL опрашиваются параллельно пачками — так 30 хопов проходят за пару секунд.
    """
    def probe(ttl: int):
        best = (ttl, None, None, False)
        for _ in range(probes):
            if cancel is not None and cancel.is_set():
                break
            r = echo(ip, timeout_ms, 32, ttl)
            if r.status == "success":
                return ttl, r.from_ip or ip, r.rtt_ms, True
            if r.status == "ttl_expired" and r.from_ip:
                return ttl, r.from_ip, r.rtt_ms, False
            if r.status in ("host_unreachable", "net_unreachable") and r.from_ip:
                best = (ttl, r.from_ip, r.rtt_ms, False)
        return best

    hops: list = []
    batch = 8
    for start in range(1, max_hops + 1, batch):
        if cancel is not None and cancel.is_set():
            break
        ttls = list(range(start, min(start + batch, max_hops + 1)))
        with ThreadPoolExecutor(max_workers=len(ttls)) as ex:
            results = list(ex.map(probe, ttls))
        for res in results:
            hops.append(res)
            if res[3]:
                return hops
    return hops


def path_mtu_v4(ip: str, timeout_ms: int = 1200, cancel: threading.Event | None = None) -> tuple[int | None, str]:
    """Бинарный поиск максимального ICMP-пакета с DF. Возвращает (MTU, пояснение)."""
    def works(payload: int) -> str:
        for _ in range(2):  # повтор — чтобы одиночная потеря не занизила MTU
            r = echo(ip, timeout_ms, payload, 128, df=True)
            if r.ok:
                return "ok"
            if r.status == "packet_too_big":
                return "big"
        return "lost"

    if cancel is not None and cancel.is_set():
        return None, "отменено"
    if works(56) != "ok":
        return None, "ICMP до цели не проходит — Path MTU по ICMP не определить"
    if works(1472) == "ok":
        return 1500, "пакеты 1500 байт с DF проходят"
    lo, hi = 56, 1472  # lo — проходит, hi — не проходит
    while hi - lo > 1:
        if cancel is not None and cancel.is_set():
            return None, "отменено"
        mid = (lo + hi) // 2
        if works(mid) == "ok":
            lo = mid
        else:
            hi = mid
    return lo + 28, f"максимальный payload с DF = {lo} байт (+28 байт заголовков IP/ICMP)"
