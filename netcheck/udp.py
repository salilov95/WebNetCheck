"""UDP наружу: STUN Binding Request (RFC 5389) к нескольким публичным серверам.

Зачем: голос и видео (Discord, звонки, WebRTC) и HTTP/3 идут по UDP. HTTP-прокси
UDP не переносит, поэтому «сайт открывается, а голоса нет» — типичный симптом.
STUN отвечает, с какого внешнего адреса и порта сервер увидел наш пакет.
"""
from __future__ import annotations

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass

MAGIC = 0x2112A442
SERVERS: tuple[tuple[str, int], ...] = (
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.sipnet.ru", 3478),
    ("stun.nextcloud.com", 443),
)


@dataclass
class StunReply:
    server: str
    ip: str = ""                   # куда слали
    ok: bool = False
    mapped_ip: str = ""
    mapped_port: int = 0
    rtt_ms: float | None = None
    error: str = ""                # dns | timeout | send: ...


def build_request(txid: bytes | None = None) -> tuple[bytes, bytes]:
    txid = txid or os.urandom(12)
    return struct.pack("!HHI", 0x0001, 0, MAGIC) + txid, txid


def parse_response(data: bytes, txid: bytes) -> tuple[str, int] | None:
    """Вернуть (ip, port) из XOR-MAPPED-ADDRESS / MAPPED-ADDRESS или None, если это не наш ответ."""
    if len(data) < 20:
        return None
    mtype, mlen, magic = struct.unpack("!HHI", data[:8])
    if mtype != 0x0101 or magic != MAGIC or data[8:20] != txid:
        return None
    pos, end = 20, min(len(data), 20 + mlen)
    plain = None
    while pos + 4 <= end:
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        val = data[pos + 4:pos + 4 + alen]
        pos += 4 + alen + (-alen % 4)
        if atype not in (0x0020, 0x0001) or len(val) < 8:
            continue
        fam = val[1]
        port = struct.unpack("!H", val[2:4])[0]
        raw = val[4:8] if fam == 1 else val[4:20]
        if fam == 2 and len(raw) < 16:
            continue
        if atype == 0x0020:
            port ^= MAGIC >> 16
            key = struct.pack("!I", MAGIC) + txid
            raw = bytes(b ^ k for b, k in zip(raw, key))
        ip = socket.inet_ntop(socket.AF_INET if fam == 1 else socket.AF_INET6, raw)
        if atype == 0x0020:
            return ip, port
        plain = (ip, port)
    return plain


def probe(servers=SERVERS, timeout: float = 2.0, attempts: int = 2,
          cancel: threading.Event | None = None) -> list[StunReply]:
    """Опросить серверы с одного сокета: одинаковый локальный порт позволяет сравнить отображение NAT."""
    replies = [StunReply(f"{h}:{p}") for h, p in servers]
    pending: dict[bytes, tuple[StunReply, float]] = {}
    targets: list[tuple[StunReply, tuple[str, int]]] = []
    for rep, (host, port) in zip(replies, servers):
        try:
            rep.ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
            targets.append((rep, (rep.ip, port)))
        except OSError:
            rep.error = "dns"
    if not targets:
        return replies
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 0))
        for _ in range(attempts):
            if cancel is not None and cancel.is_set():
                break
            for rep, addr in targets:
                if rep.ok:
                    continue
                req, txid = build_request()
                try:
                    sock.sendto(req, addr)
                    pending[txid] = (rep, time.perf_counter())
                except OSError as e:
                    rep.error = f"send: {e}"
            deadline = time.perf_counter() + timeout
            while any(not r.ok for r, _ in targets):
                left = deadline - time.perf_counter()
                if left <= 0 or (cancel is not None and cancel.is_set()):
                    break
                sock.settimeout(min(left, 0.25))
                try:
                    data, _src = sock.recvfrom(2048)
                except (socket.timeout, TimeoutError):
                    continue
                except OSError:
                    # Windows: ICMP port unreachable приходит как WSAECONNRESET на UDP-сокете
                    continue
                txid = data[8:20]
                if txid not in pending:
                    continue
                rep, sent = pending[txid]
                mapped = parse_response(data, txid)
                if mapped and not rep.ok:
                    rep.ok, rep.error = True, ""
                    rep.mapped_ip, rep.mapped_port = mapped
                    rep.rtt_ms = (time.perf_counter() - sent) * 1000
            if all(r.ok for r, _ in targets):
                break
    finally:
        sock.close()
    for rep, _ in targets:
        if not rep.ok and not rep.error:
            rep.error = "timeout"
    return replies
