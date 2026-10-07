"""Проба QUIC (HTTP/3): шлём настоящий Initial с ClientHello и смотрим, ответит ли сервер.

Полное соединение не поднимаем — нам нужен один факт: доходит ли UDP/443 до сервера
и возвращается ли ответ, когда в ClientHello стоит конкретное имя (SNI).
Initial-пакет шифруется ключами, выводимыми из Destination Connection ID (RFC 9001 §5.2),
так что DPI читает из него SNI так же, как из TLS поверх TCP.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

V1 = 0x00000001
SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
MIN_INITIAL = 1200

TLS_ALERTS = {40: "handshake_failure", 70: "protocol_version", 80: "internal_error", 86: "inappropriate_fallback",
              109: "missing_extension", 112: "unrecognized_name", 120: "no_application_protocol"}
TRANSPORT_ERRORS = {0x0: "NO_ERROR", 0x1: "INTERNAL_ERROR", 0x2: "CONNECTION_REFUSED", 0x7: "FRAME_ENCODING_ERROR",
                    0x8: "TRANSPORT_PARAMETER_ERROR", 0xA: "PROTOCOL_VIOLATION", 0xB: "INVALID_TOKEN"}


# --- ключи ----------------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


@dataclass
class Keys:
    key: bytes
    iv: bytes
    hp: bytes


def initial_keys(dcid: bytes, side: str) -> Keys:
    """side: 'client' или 'server'."""
    initial = hkdf_extract(SALT_V1, dcid)
    secret = hkdf_expand_label(initial, f"{side} in", 32)
    return Keys(hkdf_expand_label(secret, "quic key", 16), hkdf_expand_label(secret, "quic iv", 12),
                hkdf_expand_label(secret, "quic hp", 16))


def _hp_mask(hp: bytes, sample: bytes) -> bytes:
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


# --- varint ---------------------------------------------------------------

def varint(n: int, size: int | None = None) -> bytes:
    if size is None:
        size = 1 if n < 0x40 else 2 if n < 0x4000 else 4 if n < 0x40000000 else 8
    prefix = {1: 0x00, 2: 0x40, 4: 0x80, 8: 0xC0}[size]
    b = bytearray(n.to_bytes(size, "big"))
    b[0] |= prefix
    return bytes(b)


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    size = 1 << (buf[pos] >> 6)
    val = int.from_bytes(buf[pos:pos + size], "big") & ((1 << (8 * size - 2)) - 1)
    return val, pos + size


# --- ClientHello ----------------------------------------------------------

def _ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!HH", etype, len(body)) + body


def _tp(pid: int, value: bytes) -> bytes:
    return varint(pid) + varint(len(value)) + value


def client_hello(sni: str | None, scid: bytes, alpn: tuple[str, ...] = ("h3",)) -> bytes:
    exts = b""
    if sni:
        name = sni.encode("idna")
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        exts += _ext(0, struct.pack("!H", len(entry)) + entry)
    exts += _ext(10, struct.pack("!HHH", 4, 0x001D, 0x0017))                       # supported_groups
    sigs = struct.pack("!8H", 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
    exts += _ext(13, struct.pack("!H", len(sigs)) + sigs)                           # signature_algorithms
    protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    exts += _ext(16, struct.pack("!H", len(protos)) + protos)                       # ALPN
    exts += _ext(43, b"\x02\x03\x04")                                               # supported_versions: TLS 1.3
    exts += _ext(45, b"\x01\x01")                                                   # psk_key_exchange_modes
    share = struct.pack("!HH", 0x001D, 32) + os.urandom(32)                         # x25519: любые 32 байта валидны
    exts += _ext(51, struct.pack("!H", len(share)) + share)                         # key_share
    tp = (_tp(0x01, varint(30000)) + _tp(0x03, varint(65527)) + _tp(0x04, varint(1 << 20))
          + _tp(0x05, varint(1 << 18)) + _tp(0x06, varint(1 << 18)) + _tp(0x07, varint(1 << 18))
          + _tp(0x08, varint(16)) + _tp(0x09, varint(16)) + _tp(0x0F, scid))
    exts += _ext(0x39, tp)                                                          # quic_transport_parameters
    body = (b"\x03\x03" + os.urandom(32) + b"\x00"                                   # legacy_version, random, session_id
            + struct.pack("!H", 6) + b"\x13\x01\x13\x02\x13\x03" + b"\x01\x00"      # шифры TLS 1.3, без сжатия
            + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def sni_of(hello: bytes) -> str | None:
    """SNI из ClientHello — для самопроверки пакета в тестах."""
    pos = 4 + 2 + 32
    pos += 1 + hello[pos]
    pos += 2 + struct.unpack("!H", hello[pos:pos + 2])[0]
    pos += 1 + hello[pos]
    end = pos + 2 + struct.unpack("!H", hello[pos:pos + 2])[0]
    pos += 2
    while pos + 4 <= end:
        etype, elen = struct.unpack("!HH", hello[pos:pos + 4])
        if etype == 0:
            nlen = struct.unpack("!H", hello[pos + 7:pos + 9])[0]
            return hello[pos + 9:pos + 9 + nlen].decode("ascii")
        pos += 4 + elen
    return None


# --- пакеты ---------------------------------------------------------------

def build_initial(dcid: bytes, scid: bytes, sni: str | None, pn: int = 0) -> bytes:
    hello = client_hello(sni, scid)
    crypto = b"\x06" + varint(0) + varint(len(hello)) + hello
    pn_len = 4
    head = (bytes([0xC0 | (pn_len - 1)]) + struct.pack("!I", V1) + bytes([len(dcid)]) + dcid
            + bytes([len(scid)]) + scid + varint(0))                                 # token length = 0
    # длина поля Length — 2 байта; добиваем PADDING до минимального размера датаграммы
    overhead = len(head) + 2 + pn_len + 16
    payload = crypto + b"\x00" * max(0, MIN_INITIAL - overhead - len(crypto))
    head += varint(pn_len + len(payload) + 16, 2)
    pn_bytes = pn.to_bytes(pn_len, "big")
    return _protect(initial_keys(dcid, "client"), head, pn_bytes, payload)


def _protect(keys: Keys, head: bytes, pn_bytes: bytes, payload: bytes) -> bytes:
    pn = int.from_bytes(pn_bytes, "big")
    nonce = (int.from_bytes(keys.iv, "big") ^ pn).to_bytes(12, "big")
    ct = AESGCM(keys.key).encrypt(nonce, payload, head + pn_bytes)
    sample = ct[4 - len(pn_bytes):4 - len(pn_bytes) + 16]
    mask = _hp_mask(keys.hp, sample)
    first = head[0] ^ (mask[0] & 0x0F)
    masked_pn = bytes(b ^ m for b, m in zip(pn_bytes, mask[1:]))
    return bytes([first]) + head[1:] + masked_pn + ct


@dataclass
class Packet:
    kind: str                      # initial | handshake | retry | version_negotiation | 0rtt | short | garbage
    version: int = 0
    dcid: bytes = b""
    scid: bytes = b""
    payload: bytes | None = None   # расшифрованные кадры (только Initial)
    versions: tuple[int, ...] = ()


def parse_packet(data: bytes, keys: Keys | None = None) -> Packet:
    """Разобрать первый пакет датаграммы; Initial расшифровать, если даны ключи отправителя."""
    try:
        if not data or not data[0] & 0x80:
            return Packet("short" if data and data[0] & 0x40 else "garbage")
        version = struct.unpack("!I", data[1:5])[0]
        pos = 5
        dlen = data[pos]
        dcid = data[pos + 1:pos + 1 + dlen]
        pos += 1 + dlen
        slen = data[pos]
        scid = data[pos + 1:pos + 1 + slen]
        pos += 1 + slen
        if version == 0:
            vers = tuple(struct.unpack("!I", data[i:i + 4])[0] for i in range(pos, len(data) - 3, 4))
            return Packet("version_negotiation", 0, dcid, scid, versions=vers)
        ptype = (data[0] >> 4) & 0x03
        kind = ("initial", "0rtt", "handshake", "retry")[ptype]
        pkt = Packet(kind, version, dcid, scid)
        if kind != "initial" or keys is None:
            return pkt
        tlen, pos = read_varint(data, pos)
        pos += tlen
        length, pos = read_varint(data, pos)
        sample = data[pos + 4:pos + 20]
        mask = _hp_mask(keys.hp, sample)
        first = data[0] ^ (mask[0] & 0x0F)
        pn_len = (first & 0x03) + 1
        pn_bytes = bytes(b ^ m for b, m in zip(data[pos:pos + pn_len], mask[1:]))
        head = bytes([first]) + data[1:pos] + pn_bytes
        ct = data[pos + pn_len:pos + length]
        nonce = (int.from_bytes(keys.iv, "big") ^ int.from_bytes(pn_bytes, "big")).to_bytes(12, "big")
        pkt.payload = AESGCM(keys.key).decrypt(nonce, ct, head)
        return pkt
    except Exception:  # noqa: BLE001 — чужие байты из сети: любой сбой разбора = «не QUIC»
        return Packet("garbage")


def describe_frames(payload: bytes) -> tuple[str, str]:
    """('handshake'|'close'|'other', пояснение) по кадрам серверного Initial."""
    pos, seen_ack = 0, False
    try:
        while pos < len(payload):
            ftype = payload[pos]
            pos += 1
            if ftype in (0x00, 0x01):                         # PADDING, PING
                continue
            if ftype in (0x02, 0x03):                         # ACK
                seen_ack = True
                _, pos = read_varint(payload, pos)
                _, pos = read_varint(payload, pos)
                count, pos = read_varint(payload, pos)
                _, pos = read_varint(payload, pos)
                for _ in range(count):
                    _, pos = read_varint(payload, pos)
                    _, pos = read_varint(payload, pos)
                if ftype == 0x03:
                    for _ in range(3):
                        _, pos = read_varint(payload, pos)
                continue
            if ftype == 0x06:                                 # CRYPTO — ServerHello
                return "handshake", "сервер прислал ServerHello"
            if ftype in (0x1C, 0x1D):                         # CONNECTION_CLOSE
                code, pos = read_varint(payload, pos)
                if ftype == 0x1C:
                    _, pos = read_varint(payload, pos)
                rlen, pos = read_varint(payload, pos)
                reason = payload[pos:pos + rlen].decode("utf-8", "replace")
                if 0x100 <= code <= 0x1FF:
                    name = "TLS alert " + TLS_ALERTS.get(code - 0x100, str(code - 0x100))
                else:
                    name = TRANSPORT_ERRORS.get(code, hex(code))
                return "close", f"сервер закрыл соединение: {name}" + (f" ({reason})" if reason else "")
            break
    except (IndexError, ValueError):
        pass
    return "other", "сервер подтвердил пакет" if seen_ack else "ответ получен"


# --- проба -----------------------------------------------------------------

@dataclass
class QuicResult:
    answered: bool = False
    kind: str = "timeout"          # handshake | close | retry | version_negotiation | response | timeout | error
    detail: str = ""
    rtt_ms: float | None = None
    sent: int = 0


def probe(ip: str, sni: str | None, port: int = 443, timeout: float = 3.0,
          cancel: threading.Event | None = None) -> QuicResult:
    """Отправить Initial (с одним повтором) и дождаться первого осмысленного ответа."""
    res = QuicResult()
    dcid, scid = os.urandom(8), os.urandom(8)
    server_keys = initial_keys(dcid, "server")
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        sock = socket.socket(fam, socket.SOCK_DGRAM)
    except OSError as e:
        res.kind, res.detail = "error", str(e)
        return res
    try:
        sock.connect((ip, port))
        start = time.perf_counter()
        deadline = start + timeout
        resend_at = start
        pn = 0
        while True:
            now = time.perf_counter()
            if cancel is not None and cancel.is_set():
                res.detail = "отменено"
                return res
            if now >= deadline:
                res.kind, res.detail = "timeout", f"нет ответа за {timeout:.0f} s ({res.sent} пакет(а))"
                return res
            if now >= resend_at and res.sent < 3:
                sock.send(build_initial(dcid, scid, sni, pn))
                pn += 1
                res.sent += 1
                resend_at = now + 1.0
            sock.settimeout(max(0.05, min(deadline, resend_at) - time.perf_counter()))
            try:
                data = sock.recv(4096)
            except (socket.timeout, TimeoutError):
                continue
            pkt = parse_packet(data, server_keys)
            if pkt.kind in ("garbage", "short") or pkt.dcid != scid:
                continue                                        # не наш ответ — ждём дальше
            res.answered = True
            res.rtt_ms = (time.perf_counter() - start) * 1000
            if pkt.kind == "version_negotiation":
                res.kind = "version_negotiation"
                res.detail = "сервер предлагает другие версии QUIC: " + ", ".join(hex(v) for v in pkt.versions[:6])
            elif pkt.kind == "retry":
                res.kind, res.detail = "retry", "сервер ответил Retry (проверка адреса) — путь по UDP/443 жив"
            elif pkt.kind == "initial" and pkt.payload is not None:
                res.kind, res.detail = describe_frames(pkt.payload)
                if res.kind == "other":
                    res.kind = "response"
            else:
                res.kind, res.detail = "response", f"получен пакет {pkt.kind}"
            return res
    except OSError as e:
        # Windows отдаёт ICMP port unreachable как ConnectionResetError на recv
        res.kind = "error"
        res.detail = "порт UDP/443 закрыт (ICMP port unreachable)" if isinstance(e, ConnectionError) else str(e)
        return res
    finally:
        sock.close()
