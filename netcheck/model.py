"""Модель результатов: одна проверка = один Check, весь прогон = Report."""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"

    @property
    def rank(self) -> int:
        return {"FAIL": 4, "WARN": 3, "OK": 2, "INFO": 1, "SKIP": 0}[self.value]


def worst(statuses) -> Status:
    """Худший статус из набора (FAIL > WARN > OK > INFO > SKIP)."""
    result = Status.SKIP
    for s in statuses:
        if s.rank > result.rank:
            result = s
    return result


# Слои в порядке модели «снизу вверх». Порядок важен для GUI и отчёта.
LAYERS: list[tuple[str, str]] = [
    ("proxy", "Выход в сеть"),
    ("dns", "DNS"),
    ("icmp", "ICMP"),
    ("path", "Маршрут / MTU"),
    ("tcp", "TCP"),
    ("tls", "TLS"),
    ("http", "HTTP"),
    ("hosts", "Зависимости"),
    ("api", "API-пробы"),
    ("content", "Целостность"),
]
LAYER_TITLES = dict(LAYERS)


@dataclass
class Check:
    layer: str                 # ключ из LAYERS
    title: str                 # что проверяли: «A через 8.8.8.8»
    target: str                # хост / URL / IP
    status: Status
    summary: str = ""          # одна строка результата
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: float | None = None
    family: str | None = None  # "IPv4" / "IPv6" / None
    tags: list[str] = field(default_factory=list)  # машинные метки для диагноза

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Diagnosis:
    severity: Status
    title: str
    explanation: str
    next_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class HostRow:
    host: str
    source: str            # static / discovered / metadata / main
    ip: str = "-"
    family: str = "-"
    dns_ms: float | None = None
    tcp_ms: float | None = None
    tls: str = "-"
    tls_ms: float | None = None
    http: str = "-"
    total_ms: float | None = None
    status: Status = Status.SKIP
    note: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Hop:
    family: str
    ttl: int
    ip: str | None
    rtt_ms: float | None
    name: str | None = None
    reached: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AssetRow:
    url: str
    expected: int | None
    received: int = 0
    http: str = "-"
    sha256: str = ""
    full: str = "-"
    tail: str = "-"
    speed_kbps: float | None = None
    status: Status = Status.SKIP
    note: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Report:
    target: str
    profile: str
    options: dict[str, Any]
    started: float = field(default_factory=time.time)
    finished: float | None = None
    checks: list[Check] = field(default_factory=list)
    hosts: list[HostRow] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    assets: list[AssetRow] = field(default_factory=list)
    diagnosis: list[Diagnosis] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)
    cancelled: bool = False

    def layer_status(self, layer: str) -> Status:
        return worst(c.status for c in self.checks if c.layer == layer)

    @property
    def overall(self) -> Status:
        s = worst(c.status for c in self.checks)
        return s if s in (Status.FAIL, Status.WARN) else (Status.OK if self.checks else Status.SKIP)

    def by_tag(self, tag: str) -> list[Check]:
        return [c for c in self.checks if tag in c.tags]

    def to_dict(self) -> dict:
        return {
            "tool": "WebNetCheck",
            "target": self.target,
            "profile": self.profile,
            "options": self.options,
            "started": self.started,
            "finished": self.finished,
            "cancelled": self.cancelled,
            "overall": self.overall.value,
            "layers": {k: self.layer_status(k).value for k, _ in LAYERS},
            "environment": self.environment,
            "diagnosis": [d.to_dict() for d in self.diagnosis],
            "checks": [c.to_dict() for c in self.checks],
            "hosts": [h.to_dict() for h in self.hosts],
            "hops": [h.to_dict() for h in self.hops],
            "assets": [a.to_dict() for a in self.assets],
        }
