"""Профили сервисов (TOML). Порядок поиска: папка рядом с exe/скриптом → встроенные."""
from __future__ import annotations

import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ApiProbe:
    name: str
    method: str
    url: str
    expect: str = "non5xx"            # 2xx | non5xx | any | <код>
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    require_env: list[str] = field(default_factory=list)  # проба только если переменные заданы
    skip_if_env: list[str] = field(default_factory=list)  # и наоборот


@dataclass
class Profile:
    key: str
    name: str
    description: str = ""
    base_url: str = ""
    static_hosts: list[str] = field(default_factory=list)
    probe_urls: list[str] = field(default_factory=list)
    discover_html: bool = True
    check_assets: bool = True
    asset_url_regex: str = r"^https?://"
    asset_count: int = 3
    min_asset_size: int = 32 * 1024
    range_size: int = 4096
    metadata_url: str = ""
    metadata_path: str = ""
    tcp_ports: list[int] = field(default_factory=list)
    api_probes: list[ApiProbe] = field(default_factory=list)
    path: str = ""


def profile_dirs() -> list[Path]:
    dirs = []
    if os.environ.get("WEBNETCHECK_PROFILES"):
        dirs.append(Path(os.environ["WEBNETCHECK_PROFILES"]))
    if getattr(sys, "frozen", False):
        dirs.append(Path(sys.executable).parent / "profiles")
        if hasattr(sys, "_MEIPASS"):
            dirs.append(Path(sys._MEIPASS) / "profiles")
    dirs.append(Path(__file__).resolve().parent.parent / "profiles")
    return dirs


_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(s: str) -> str:
    """${VAR} и ${VAR:-default} — как в shell."""
    return _ENV.sub(lambda m: os.environ.get(m.group(1)) or (m.group(2) or ""), s)


def _load(path: Path) -> Profile:
    with open(path, "rb") as f:
        d = tomllib.load(f)
    probes = [ApiProbe(name=p.get("name", p["url"]), method=p.get("method", "GET").upper(), url=p["url"],
                       expect=str(p.get("expect", "non5xx")), headers=p.get("headers", {}),
                       body=p.get("body"), require_env=p.get("require_env", []),
                       skip_if_env=p.get("skip_if_env", []))
              for p in d.get("api_probe", [])]
    meta = d.get("metadata", {})
    return Profile(
        key=path.stem, name=d.get("name", path.stem), description=d.get("description", ""),
        base_url=d.get("base_url", ""), static_hosts=d.get("static_hosts", []),
        probe_urls=d.get("probe_urls", []), discover_html=d.get("discover_html", True),
        check_assets=d.get("check_assets", True), asset_url_regex=d.get("asset_url_regex", r"^https?://"),
        asset_count=int(d.get("asset_count", 3)), min_asset_size=int(d.get("min_asset_size", 32 * 1024)),
        range_size=int(d.get("range_size", 4096)), metadata_url=meta.get("url", ""),
        metadata_path=meta.get("path", ""), tcp_ports=[int(p) for p in d.get("tcp_ports", [])],
        api_probes=probes, path=str(path),
    )


def load_all() -> dict[str, Profile]:
    found: dict[str, Profile] = {}
    for d in profile_dirs():
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.toml")):
            if p.stem in found or p.stem.startswith("_"):
                continue  # первый найденный побеждает: пользовательская папка перекрывает встроенную
            try:
                found[p.stem] = _load(p)
            except Exception as e:  # noqa: BLE001
                found[p.stem] = Profile(key=p.stem, name=f"{p.stem} (ошибка: {e})", path=str(p))
    return found
