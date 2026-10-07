"""Поиск зависимостей страницы: ресурсы из тегов, а не навигационные ссылки."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# rel у <link>, которые НЕ являются зависимостями страницы
_LINK_REL_IGNORE = {"canonical", "alternate", "next", "prev", "author", "license", "search", "me",
                    "help", "bookmark", "external", "nofollow", "noopener", "noreferrer", "tag"}
# rel, которые дают только хост (соединение заранее), а не объект для загрузки
_LINK_REL_HOST_ONLY = {"preconnect", "dns-prefetch"}

_TAG_ATTRS = {
    "script": ("src",),
    "img": ("src", "srcset", "data-src"),
    "source": ("src", "srcset"),
    "iframe": ("src",),
    "video": ("src", "poster"),
    "audio": ("src",),
    "embed": ("src",),
    "track": ("src",),
}


class _Collector(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.resources: list[tuple[str, str]] = []  # (url, tag)
        self.host_only: list[str] = []

    def _add(self, ref: str, tag: str, host_only: bool = False):
        ref = (ref or "").strip()
        if not ref or ref.startswith(("data:", "javascript:", "mailto:", "#", "blob:", "about:")):
            return
        url = urljoin(self.base, ref)
        if urlsplit(url).scheme not in ("http", "https"):
            return
        if host_only:
            self.host_only.append(url)
        else:
            self.resources.append((url, tag))

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = urljoin(self.base, a["href"])
            return
        if tag == "link":
            rels = set(a.get("rel", "").lower().split())
            if not a.get("href") or rels & _LINK_REL_IGNORE:
                return
            self._add(a["href"], "link:" + (",".join(sorted(rels)) or "?"), host_only=bool(rels & _LINK_REL_HOST_ONLY))
            return
        for attr in _TAG_ATTRS.get(tag, ()):
            val = a.get(attr)
            if not val:
                continue
            if attr == "srcset":
                for part in val.split(","):
                    self._add(part.strip().split(" ")[0], tag)
            else:
                self._add(val, tag)

    handle_startendtag = handle_starttag


def discover(html: str, base_url: str) -> tuple[list[tuple[str, str]], list[str]]:
    """→ (уникальные ресурсы [(url, tag)], хосты из preconnect/dns-prefetch)."""
    c = _Collector(base_url)
    try:
        c.feed(html)
        c.close()
    except Exception:  # noqa: BLE001 — кривой HTML не должен ронять проверку
        pass
    seen = set()
    res = []
    for url, tag in c.resources:
        if url not in seen:
            seen.add(url)
            res.append((url, tag))
    hosts = sorted({urlsplit(u).hostname or "" for u in c.host_only} - {""})
    return res, hosts


def hosts_of(urls) -> list[str]:
    return sorted({(urlsplit(u).hostname or "").lower() for u in urls} - {""})


def json_strings(obj, path: str) -> list[str]:
    """Все строки внутри obj[path...] (рекурсивно) — аналог jq '.domains | .. | strings'."""
    for key in [k for k in path.split(".") if k]:
        if isinstance(obj, dict):
            obj = obj.get(key, {})
        else:
            return []
    out: list[str] = []

    def walk(o):
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    return out
