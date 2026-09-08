"""Parse ATOM (and RSS) syndication feeds and collect CVE IDs."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from app.utils.cve import extract_cves

FEED_ACCEPT = "application/atom+xml, application/rss+xml, application/xml, text/xml, */*"
SEEN_CAP = 500


def local_name(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    parts = [el.text or ""]
    for child in list(el):
        parts.append(_text(child))
        parts.append(child.tail or "")
    return "".join(parts).strip()


def _first_child(el: ET.Element, *names: str) -> ET.Element | None:
    wanted = set(names)
    for child in list(el):
        if local_name(child.tag) in wanted:
            return child
    return None


def _child_text(el: ET.Element, *names: str) -> str:
    return _text(_first_child(el, *names))


def _link_href(el: ET.Element) -> str:
    preferred = ""
    for child in list(el):
        if local_name(child.tag) != "link":
            continue
        href = (child.attrib.get("href") or _text(child) or "").strip()
        if not href:
            continue
        rel = (child.attrib.get("rel") or "alternate").lower()
        if rel in {"alternate", ""}:
            return href
        if not preferred:
            preferred = href
    return preferred


def _parse_atom_entry(entry: ET.Element) -> dict[str, str]:
    entry_id = _child_text(entry, "id") or _link_href(entry)
    title = _child_text(entry, "title")
    summary = _child_text(entry, "summary", "content")
    content_el = _first_child(entry, "content")
    content = _text(content_el) if content_el is not None else ""
    updated = _child_text(entry, "updated", "published")
    link = _link_href(entry)
    return {
        "id": entry_id or title or link,
        "title": title,
        "summary": summary,
        "content": content,
        "updated": updated,
        "link": link,
    }


def _parse_rss_item(item: ET.Element) -> dict[str, str]:
    title = _child_text(item, "title")
    link = _child_text(item, "link") or _link_href(item)
    guid = _child_text(item, "guid")
    summary = _child_text(item, "description", "summary")
    content = ""
    for child in list(item):
        if local_name(child.tag) in {"encoded", "content"}:
            content = _text(child)
            break
    updated = _child_text(item, "pubDate", "updated", "published")
    return {
        "id": guid or link or title,
        "title": title,
        "summary": summary,
        "content": content,
        "updated": updated,
        "link": link,
    }


def parse_feed(xml_text: str) -> dict[str, Any]:
    """Return ``{format, title, entries}`` from ATOM 1.0 or RSS 2.0 XML."""
    blob = (xml_text or "").lstrip("\ufeff").strip()
    if not blob:
        raise ValueError("Feed is empty")
    try:
        root = ET.fromstring(blob)
    except ET.ParseError as exc:
        raise ValueError(f"Not valid XML: {exc}") from exc

    kind = local_name(root.tag).lower()
    if kind == "feed":
        entries = [_parse_atom_entry(child) for child in list(root) if local_name(child.tag) == "entry"]
        return {"format": "atom", "title": _child_text(root, "title"), "entries": entries}
    if kind == "rss":
        channel = _first_child(root, "channel") or root
        entries = [_parse_rss_item(child) for child in list(channel) if local_name(child.tag) == "item"]
        return {"format": "rss", "title": _child_text(channel, "title"), "entries": entries}
    raise ValueError("URL is not an ATOM or RSS feed")


def entry_text(entry: dict[str, str]) -> str:
    return "\n".join(
        part
        for part in (
            entry.get("title") or "",
            entry.get("summary") or "",
            entry.get("content") or "",
            entry.get("link") or "",
        )
        if part
    )


def entry_cves(entry: dict[str, str]) -> list[str]:
    return extract_cves(entry_text(entry))


def entry_stamp(entry: dict[str, str]) -> str:
    return f"{entry.get('id') or ''}:{entry.get('updated') or ''}"


def normalize_feeds(cfg: dict[str, Any] | None) -> list[dict[str, str]]:
    """Turn stored config into a list of ``{url, name, token}`` (legacy ``url`` included)."""
    cfg = dict(cfg or {})
    legacy_token = str(cfg.get("token") or "").strip()
    raw = cfg.get("feeds")
    items: list[Any]
    if isinstance(raw, list) and raw:
        items = raw
    elif cfg.get("url"):
        items = [{"url": cfg.get("url"), "name": "", "token": legacy_token}]
    else:
        items = []

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        if isinstance(item, str):
            item = {"url": item}
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        kind = str(item.get("feed_type") or "").strip().lower()
        if kind not in {"nvd", "epss", "atom"}:
            lower = url.lower()
            if "nvd.nist.gov" in lower:
                kind = "nvd"
            elif "api.first.org" in lower:
                kind = "epss"
            else:
                kind = "atom"
        out.append(
            {
                "url": url,
                "name": str(item.get("name") or "").strip(),
                "token": str(item.get("token") or "").strip() or legacy_token,
                "feed_type": kind,
            }
        )
    return out


def merge_preserved_tokens(
    new_feeds: list[dict[str, str]],
    old_cfg: dict[str, Any] | None,
) -> list[dict[str, str]]:
    old_by_url = {row["url"]: row for row in normalize_feeds(old_cfg)}
    merged: list[dict[str, str]] = []
    for row in new_feeds:
        copy = dict(row)
        if not copy.get("token"):
            copy["token"] = (old_by_url.get(copy["url"]) or {}).get("token") or ""
        merged.append(copy)
    return merged


def public_feeds(cfg: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [
        {
            "url": row["url"],
            "name": row.get("name") or "",
            "token_set": bool(row.get("token")),
            "feed_type": row.get("feed_type") or "",
        }
        for row in normalize_feeds(cfg)
    ]


def feed_headers(token: str = "") -> dict[str, str]:
    headers = {
        "User-Agent": "EVulnTasker/1.0",
        "Accept": FEED_ACCEPT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def trim_seen(stamps: list[str], cap: int = SEEN_CAP) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for stamp in stamps:
        if not stamp or stamp in seen:
            continue
        seen.add(stamp)
        out.append(stamp)
        if len(out) >= cap:
            break
    return out
