"""Parse CVE intelligence from free-text, CSV, and JSON files.

CVE IDs are taken with regex. Vendor / product / version are taken from:
  * labeled fields (Vendor:, Product:, Version:)
  * CSV / JSON columns
  * CPE strings
  * a small window of lines around each CVE
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from io import StringIO

from app.utils.cve import extract_cves, flatten_text

CVE_FINDER = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

LABEL = re.compile(
    r"(?im)^\s*(vendor|product|package|software|component|version|ver|affected[_ ]?version)s?\s*[:=]\s*(.+?)\s*$"
)
CPE = re.compile(
    r"cpe:2\.3:[aho]:([^:]+):([^:]+):([^:]+)",
    re.IGNORECASE,
)
HEADER_MAP = {
    "cve": "cve_id",
    "cve_id": "cve_id",
    "cveid": "cve_id",
    "id": "cve_id",
    "vendor": "vendor",
    "vendor_name": "vendor",
    "product": "product",
    "package": "product",
    "software": "product",
    "component": "product",
    "version": "version",
    "ver": "version",
    "affected_version": "version",
    "affected_versions": "version",
    "summary": "summary",
    "title": "summary",
    "description": "summary",
}


@dataclass
class IntelRecord:
    cve_id: str
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    summary: str | None = None
    extras: dict = field(default_factory=dict)


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("\"'")
    if not text or text.lower() in {"n/a", "na", "none", "unknown", "-", "*"}:
        return None
    if text in {":", "*"}:
        return None
    return text[:256]


def _norm_header(name: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    return HEADER_MAP.get(key, key)


def parse_intel(text: str, filename: str = "") -> list[IntelRecord]:
    name = (filename or "").lower()
    stripped = (text or "").lstrip("\ufeff")
    if not stripped.strip():
        return []
    if name.endswith(".json") or stripped[:1] in "[{":
        records = _parse_json(stripped)
        if records:
            return records
    if name.endswith(".csv") or ("," in stripped.splitlines()[0] and "cve" in stripped[:400].lower()):
        records = _parse_csv(stripped)
        if records:
            return records
    if name.endswith((".html", ".htm", ".xhtml")) or stripped.lstrip()[:1] == "<":
        records = _parse_text(flatten_text(stripped) + "\n" + stripped)
        if records:
            return records
    return _parse_text(stripped)


def _parse_json(text: str) -> list[IntelRecord]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows: list = []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        for key in ("records", "items", "vulnerabilities", "cves", "data"):
            if isinstance(data.get(key), list):
                rows = data[key]
                break
        if not rows:
            rows = [data]
    out: list[IntelRecord] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        mapped = {_norm_header(str(k)): v for k, v in row.items()}
        cves = extract_cves(str(mapped.get("cve_id") or ""))
        if not cves:
            cves = extract_cves(json.dumps(row, default=str))
        for cve in cves:
            out.append(
                IntelRecord(
                    cve_id=cve,
                    vendor=_clean(mapped.get("vendor")),
                    product=_clean(mapped.get("product")),
                    version=_clean(mapped.get("version")),
                    summary=_clean(mapped.get("summary")),
                )
            )
    return _dedupe(out)


def _parse_csv(text: str) -> list[IntelRecord]:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        return []
    out: list[IntelRecord] = []
    for row in reader:
        mapped = {_norm_header(str(k)): v for k, v in row.items() if k}
        blob = " ".join(str(v) for v in row.values() if v)
        cves = extract_cves(str(mapped.get("cve_id") or "")) or extract_cves(blob)
        for cve in cves:
            out.append(
                IntelRecord(
                    cve_id=cve,
                    vendor=_clean(mapped.get("vendor")),
                    product=_clean(mapped.get("product")),
                    version=_clean(mapped.get("version")),
                    summary=_clean(mapped.get("summary")),
                )
            )
    return _dedupe(out)


def _labels_in(block: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in LABEL.finditer(block):
        kind = match.group(1).lower()
        value = _clean(match.group(2))
        if not value:
            continue
        if kind in {"vendor"}:
            found["vendor"] = value
        elif kind in {"product", "package", "software", "component"}:
            found["product"] = value
        else:
            found["version"] = value
    cpe = CPE.search(block)
    if cpe:
        found.setdefault("vendor", _clean(cpe.group(1).replace("_", " ")))
        found.setdefault("product", _clean(cpe.group(2).replace("_", " ")))
        ver = cpe.group(3)
        if ver not in {"*", "-", ""}:
            found.setdefault("version", _clean(ver))
    return found


def _parse_text(text: str) -> list[IntelRecord]:
    lines = text.splitlines()
    matches = list(CVE_FINDER.finditer(text))
    if not matches:
        return [
            IntelRecord(cve_id=cve)
            for cve in extract_cves(text)
        ]
    line_starts = []
    pos = 0
    for line in lines:
        line_starts.append(pos)
        pos += len(line) + 1

    def line_index(offset: int) -> int:
        idx = 0
        for i, start in enumerate(line_starts):
            if start <= offset:
                idx = i
        return idx

    global_labels = _labels_in(text)
    out: list[IntelRecord] = []
    for match in matches:
        cve = match.group(0).upper()
        idx = line_index(match.start())
        window = "\n".join(lines[max(0, idx - 4) : idx + 6])
        labels = {**global_labels, **_labels_in(window)}
        summary = _clean(lines[idx]) if idx < len(lines) else cve
        out.append(
            IntelRecord(
                cve_id=cve,
                vendor=labels.get("vendor"),
                product=labels.get("product"),
                version=labels.get("version"),
                summary=summary,
            )
        )
    return _dedupe(out)


def _dedupe(records: list[IntelRecord]) -> list[IntelRecord]:
    merged: dict[str, IntelRecord] = {}
    for rec in records:
        current = merged.get(rec.cve_id)
        if current is None:
            merged[rec.cve_id] = rec
            continue
        current.vendor = current.vendor or rec.vendor
        current.product = current.product or rec.product
        current.version = current.version or rec.version
        current.summary = current.summary or rec.summary
    return list(merged.values())
