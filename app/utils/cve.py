"""CVE identifier extraction and CVSS helpers."""

from __future__ import annotations

import html
import re

# Official CVE ID pattern (year + 4–7 digit sequence). Case-insensitive.
# Also matches IDs inside HTML, URLs, and unicode hyphens.
CVE_REGEX = re.compile(r"CVE[-–—]\d{4}-\d{4,7}", re.IGNORECASE)
_SCRIPT = re.compile(r"(?is)<script[^>]*>.*?</script>")
_STYLE = re.compile(r"(?is)<style[^>]*>.*?</style>")
_TAG = re.compile(r"<[^>]+>")


def flatten_text(text: str) -> str:
    """Decode HTML entities and replace markup so regex can see CVE IDs."""
    blob = html.unescape(text)
    blob = _SCRIPT.sub(" ", blob)
    blob = _STYLE.sub(" ", blob)
    blob = _TAG.sub(" ", blob)
    return blob


def extract_cves(text: str | None) -> list[str]:
    """Return unique, upper-cased CVE IDs found in free-form text or HTML."""
    if not text:
        return []
    found = CVE_REGEX.findall(text) + CVE_REGEX.findall(flatten_text(text))
    seen: set[str] = set()
    result: list[str] = []
    for match in found:
        cve = match.upper().replace("–", "-").replace("—", "-")
        if cve not in seen:
            seen.add(cve)
            result.append(cve)
    return result


def severity_from_cvss(score: float | None) -> str:
    """Map a CVSS v3 base score to NVD qualitative severity."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def priority_from_scores(cvss: float | None, epss: float | None) -> str:
    """
    Combine CVSS (impact) and EPSS (exploitation probability) into a
    product-team priority. EPSS >= 0.5 with High/Critical CVSS is P1.
    """
    cvss = cvss or 0.0
    epss = epss or 0.0
    if cvss >= 9.0 or (cvss >= 7.0 and epss >= 0.5):
        return "P1"
    if cvss >= 7.0 or epss >= 0.2:
        return "P2"
    if cvss >= 4.0:
        return "P3"
    return "P4"
