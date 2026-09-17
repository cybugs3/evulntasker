from app.integrations.nvd import NVDClient


def _client() -> NVDClient:
    return NVDClient.__new__(NVDClient)


def test_normalize_reads_affected_when_configurations_missing():
    cve = {
        "id": "CVE-2024-4844",
        "descriptions": [
            {
                "lang": "en",
                "value": "Hardcoded credentials in Trellix ePolicy Orchestrator (ePO).",
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "NETWORK",
                        "attackComplexity": "HIGH",
                        "privilegesRequired": "LOW",
                        "userInteraction": "NONE",
                    }
                }
            ]
        },
        "affected": [
            {
                "source": "trellixpsirt@trellix.com",
                "affectedData": [
                    {
                        "vendor": "Trellix",
                        "product": "ePolicy Orchestrator",
                        "versions": [
                            {
                                "version": "All versions below ePO 5.10 Service Pack 1 Update 2",
                                "status": "affected",
                            }
                        ],
                    }
                ],
            }
        ],
    }
    parsed = _client()._normalize("CVE-2024-4844", cve)
    assert parsed["vendor"] == "Trellix"
    assert parsed["product"] == "ePolicy Orchestrator"
    assert parsed["cvss_score"] == 7.5
    assert parsed["attack_vector"] == "NETWORK"


def test_normalize_falls_back_to_cpe_in_affected_cpes():
    cve = {
        "descriptions": [{"lang": "en", "value": "Example"}],
        "metrics": {},
        "affected": [
            {
                "affectedData": [
                    {
                        "cpes": [
                            "cpe:2.3:a:trellix:epolicy_orchestrator:5.10:*:*:*:*:*:*:*"
                        ]
                    }
                ]
            }
        ],
    }
    parsed = _client()._normalize("CVE-2024-4844", cve)
    assert parsed["vendor"] == "trellix"
    assert parsed["product"] == "epolicy orchestrator"
    assert parsed["affected_versions"] == "5.10"


def test_normalize_derives_identity_when_affected_is_placeholder():
    cve = {
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "Opswat Metadefender Core before 5.2.1 does not properly defend "
                    "against potential HTML injection and XSS attacks."
                ),
            }
        ],
        "metrics": {},
        "affected": [{"vendor": "n/a", "product": "n/a", "versions": [{"version": "n/a"}]}],
    }
    parsed = _client()._normalize("CVE-2023-25364", cve)
    assert parsed["vendor"].lower() == "opswat"
    assert "metadefender" in parsed["product"].lower()
    assert parsed["affected_versions"] in (None, "")
