from types import SimpleNamespace

from app.integrations.sonatype import SonatypeClient, _component_row, _from_purl, _pick_latest_reports


def test_maven_component_maps_group_artifact_version():
    row = _component_row(
        {
            "hash": "1249e25aebb15358bedd",
            "displayName": "tomcat : tomcat-util : 5.5.23",
            "componentIdentifier": {
                "format": "maven",
                "coordinates": {
                    "groupId": "tomcat",
                    "artifactId": "tomcat-util",
                    "version": "5.5.23",
                },
            },
            "packageUrl": "pkg:maven/tomcat/tomcat-util@5.5.23?type=jar",
        }
    )
    assert row["vendor"] == "tomcat"
    assert row["product"] == "tomcat-util"
    assert row["version"] == "5.5.23"
    assert row["product_type"] == "library"


def test_purl_fills_missing_coordinates():
    vendor, product, version = _from_purl("pkg:npm/%40angular/core@17.0.0")
    assert vendor == "@angular"
    assert product == "core"
    assert version == "17.0.0"


def test_latest_report_prefers_newer_evaluation():
    reports = [
        {
            "applicationId": "app-1",
            "stage": "build",
            "evaluationDate": "2024-01-01T00:00:00Z",
            "reportDataUrl": "api/v2/applications/MyApp/reports/old",
        },
        {
            "applicationId": "app-1",
            "stage": "release",
            "evaluationDate": "2024-06-01T00:00:00Z",
            "reportDataUrl": "api/v2/applications/MyApp/reports/new",
        },
    ]
    latest = _pick_latest_reports(reports)
    assert latest["app-1"]["reportDataUrl"].endswith("/new")


def test_harvest_catalog_pulls_apps_and_libraries():
    payloads = {
        "/api/v2/applications": {
            "applications": [
                {
                    "id": "internal-1",
                    "publicId": "MyApp",
                    "name": "Payments",
                    "contactUserName": "owner.user",
                }
            ]
        },
        "/api/v2/reports/applications": [
            {
                "applicationId": "internal-1",
                "stage": "build",
                "evaluationDate": "2024-06-01T12:00:00Z",
                "reportDataUrl": "api/v2/applications/MyApp/reports/scan-99",
            }
        ],
        "/api/v2/applications/MyApp/reports/scan-99/raw": {
            "components": [
                {
                    "hash": "abc123",
                    "componentIdentifier": {
                        "format": "maven",
                        "coordinates": {
                            "groupId": "org.apache.logging.log4j",
                            "artifactId": "log4j-core",
                            "version": "2.17.1",
                        },
                    },
                }
            ]
        },
    }

    def get_json(path: str):
        return payloads[path]

    conn = SimpleNamespace(configured=True, base_url="https://iq.example")
    rows = SonatypeClient(conn).harvest_catalog(get_json=get_json)
    products = {row["product"] for row in rows}
    assert "Payments" in products
    assert "log4j-core" in products
    lib = next(row for row in rows if row["product"] == "log4j-core")
    assert lib["vendor"] == "org.apache.logging.log4j"
    assert lib["version"] == "2.17.1"
    assert lib["product_type"] == "library"
