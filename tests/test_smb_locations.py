from app.integrations.smb import location_config, normalize_locations


def test_normalize_migrates_legacy_single_share():
    locations = normalize_locations(
        {"server": "fileserver.corp.local", "share": "intel", "path": "cve-advisories"}
    )
    assert locations == [
        {
            "name": "",
            "server": "fileserver.corp.local",
            "share": "intel",
            "path": "cve-advisories",
        }
    ]


def test_normalize_dedupes_locations():
    locations = normalize_locations(
        {
            "locations": [
                {"server": "fs1", "share": "intel", "path": "a", "name": "One"},
                {"server": "FS1", "share": "intel", "path": "a", "name": "dup"},
                {"server": "fs1", "share": "intel", "path": "b", "name": "Two"},
                {"server": "", "share": "intel"},
            ]
        }
    )
    assert [row["path"] for row in locations] == ["a", "b"]
    assert locations[0]["name"] == "One"


def test_location_config_overrides_server_share_path():
    merged = location_config(
        {"server": "old", "share": "old", "path": "old", "username": "soc"},
        {"server": "fs2", "share": "advisories", "path": "inbox"},
    )
    assert merged["server"] == "fs2"
    assert merged["share"] == "advisories"
    assert merged["path"] == "inbox"
    assert merged["username"] == "soc"
