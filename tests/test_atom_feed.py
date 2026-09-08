from app.services.atom_feed import (
    entry_cves,
    normalize_feeds,
    parse_feed,
    public_feeds,
    trim_seen,
)

ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Vendor advisories</title>
  <entry>
    <id>urn:uuid:1</id>
    <title>xz backdoor CVE-2024-3094</title>
    <updated>2024-04-01T00:00:00Z</updated>
    <summary>Remote code execution in xz (CVE-2024-3094).</summary>
    <link href="https://vendor.example/cve-2024-3094"/>
  </entry>
  <entry>
    <id>urn:uuid:2</id>
    <title>Routine maintenance</title>
    <updated>2024-04-02T00:00:00Z</updated>
    <content>No vulnerability identifier in this post.</content>
  </entry>
</feed>
"""

RSS = """<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Security blog</title>
    <item>
      <guid>https://blog.example/log4j</guid>
      <title>Log4Shell</title>
      <link>https://blog.example/log4j</link>
      <description>Details for CVE-2021-44228</description>
    </item>
  </channel>
</rss>
"""


def test_parse_atom_extracts_cve_by_id():
    parsed = parse_feed(ATOM)
    assert parsed["format"] == "atom"
    assert len(parsed["entries"]) == 2
    cves = [entry_cves(entry) for entry in parsed["entries"]]
    assert cves[0] == ["CVE-2024-3094"]
    assert cves[1] == []


def test_parse_rss_extracts_cve():
    parsed = parse_feed(RSS)
    assert parsed["format"] == "rss"
    assert entry_cves(parsed["entries"][0]) == ["CVE-2021-44228"]


def test_normalize_feeds_migrates_legacy_url():
    feeds = normalize_feeds({"url": "https://vendor.example/atom.xml", "token": "secret"})
    assert feeds == [
        {"url": "https://vendor.example/atom.xml", "name": "", "token": "secret", "feed_type": "atom"}
    ]


def test_normalize_feeds_dedupes_and_skips_empty():
    feeds = normalize_feeds(
        {
            "feeds": [
                {"url": "https://a.example/atom.xml", "name": "A"},
                {"url": "https://a.example/atom.xml", "name": "dup"},
                {"url": "  "},
                {"url": "https://b.example/atom.xml", "name": "B"},
            ]
        }
    )
    assert [row["url"] for row in feeds] == [
        "https://a.example/atom.xml",
        "https://b.example/atom.xml",
    ]


def test_public_feeds_hides_tokens():
    rows = public_feeds(
        {"feeds": [{"url": "https://a.example/atom.xml", "name": "A", "token": "secret"}]}
    )
    assert rows == [{"url": "https://a.example/atom.xml", "name": "A", "token_set": True, "feed_type": "atom"}]
    assert "token" not in rows[0]


def test_trim_seen_caps_and_dedupes():
    assert trim_seen(["a", "b", "a", "c"], cap=2) == ["a", "b"]
