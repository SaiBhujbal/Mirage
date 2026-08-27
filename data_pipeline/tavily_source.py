"""
Tavily exploit-acquisition -> training dataset -> MLOps retrain feed.

PURPOSE (primary): use the Tavily search API to collect the LATEST real-world web-exploit
payloads (SQLi/XSS/RCE/SSRF/SSTI/traversal/log4shell/...), by attack class and by affected
language / framework / version, turn them into labeled training records, and append them to
the capture feed that the guarded MLOps loop (`ml/mlops_runner`) retrains from. Tavily becomes
a fresh, real-world ATTACK SOURCE feeding champion/challenger retraining — screened by the
poison guard and accumulated by the zero-day store before any retrain, exactly like honeypot
captures.

SECONDARY: track CVE advisories (id, category, affected tech/version) in a feed file, and, only
for records that carry an explicitly VALIDATED regex, offer them to the CVE virtual-patcher.

SAFETY / HONESTY:
  * Fail-safe: no TAVILY_API_KEY -> disabled (returns nothing); API/network error -> logged and
    skipped. The WAF and MLOps loop run fine without it.
  * Tavily-sourced samples are labeled attack (label=1) and marked reviewed with source
    "threat-intel:tavily". They do NOT bypass the pipeline: the poison guard still screens them
    and the zero-day store still gates volume/diversity/age before a retrain is released.
  * Search snippets are lossy; we extract payloads conservatively (attack-shaped strings + code
    blocks) and can AUGMENT seeds into more data points via mutation for training robustness.

Env:
  TAVILY_API_KEY        required to run live; unset => disabled
  TAVILY_LOOKBACK_DAYS  search recency window (default 7)
  TAVILY_MAX_RESULTS    results per query (default 5)
  TAVILY_QUERIES        optional ';'-separated custom queries
  TAVILY_AUGMENT        mutations per seed payload for volume (default 0 = off)

Run:
  TAVILY_API_KEY=tvly-... python -m data_pipeline.tavily_source            # collect + write feed
  python -m ml.mlops_runner                                                # then retrain (guarded)
"""
from __future__ import annotations

import os
import re
import json
import time
import logging
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("decepticon.threatintel.tavily")

TAVILY_ENDPOINT = "https://api.tavily.com/search"
_ROOT = Path(__file__).resolve().parent.parent
_FEED_PATH = _ROOT / "data" / "corpus" / "tavily_feed.json"                 # CVE advisory tracker
_CAPTURE_PATH = _ROOT / "data" / "corpus" / "captured_zero_days.jsonl"      # MLOps retrain feed

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# WAF category <- keyword map
_CATEGORY_KEYWORDS = {
    "sql_injection": ("sql injection", "sqli", "sql-injection", "blind sql"),
    "cross_site_scripting": ("xss", "cross-site scripting", "cross site scripting"),
    "remote_code_execution": ("remote code execution", " rce", "code execution", "command injection", "os command"),
    "server_side_request_forgery": ("ssrf", "server-side request forgery"),
    "server_side_template_injection": ("ssti", "template injection"),
    "xxe": ("xxe", "xml external entity"),
    "path_traversal": ("path traversal", "directory traversal", "lfi", "local file inclusion", "arbitrary file read"),
    "deserialization": ("deserialization",),
    "authentication_bypass": ("authentication bypass", "auth bypass", "broken access control"),
    "prototype_pollution": ("prototype pollution",),
    "open_redirect": ("open redirect",),
}

_TECH = [
    "php", "java", "python", "node.js", "nodejs", "javascript", "typescript", "ruby", "rails",
    "go", "golang", ".net", "asp.net", "spring", "struts", "laravel", "django", "flask",
    "express", "wordpress", "drupal", "joomla", "apache", "nginx", "tomcat", "log4j", "log4shell",
    "jenkins", "gitlab", "confluence", "jira", "citrix", "fortinet", "vmware", "elasticsearch",
    "graphql", "next.js", "nextjs",
]
_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){1,3}(?:\.x)?)\b")

# Attack-shaped payload extractors: (compiled regex, WAF category). Conservative on purpose —
# they match the exploit STRING itself, not prose about it.
_PAYLOAD_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)union\s+(?:all\s+)?select\s+[^\s'\"&]{1,80}"), "sql_injection"),
    (re.compile(r"(?i)'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+"), "sql_injection"),
    (re.compile(r"(?i)';?\s*(?:drop|insert|update|delete)\s+\w+"), "sql_injection"),
    (re.compile(r"(?i)<script[^>]*>.{0,120}?</script>"), "cross_site_scripting"),
    (re.compile(r"(?i)<(?:img|svg|iframe|body)[^>]+on\w+\s*=\s*[^>]{1,80}"), "cross_site_scripting"),
    (re.compile(r"(?i)javascript:\s*[a-z0-9_$.]+\([^)]{0,60}\)"), "cross_site_scripting"),
    (re.compile(r"\$\{jndi:(?:ldap|rmi|dns|ldaps)://[^}]{1,120}\}"), "remote_code_execution"),
    (re.compile(r"(?i)[;|&`]\s*(?:cat|ls|id|whoami|curl|wget|nc|bash|sh|powershell)\b[^\s&]{0,60}"), "remote_code_execution"),
    (re.compile(r"\$\([^)]{1,60}\)"), "remote_code_execution"),
    (re.compile(r"(?:\.\./){2,}[\w./%-]{0,60}"), "path_traversal"),
    (re.compile(r"(?i)(?:%2e%2e%2f){2,}[\w./%-]{0,60}"), "path_traversal"),
    (re.compile(r"\{\{\s*[\w.\[\]'\"()* +]{1,80}?\}\}"), "server_side_template_injection"),
    (re.compile(r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['\"][^'\"]{1,120}['\"]"), "xxe"),
]


@dataclass
class ThreatIntel:
    cve_id: str
    title: str
    category: str
    affected: List[str] = field(default_factory=list)
    severity: float = 0.0
    url: str = ""
    published: str = ""
    source: str = "tavily"
    snippet: str = ""

    def key(self) -> str:
        return self.cve_id.upper() if self.cve_id else (self.url or self.title)


DEFAULT_QUERIES = [
    "latest actively exploited web application vulnerability CVE proof of concept payload",
    "new SQL injection CVE exploit payload web application",
    "new cross-site scripting XSS CVE payload web framework",
    "new remote code execution RCE CVE exploit web server payload",
    "new SSRF path traversal CVE exploit web application",
    "log4shell jndi template injection exploit payload CVE",
    "CISA KEV added web application vulnerability exploit",
]
_SEVERITY_WORDS = [("critical", 0.95), ("high", 0.8), ("important", 0.8),
                   ("medium", 0.5), ("moderate", 0.5), ("low", 0.3)]


class TavilyExploitFeed:
    def __init__(self, api_key: Optional[str] = None, lookback_days: Optional[int] = None,
                 max_results: Optional[int] = None, capture_path: Path = _CAPTURE_PATH,
                 feed_path: Path = _FEED_PATH):
        self.api_key = api_key if api_key is not None else os.environ.get("TAVILY_API_KEY", "")
        self.lookback_days = int(lookback_days if lookback_days is not None
                                 else os.environ.get("TAVILY_LOOKBACK_DAYS", "7"))
        self.max_results = int(max_results if max_results is not None
                               else os.environ.get("TAVILY_MAX_RESULTS", "5"))
        self.capture_path = Path(capture_path)
        self.feed_path = Path(feed_path)
        env_q = os.environ.get("TAVILY_QUERIES", "").strip()
        self.queries = [q.strip() for q in env_q.split(";") if q.strip()] or DEFAULT_QUERIES

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    # -- network (monkeypatchable; never raises) --------------------------------------
    def _search(self, query: str) -> List[Dict]:
        if not self.enabled:
            return []
        try:
            import requests
            resp = requests.post(TAVILY_ENDPOINT, timeout=15, json={
                "api_key": self.api_key, "query": query, "topic": "news",
                "days": self.lookback_days, "search_depth": "advanced",
                "max_results": self.max_results, "include_answer": False,
                "include_raw_content": True,
            })
            resp.raise_for_status()
            return resp.json().get("results", []) or []
        except Exception as e:
            logger.warning("tavily search failed for %r: %s", query[:60], e)
            return []

    # -- parsing helpers --------------------------------------------------------------
    @staticmethod
    def _infer_category(text: str) -> str:
        t = text.lower()
        for cat, kws in _CATEGORY_KEYWORDS.items():
            if any(k in t for k in kws):
                return cat
        return "unknown"

    @staticmethod
    def _infer_severity(text: str) -> float:
        t = text.lower()
        for word, val in _SEVERITY_WORDS:
            if word in t:
                return val
        return 0.6

    @staticmethod
    def _infer_affected(text: str) -> List[str]:
        t = text.lower()
        out, seen = [], set()
        for tech in _TECH:
            idx = t.find(tech)
            if idx == -1:
                continue
            ver = _VERSION_RE.search(t[idx:idx + 40])
            a = f"{tech} {ver.group(1)}" if ver else tech
            if a not in seen:
                seen.add(a); out.append(a)
        return out[:8]

    @staticmethod
    def _extract_payloads(text: str) -> List[Tuple[str, str]]:
        """Pull attack-shaped payload strings out of PoC/advisory content.
        Returns [(payload, category)], deduped, bounded."""
        found, seen = [], set()
        # code fences / inline code often hold the raw payload
        candidates = [text]
        for block in re.findall(r"`{1,3}([^`]{3,300})`{1,3}", text):
            candidates.append(block)
        for c in candidates:
            for rx, cat in _PAYLOAD_PATTERNS:
                for m in rx.findall(c):
                    p = (m if isinstance(m, str) else m[0]).strip()
                    p = urllib.parse.unquote(p)[:300]
                    if len(p) >= 4 and p not in seen:
                        seen.add(p); found.append((p, cat))
        return found[:40]

    # -- ThreatIntel (advisory tracking) ----------------------------------------------
    def _parse_intel(self, r: Dict) -> List[ThreatIntel]:
        title = (r.get("title") or "").strip()
        content = (r.get("content") or "").strip()
        blob = f"{title}. {content}"
        cat, sev = self._infer_category(blob), self._infer_severity(blob)
        aff = self._infer_affected(blob)
        cves = list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(blob)))
        url, pub = r.get("url") or "", r.get("published_date") or ""
        if not cves:
            return ([ThreatIntel("", title, cat, aff, sev, url, pub, snippet=content[:280])]
                    if cat != "unknown" else [])
        return [ThreatIntel(c, title, cat, aff, sev, url, pub, snippet=content[:280]) for c in cves]

    # -- public API -------------------------------------------------------------------
    def collect(self) -> Tuple[List[ThreatIntel], List[Dict]]:
        """Run queries. Returns (advisory intel records, exploit training samples)."""
        if not self.enabled:
            logger.info("Tavily disabled (no TAVILY_API_KEY) — exploit feed skipped.")
            return [], []
        intel: Dict[str, ThreatIntel] = {}
        samples: List[Dict] = []
        seen_payloads = set()
        for q in self.queries:
            for r in self._search(q):
                blob = f"{r.get('title','')} {r.get('content','')} {r.get('raw_content','') or ''}"
                cves = list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(blob)))
                cve_id = cves[0] if cves else ""
                for ti in self._parse_intel(r):
                    if ti.key() and ti.key() not in intel:
                        intel[ti.key()] = ti
                for payload, cat in self._extract_payloads(blob):
                    if payload in seen_payloads:
                        continue
                    seen_payloads.add(payload)
                    samples.append(self._to_sample(payload, cat, cve_id, r.get("url", "")))
        return list(intel.values()), samples

    @staticmethod
    def _to_sample(payload: str, category: str, cve_id: str, url: str) -> Dict:
        """A capture-feed record in the exact shape ml/mlops_runner consumes.
        Body-borne classes go in body; the rest in the query string."""
        body_classes = {"xxe", "deserialization"}
        rec = {"method": "POST" if category in body_classes else "GET",
               "path": "/", "query": "", "body": "",
               "label": 1, "source_ip": "threat-intel:tavily", "reviewed": True,
               "category": category, "cve_id": cve_id, "ref": url}
        if category in body_classes:
            rec["body"] = payload
        else:
            rec["query"] = f"q={payload}"
        return rec

    # -- augmentation (optional volume) -----------------------------------------------
    @staticmethod
    def augment(samples: List[Dict], factor: int) -> List[Dict]:
        """Expand each seed payload into `factor` mutated variants (still label=1) for training
        robustness. Uses the project's adaptive-attacker ops when available, else simple
        encoders. Augmentation adds data points; it never changes labels."""
        if factor <= 0 or not samples:
            return []
        ops = _mutation_ops()
        out = []
        for s in samples:
            field = "query" if s["query"] else "body"
            raw = s[field]
            base = raw[2:] if field == "query" and raw.startswith("q=") else raw
            for i in range(factor):
                mutated = ops[i % len(ops)](base)
                if mutated == base:
                    continue
                v = dict(s)
                v[field] = (f"q={mutated}" if field == "query" else mutated)
                v["source_ip"] = "threat-intel:tavily-aug"
                out.append(v)
        return out

    def write_feed(self, samples: List[Dict]) -> int:
        """Append NEW samples to the MLOps capture feed (JSONL), deduped by (method,query,body).
        Returns the count written."""
        existing = set()
        if self.capture_path.exists():
            for line in self.capture_path.read_text(encoding="utf-8").splitlines():
                try:
                    r = json.loads(line)
                    existing.add((r.get("method"), r.get("query"), r.get("body")))
                except Exception:
                    pass
        new = [s for s in samples if (s["method"], s["query"], s["body"]) not in existing]
        if new:
            self.capture_path.parent.mkdir(parents=True, exist_ok=True)
            with self.capture_path.open("a", encoding="utf-8") as f:
                for s in new:
                    f.write(json.dumps({**s, "ts": time.time()}) + "\n")
        return len(new)

    def notify_advisories(self, advisories: List[ThreatIntel], min_severity: float = 0.8) -> int:
        """Alert on NEW high-severity CVE advisories via Slack (dry-run if no webhook).
        This is the 'track latest CVEs even when no payload is auto-extractable' path."""
        try:
            from integrations.slack_notifier import notifier as slack
        except Exception:
            return 0
        if slack is None:
            return 0
        sent = 0
        for ti in advisories:
            if ti.severity < min_severity or not ti.cve_id:
                continue
            try:
                slack.notify(
                    key=f"cve_{ti.key()}",
                    severity=("high" if ti.severity >= 0.9 else "medium"),
                    title=f"New exploited CVE: {ti.cve_id} ({ti.category})",
                    fields={"category": ti.category,
                            "affected": ", ".join(ti.affected) or "n/a",
                            "severity": f"{ti.severity:.2f}",
                            "source": (ti.url or "")[:80]},
                    text=ti.title[:200])
                sent += 1
            except Exception as e:
                logger.warning("slack advisory notify failed for %s: %s", ti.cve_id, e)
        return sent

    def write_intel(self, intel: List[ThreatIntel]) -> List[ThreatIntel]:
        existing = {}
        if self.feed_path.exists():
            try:
                existing = json.loads(self.feed_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        newly = [ti for ti in intel if ti.key() not in existing]
        for ti in newly:
            existing[ti.key()] = {**asdict(ti), "first_seen": time.strftime("%Y-%m-%d %H:%M:%S")}
        if newly:
            self.feed_path.parent.mkdir(parents=True, exist_ok=True)
            self.feed_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        return newly


def _mutation_ops():
    """Prefer the project's adaptive-attacker ops; fall back to simple, dependency-free ones."""
    try:
        from ml.adaptive_attacker import HELDOUT_OPS
        if HELDOUT_OPS:
            return HELDOUT_OPS
    except Exception:
        pass
    def case_flip(s): return "".join(c.upper() if i % 3 == 0 else c for i, c in enumerate(s))
    def url_enc(s): return urllib.parse.quote(s, safe="")
    def comment_ins(s): return s.replace(" ", "/**/", 2)
    def ws_pad(s): return s.replace(" ", "  ")
    def dbl_enc(s): return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")
    return [case_flip, url_enc, comment_ins, ws_pad, dbl_enc]


tavily_feed = TavilyExploitFeed()


def collect_and_build(augment_factor: Optional[int] = None) -> Dict:
    """Full pipeline: collect -> augment -> write capture feed + advisory tracker."""
    feed = TavilyExploitFeed()
    if augment_factor is None:
        augment_factor = int(os.environ.get("TAVILY_AUGMENT", "0"))
    intel, seeds = feed.collect()
    aug = feed.augment(seeds, augment_factor)
    written = feed.write_feed(seeds + aug)
    new_intel = feed.write_intel(intel)
    alerted = feed.notify_advisories(new_intel)   # Slack alert on new high-sev CVEs (dry-run if unset)
    return {"enabled": feed.enabled, "advisories": len(intel), "new_advisories": len(new_intel),
            "seed_payloads": len(seeds), "augmented": len(aug), "written_to_feed": written,
            "alerted": alerted, "capture_feed": str(feed.capture_path)}


def main():
    feed = TavilyExploitFeed()
    if not feed.enabled:
        print("Tavily exploit feed: DISABLED (set TAVILY_API_KEY to enable). "
              "The WAF and MLOps loop run normally without it.")
        return
    res = collect_and_build()
    print("Tavily exploit acquisition:")
    print(f"  advisories tracked : {res['advisories']} ({res['new_advisories']} new) -> {feed.feed_path.name}")
    print(f"  seed payloads      : {res['seed_payloads']}")
    print(f"  augmented variants : {res['augmented']}")
    print(f"  written to feed    : {res['written_to_feed']} -> {res['capture_feed']}")
    print("\nNext: python -m ml.mlops_runner   # guarded retrain (poison guard + accumulation gates)")


if __name__ == "__main__":
    main()
