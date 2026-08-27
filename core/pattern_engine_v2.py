"""
MIRAGE Ultra-Fast Pattern Matching Engine v2.0
===================================================
Naval SWAVLAMBAN 2025 Challenge 3

COMPLETE coverage of ALL modern attack vectors:
- OWASP Top 10 2021
- Modern API attacks (GraphQL, JWT, NoSQL)
- Cloud-specific attacks (SSRF to metadata)
- Advanced evasion detection

Target: < 0.5ms for all pattern checks combined

Security Hardened:
- No eval(), no exec(), no pickle
- Pre-compiled regex only
- Safe string operations
"""

import re
import hashlib
import mmh3
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from collections import defaultdict
import struct

# Import comprehensive patterns
from core.comprehensive_patterns import (
    AttackCategory, AttackPattern,
    SQLI_PATTERNS, NOSQL_PATTERNS, XSS_PATTERNS, RCE_PATTERNS,
    PATH_TRAVERSAL_PATTERNS, LFI_PATTERNS, RFI_PATTERNS,
    SSRF_PATTERNS, XXE_PATTERNS, SSTI_PATTERNS,
    JWT_PATTERNS, GRAPHQL_PATTERNS, PROTOTYPE_PATTERNS,
    DESERIALIZATION_PATTERNS, LDAP_PATTERNS, CRLF_PATTERNS,
    REDIRECT_PATTERNS, HOST_HEADER_PATTERNS, SCANNER_PATTERNS,
    DOS_PATTERNS, compile_patterns, get_all_patterns
)


class BloomFilter:
    """
    Ultra-fast bloom filter for known malicious signatures
    O(1) lookup with configurable false positive rate
    """
    
    def __init__(self, expected_items: int = 100000, fp_rate: float = 0.001):
        import math
        self.size = int(-(expected_items * math.log(fp_rate)) / (math.log(2) ** 2))
        self.hash_count = max(1, int((self.size / expected_items) * math.log(2)))
        self.bit_array = bytearray((self.size + 7) // 8)
        self.count = 0
    
    def _get_hash_values(self, item: str) -> List[int]:
        """Generate k hash values using double hashing"""
        h1 = mmh3.hash(item, seed=0) & 0xFFFFFFFF
        h2 = mmh3.hash(item, seed=h1) & 0xFFFFFFFF
        return [(h1 + i * h2) % self.size for i in range(self.hash_count)]
    
    def add(self, item: str):
        """Add item to bloom filter"""
        for pos in self._get_hash_values(item):
            byte_pos = pos // 8
            bit_pos = pos % 8
            self.bit_array[byte_pos] |= (1 << bit_pos)
        self.count += 1
    
    def contains(self, item: str) -> bool:
        """Check if item might be in the filter - O(1)"""
        for pos in self._get_hash_values(item):
            byte_pos = pos // 8
            bit_pos = pos % 8
            if not (self.bit_array[byte_pos] & (1 << bit_pos)):
                return False
        return True
    
    def add_bulk(self, items: List[str]):
        """Add multiple items efficiently"""
        for item in items:
            self.add(item)


@dataclass
class PatternRule:
    """Single pattern rule with compiled regex"""
    rule_id: str
    category: str
    pattern: re.Pattern
    severity: float
    description: str
    locations: List[str]
    owasp: Optional[str] = None


class ComprehensivePatternEngine:
    """
    High-performance pattern matching engine with FULL attack coverage.
    
    Covers ALL attack types:
    - SQL Injection (Boolean, Union, Time, Error, Stacked)
    - NoSQL Injection (MongoDB, CouchDB)
    - XSS (Reflected, Stored, DOM, Event handlers)
    - RCE (Command injection, Shell, Reverse shells)
    - Path Traversal / LFI / RFI
    - SSRF (Localhost, Cloud metadata, Protocols)
    - XXE (External entities, Parameter entities)
    - SSTI (Jinja2, Twig, Freemarker, Velocity)
    - JWT Attacks (alg:none, kid injection, jku/x5u)
    - GraphQL (Introspection, Batching, DoS)
    - Prototype Pollution
    - Deserialization (Java, PHP, Python, .NET)
    - LDAP Injection
    - CRLF / HTTP Response Splitting
    - Open Redirect
    - Host Header Injection
    - Scanner Detection
    - DoS / ReDoS
    
    Target: < 0.5ms for full scan
    """
    
    def __init__(self):
        # Bloom filter for known malicious payloads
        self.signature_bloom = BloomFilter(expected_items=100000, fp_rate=0.001)
        
        # Compiled regex patterns by category
        self.patterns: Dict[str, List[PatternRule]] = defaultdict(list)
        
        # Quick keyword sets for fast pre-filtering
        self.attack_keywords: Dict[str, Set[str]] = {
            'sqli': set(),
            'nosql': set(),
            'xss': set(),
            'rce': set(),
            'traversal': set(),
            'ssrf': set(),
            'xxe': set(),
            'ssti': set(),
            'jwt': set(),
            'graphql': set(),
            'proto': set(),
            'deser': set(),
            'ldap': set(),
        }
        
        # Initialize everything
        self._init_comprehensive_patterns()
        self._init_keywords()
        self._init_known_signatures()
    
    def _init_comprehensive_patterns(self):
        """Initialize ALL compiled regex patterns from comprehensive_patterns"""
        
        # Map AttackCategory to string category names
        category_map = {
            AttackCategory.SQLI: "SQLI",
            AttackCategory.NOSQL: "NOSQL",
            AttackCategory.XSS: "XSS",
            AttackCategory.RCE: "RCE",
            AttackCategory.PATH_TRAVERSAL: "PATH_TRAVERSAL",
            AttackCategory.LFI: "LFI",
            AttackCategory.RFI: "RFI",
            AttackCategory.SSRF: "SSRF",
            AttackCategory.XXE: "XXE",
            AttackCategory.SSTI: "SSTI",
            AttackCategory.JWT: "JWT",
            AttackCategory.GRAPHQL: "GRAPHQL",
            AttackCategory.PROTOTYPE_POLLUTION: "PROTO_POLLUTION",
            AttackCategory.DESERIALIZATION: "DESERIALIZATION",
            AttackCategory.LDAP: "LDAP",
            AttackCategory.CRLF: "CRLF",
            AttackCategory.OPEN_REDIRECT: "OPEN_REDIRECT",
            AttackCategory.HOST_HEADER: "HOST_HEADER",
            AttackCategory.SCANNER: "SCANNER",
            AttackCategory.DOS: "DOS",
        }
        
        # Location mappings for each category
        location_map = {
            "SQLI": ["query", "body", "path", "cookie"],
            "NOSQL": ["query", "body"],
            "XSS": ["query", "body", "path", "headers"],
            "RCE": ["query", "body"],
            "PATH_TRAVERSAL": ["path", "query"],
            "LFI": ["path", "query"],
            "RFI": ["query", "body"],
            "SSRF": ["query", "body"],
            "XXE": ["body"],
            "SSTI": ["query", "body"],
            "JWT": ["headers", "body", "cookie"],
            "GRAPHQL": ["body", "query"],
            "PROTO_POLLUTION": ["body", "query"],
            "DESERIALIZATION": ["body", "cookie"],
            "LDAP": ["query", "body"],
            "CRLF": ["query", "headers", "path"],
            "OPEN_REDIRECT": ["query"],
            "HOST_HEADER": ["headers"],
            "SCANNER": ["headers"],
            "DOS": ["body", "query"],
        }
        
        # Load all patterns
        all_patterns = get_all_patterns()
        
        for attack_cat, patterns in all_patterns.items():
            cat_name = category_map.get(attack_cat, attack_cat.name)
            locations = location_map.get(cat_name, ["query", "body"])
            
            for pattern in patterns:
                try:
                    compiled = re.compile(pattern.pattern, re.IGNORECASE | re.MULTILINE)
                    rule = PatternRule(
                        rule_id=pattern.id,
                        category=cat_name,
                        pattern=compiled,
                        severity=pattern.severity,
                        description=pattern.description,
                        locations=locations,
                        owasp=pattern.owasp
                    )
                    self.patterns[cat_name].append(rule)
                except re.error as e:
                    pass  # Skip invalid regex
        
        # Add additional custom patterns for edge cases
        self._add_custom_patterns()
    
    def _add_custom_patterns(self):
        """Add additional custom patterns for edge cases"""
        
        # Additional SQLi patterns for completeness
        additional_sqli = [
            (r"(?i);\s*shutdown\s*;?", 0.99, "SQL Server shutdown"),
            (r"(?i)master\.\.sysdatabases", 0.95, "MSSQL system database"),
            (r"(?i)sys\.database_name", 0.90, "SQL Server sys tables"),
        ]
        
        for pattern, severity, desc in additional_sqli:
            try:
                self.patterns["SQLI"].append(PatternRule(
                    rule_id=f"SQLI-CUSTOM-{len(self.patterns['SQLI'])+1}",
                    category="SQLI",
                    pattern=re.compile(pattern),
                    severity=severity,
                    description=desc,
                    locations=["query", "body", "path"],
                    owasp="A03:2021"
                ))
            except:
                pass
        
        # Additional auth bypass patterns
        auth_bypass = [
            (r"(?i)admin['\"\s]*--", 0.95, "Admin comment bypass"),
            (r"(?i)['\"][;\s]*drop\s", 0.98, "Drop statement injection"),
            (r"(?i)(?:password|passwd|pwd)\s*=\s*password", 0.85, "Password comparison bypass"),
        ]
        
        for pattern, severity, desc in auth_bypass:
            try:
                self.patterns["AUTH_BYPASS"].append(PatternRule(
                    rule_id=f"AUTH-{len(self.patterns['AUTH_BYPASS'])+1}",
                    category="AUTH_BYPASS",
                    pattern=re.compile(pattern),
                    severity=severity,
                    description=desc,
                    locations=["query", "body"],
                    owasp="A07:2021"
                ))
            except:
                pass
    
    def _init_keywords(self):
        """Initialize quick-lookup keyword sets"""
        
        # SQL keywords
        self.attack_keywords['sqli'] = {
            'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
            'alter', 'exec', 'execute', 'xp_', 'sp_', 'declare', 'cast',
            'convert', 'table', 'from', 'where', 'having', 'group', 'order',
            'null', 'like', 'between', 'exists', 'sleep', 'benchmark',
            'waitfor', 'delay', 'shutdown', 'truncate', 'information_schema',
            'sysobjects', 'syscolumns', 'pg_', 'mysql', 'sqlite',
        }
        
        # NoSQL keywords
        self.attack_keywords['nosql'] = {
            '$gt', '$lt', '$ne', '$eq', '$in', '$nin', '$or', '$and',
            '$not', '$nor', '$exists', '$type', '$regex', '$where',
            '$elemMatch', '$size', '$all', 'mapreduce', 'db.', 'collection',
            'find(', 'findone', 'aggregate', 'eval', '$function',
        }
        
        # XSS keywords
        self.attack_keywords['xss'] = {
            'script', 'javascript', 'onerror', 'onload', 'onclick', 'onmouseover',
            'onfocus', 'onblur', 'alert', 'confirm', 'prompt', 'eval',
            'document', 'window', 'cookie', 'innerhtml', 'outerhtml',
            'iframe', 'svg', 'img', 'body', 'input', 'form', 'style',
            'expression', 'vbscript', 'livescript', 'data:', 'base64',
            'fromcharcode', 'settimeout', 'setinterval',
        }
        
        # RCE keywords
        self.attack_keywords['rce'] = {
            'cat', 'ls', 'dir', 'type', 'more', 'head', 'tail', 'less',
            'wget', 'curl', 'nc', 'netcat', 'ncat', 'bash', 'sh', 'zsh',
            'cmd', 'powershell', 'python', 'perl', 'ruby', 'php',
            'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
            'eval', 'assert', '/etc/passwd', '/bin/sh', 'whoami', 'id',
            'uname', 'ifconfig', 'ipconfig', '/dev/tcp', 'mkfifo',
        }
        
        # Path traversal keywords
        self.attack_keywords['traversal'] = {
            '..', '%2e', '%252e', 'etc/passwd', 'etc/shadow', 'windows',
            'win.ini', 'boot.ini', 'system.ini', 'php://', 'file://',
            'data://', 'expect://', 'phar://', 'zip://', 'proc/self',
        }
        
        # SSRF keywords
        self.attack_keywords['ssrf'] = {
            'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254',
            'metadata', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
            'file://', 'gopher://', 'dict://', 'ldap://', 'tftp://',
            '::1', '[::1]', '0x7f', '2130706433', 'localtest.me',
            'xip.io', 'nip.io', 'sslip.io',
        }
        
        # XXE keywords
        self.attack_keywords['xxe'] = {
            '<!doctype', '<!entity', 'system', 'public', '<!element',
            '<!attlist', '&xxe', 'file://', 'http://', 'expect://',
            'php://', 'data://', 'xinclude', 'xmlns:xi',
        }
        
        # SSTI keywords
        self.attack_keywords['ssti'] = {
            '{{', '}}', '{%', '%}', '${', '<%', '%>', '#{',
            '__class__', '__mro__', '__subclasses__', '__globals__',
            '__builtins__', '__import__', 'config', 'request',
            'lipsum', 'cycler', 'joiner', 'namespace',
        }
        
        # JWT keywords
        self.attack_keywords['jwt'] = {
            'eyj', 'jwt', 'alg', 'none', 'hs256', 'rs256', 'kid', 'jku', 'x5u',
        }
        
        # GraphQL keywords
        self.attack_keywords['graphql'] = {
            '__schema', '__type', '__typename', 'query', 'mutation',
            'subscription', 'introspection', 'graphql',
        }
        
        # Prototype pollution keywords
        self.attack_keywords['proto'] = {
            '__proto__', 'constructor', 'prototype', 'polluted',
        }
        
        # Deserialization keywords
        self.attack_keywords['deser'] = {
            'ro0ab', 'aced0005', 'aaeaaad', 'o:8:', 'o:4:', 'a:1:',
            '__reduce__', 'pickle', 'marshal', 'yaml.load',
            '_$$nd_func$$_', 'binaryformatter',
        }
        
        # LDAP keywords
        self.attack_keywords['ldap'] = {
            'ldap', '(cn=', '(uid=', '(objectclass', '|(',  '&(', '!(', '*)',
        }
    
    def _init_known_signatures(self):
        """Initialize bloom filter with known malicious payloads"""
        
        known_payloads = [
            # SQLi
            "' or '1'='1", "' or 1=1--", "' union select", "'; drop table",
            "1' or '1'='1", "admin'--", "' and 1=1--", "' and sleep(",
            "'; waitfor delay", "' union all select null",
            
            # XSS
            "<script>alert(", "javascript:alert", "onerror=alert",
            "<img src=x onerror", "<svg onload", "<body onload",
            "document.cookie", "eval(", "fromcharcode",
            
            # RCE
            "; cat /etc/passwd", "| whoami", "`id`", "$(id)",
            "; nc -e", "bash -i >& /dev/tcp", "| nc -c sh",
            
            # Path traversal
            "../../../etc/passwd", "..\\..\\windows", "....//....//",
            "php://filter/convert", "file:///etc/passwd",
            
            # SSRF
            "http://127.0.0.1", "http://localhost", "http://169.254.169.254",
            "gopher://127.0.0.1", "dict://localhost",
            
            # XXE
            "<!entity xxe system", "<!doctype foo", "file:///etc/passwd",
            
            # SSTI
            "{{7*7}}", "${7*7}", "__class__.__mro__", "__globals__",
            "config.__class__", "request.application",
            
            # NoSQL
            '{"$ne": null}', '{"$gt": ""}', '{"$where":', '[$ne]=',
            
            # JWT
            '"alg":"none"', '"alg": "none"', 'eyJhbGciOiJub25lIi',
            
            # GraphQL
            "__schema{types{name}}", "__type(name:",
            
            # Prototype pollution
            '"__proto__":', 'constructor.prototype', '__proto__=',
            
            # Deserialization
            "ro0ab", "aced0005", 'o:8:"stdclass"', "_$$nd_func$$_",
            
            # LDAP
            "*)(uid=*))(|(uid=*", ")(cn=*)", "&(uid=",
            
            # CRLF
            "%0d%0aset-cookie", "%0d%0alocation:", "\r\nset-cookie",
        ]
        
        for payload in known_payloads:
            self.signature_bloom.add(payload.lower())
            # Add normalized version
            normalized = self._normalize_payload(payload)
            self.signature_bloom.add(normalized)
    
    def _normalize_payload(self, payload: str) -> str:
        """Normalize payload for signature matching"""
        normalized = ' '.join(payload.lower().split())
        normalized = normalized.replace('/*', '').replace('*/', '')
        normalized = normalized.replace('%20', ' ').replace('+', ' ')
        return normalized
    
    def quick_check(self, text: str) -> Tuple[bool, Set[str]]:
        """
        Ultra-fast pre-filter using keyword matching
        Returns (is_suspicious, potential_categories)
        Target: < 0.1ms
        """
        if not text:
            return False, set()
        
        text_lower = text.lower()
        categories = set()
        
        # Check bloom filter first (O(1))
        if self.signature_bloom.contains(text_lower):
            return True, {"KNOWN_SIGNATURE"}
        
        if self.signature_bloom.contains(self._normalize_payload(text)):
            return True, {"KNOWN_SIGNATURE"}
        
        # For query strings, also check individual parameter values
        if '=' in text:
            for part in text.split('&'):
                if '=' in part:
                    value = part.split('=', 1)[1] if '=' in part else part
                    if self.signature_bloom.contains(value.lower()):
                        return True, {"KNOWN_SIGNATURE"}
        
        # Quick keyword check
        words = set(re.findall(r'[a-zA-Z_$]{2,}', text_lower))
        
        # Check each attack category
        if words & self.attack_keywords['sqli']:
            categories.add("SQLI")
        if words & self.attack_keywords['nosql']:
            categories.add("NOSQL")
        if words & self.attack_keywords['xss']:
            categories.add("XSS")
        if words & self.attack_keywords['rce']:
            categories.add("RCE")
        if words & self.attack_keywords['xxe']:
            categories.add("XXE")
        if words & self.attack_keywords['ssti']:
            categories.add("SSTI")
        if words & self.attack_keywords['jwt']:
            categories.add("JWT")
        if words & self.attack_keywords['graphql']:
            categories.add("GRAPHQL")
        if words & self.attack_keywords['proto']:
            categories.add("PROTO_POLLUTION")
        if words & self.attack_keywords['deser']:
            categories.add("DESERIALIZATION")
        if words & self.attack_keywords['ldap']:
            categories.add("LDAP")
        
        # Character pattern checks
        if '../' in text or '..\\' in text or '%2e%2e' in text_lower:
            categories.add("PATH_TRAVERSAL")
            categories.add("LFI")
        
        if '<' in text and '>' in text:
            categories.add("XSS")
        
        if any(c in text for c in [';', '|', '`', '$(']):
            categories.add("RCE")
        
        if '{{' in text or '${' in text or '<%' in text:
            categories.add("SSTI")
        
        if '{' in text and '$' in text:
            categories.add("NOSQL")
            categories.add("PROTO_POLLUTION")
        
        # SSRF checks
        for kw in ['169.254.', '127.0.0.1', 'localhost', '10.', '192.168.', '172.16.']:
            if kw in text_lower:
                categories.add("SSRF")
                break
        
        if any(p in text_lower for p in ['file://', 'gopher://', 'dict://', 'ldap://']):
            categories.add("SSRF")
        
        # CRLF checks
        if '%0d' in text_lower or '%0a' in text_lower or '\r' in text or '\n' in text:
            categories.add("CRLF")
        
        # Redirect checks
        if '=//' in text or '=http' in text_lower:
            categories.add("OPEN_REDIRECT")
        
        return bool(categories), categories
    
    def scan(self, text: str, location: str = "body",
             categories: Optional[Set[str]] = None) -> List[Tuple[PatternRule, re.Match]]:
        """
        Full pattern scan with optional category filtering
        Target: < 0.5ms per location
        """
        if not text:
            return []
        
        matches = []
        
        # Determine which categories to check
        if categories is None:
            categories = set(self.patterns.keys())
        
        for category in categories:
            if category not in self.patterns:
                continue
            
            for rule in self.patterns[category]:
                if location not in rule.locations:
                    continue
                
                try:
                    match = rule.pattern.search(text)
                    if match:
                        matches.append((rule, match))
                except:
                    pass
        
        return matches
    
    def scan_request(self, path: str, query: str, body: str,
                     headers: Dict[str, str]) -> List[Tuple[PatternRule, re.Match, str]]:
        """
        Scan entire request for ALL attack types
        Returns list of (rule, match, location)
        Target: < 1ms total
        """
        all_matches = []
        
        # Combine for quick check
        combined = f"{path} {query} {body}"
        is_suspicious, potential_categories = self.quick_check(combined)
        
        # Also check headers
        if not is_suspicious:
            for header_value in headers.values():
                header_suspicious, header_cats = self.quick_check(header_value)
                if header_suspicious:
                    is_suspicious = True
                    potential_categories = potential_categories | header_cats
        
        if not is_suspicious:
            return []  # Fast path - nothing suspicious
        
        # When suspicious, scan ALL attack categories
        scan_categories = set(self.patterns.keys())
        
        # Scan each location
        if path:
            for rule, match in self.scan(path, "path", scan_categories):
                all_matches.append((rule, match, "path"))
        
        if query:
            for rule, match in self.scan(query, "query", scan_categories):
                all_matches.append((rule, match, "query"))
        
        if body:
            for rule, match in self.scan(body, "body", scan_categories):
                all_matches.append((rule, match, "body"))
        
        # Check headers
        for header_name, header_value in headers.items():
            location = f"header:{header_name}"
            for rule, match in self.scan(header_value, "headers", scan_categories):
                all_matches.append((rule, match, location))
        
        # Check cookies specifically
        cookie = headers.get('cookie', '')
        if cookie:
            for rule, match in self.scan(cookie, "cookie", scan_categories):
                all_matches.append((rule, match, "cookie"))
        
        return all_matches
    
    def add_dynamic_rule(self, rule: PatternRule) -> bool:
        """Add a dynamically generated rule"""
        try:
            if isinstance(rule.pattern, str):
                rule.pattern = re.compile(rule.pattern, re.IGNORECASE)
            
            self.patterns[rule.category].append(rule)
            
            # Add key terms to bloom filter
            pattern_str = rule.pattern.pattern if hasattr(rule.pattern, 'pattern') else str(rule.pattern)
            tokens = re.findall(r'[a-zA-Z]{3,}', pattern_str)
            for token in tokens:
                self.signature_bloom.add(token.lower())
            
            return True
        except Exception as e:
            return False
    
    def get_stats(self) -> Dict[str, int]:
        """Get pattern statistics"""
        return {
            'total_patterns': sum(len(rules) for rules in self.patterns.values()),
            'categories': len(self.patterns),
            'bloom_filter_items': self.signature_bloom.count,
            **{cat: len(rules) for cat, rules in self.patterns.items()}
        }


# Singleton instance
pattern_engine = ComprehensivePatternEngine()


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    print("MIRAGE Comprehensive Pattern Engine v2.0")
    print("=" * 60)
    
    engine = ComprehensivePatternEngine()
    stats = engine.get_stats()
    
    print(f"\nTotal patterns: {stats['total_patterns']}")
    print(f"Categories: {stats['categories']}")
    print(f"Bloom filter items: {stats['bloom_filter_items']}")
    
    print("\nPatterns by category:")
    for key, value in stats.items():
        if key not in ['total_patterns', 'categories', 'bloom_filter_items']:
            print(f"  {key}: {value}")
    
    # Test scanning
    test_payloads = [
        ("SQLi", "' OR '1'='1'--"),
        ("NoSQL", '{"$ne": null}'),
        ("XSS", "<script>alert(1)</script>"),
        ("RCE", "; cat /etc/passwd"),
        ("Path Traversal", "../../../etc/passwd"),
        ("SSRF", "http://169.254.169.254/latest/meta-data/"),
        ("XXE", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM"),
        ("SSTI", "{{config.__class__}}"),
        ("JWT", '{"alg":"none"}'),
        ("GraphQL", "__schema{types}"),
        ("Prototype Pollution", '{"__proto__": {"admin": true}}'),
        ("LDAP", "*)(uid=*)"),
        ("CRLF", "%0d%0aSet-Cookie:hacked"),
        ("Benign", "search?q=hello+world"),
    ]
    
    print("\n" + "=" * 60)
    print("SCAN TESTS")
    print("=" * 60)
    
    import time
    
    for name, payload in test_payloads:
        start = time.perf_counter()
        is_suspicious, categories = engine.quick_check(payload)
        quick_time = (time.perf_counter() - start) * 1000
        
        start = time.perf_counter()
        matches = engine.scan(payload, "query")
        scan_time = (time.perf_counter() - start) * 1000
        
        status = "⚠️  BLOCKED" if matches else "✓  ALLOWED"
        cats = ', '.join(categories) if categories else 'None'
        
        print(f"\n{name}: {status}")
        print(f"  Quick check: {quick_time:.3f}ms, Categories: {cats}")
        print(f"  Full scan: {scan_time:.3f}ms, Matches: {len(matches)}")
        if matches:
            for rule, match in matches[:3]:
                print(f"    - [{rule.category}] {rule.description}")
