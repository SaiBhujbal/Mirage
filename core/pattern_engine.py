"""
DECEPTICON Fast Pattern Matching Engine
Target: < 0.5ms for all pattern checks combined

Uses:
1. Bloom filter for O(1) known-bad signature lookup
2. Pre-compiled regex patterns with early termination
3. Aho-Corasick for multi-pattern matching
"""
import re
import hashlib
try:
    import mmh3
except ImportError:
    mmh3 = None
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from collections import defaultdict
import struct

class BloomFilter:
    """
    Ultra-fast bloom filter for known malicious signatures
    O(1) lookup with configurable false positive rate
    """
    
    def __init__(self, expected_items: int = 100000, fp_rate: float = 0.001):
        # Calculate optimal size and hash count
        self.size = self._optimal_size(expected_items, fp_rate)
        self.hash_count = self._optimal_hash_count(self.size, expected_items)
        self.bit_array = bytearray((self.size + 7) // 8)
        self.count = 0
    
    def _optimal_size(self, n: int, p: float) -> int:
        """Calculate optimal bit array size"""
        import math
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)
    
    def _optimal_hash_count(self, m: int, n: int) -> int:
        """Calculate optimal number of hash functions"""
        import math
        k = (m / n) * math.log(2)
        return max(1, int(k))
    
    def _get_hash_values(self, item: str) -> List[int]:
        """Generate k hash values using double hashing"""
        if mmh3:
            h1 = mmh3.hash(item, seed=0) & 0xFFFFFFFF
            h2 = mmh3.hash(item, seed=h1) & 0xFFFFFFFF
        else:
            # Fallback to hashlib if mmh3 is not available
            h_obj = hashlib.md5(item.encode())
            h1 = int(h_obj.hexdigest()[:8], 16) & 0xFFFFFFFF
            h2 = int(h_obj.hexdigest()[8:16], 16) & 0xFFFFFFFF
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
    locations: List[str]  # Where to check: path, query, body, headers
    
class FastPatternEngine:
    """
    High-performance pattern matching engine
    Target: < 0.5ms for full scan
    """
    
    def __init__(self):
        # Bloom filter for known malicious payloads
        self.signature_bloom = BloomFilter(expected_items=100000, fp_rate=0.001)
        
        # Compiled regex patterns by category
        self.patterns: Dict[str, List[PatternRule]] = defaultdict(list)
        
        # Quick keyword sets for fast pre-filtering
        self.sqli_keywords: Set[str] = set()
        self.xss_keywords: Set[str] = set()
        self.rce_keywords: Set[str] = set()
        
        # Initialize patterns
        self._init_patterns()
        self._init_keywords()
        self._init_known_signatures()
    
    def _init_patterns(self):
        """Initialize compiled regex patterns"""
        
        # SQL Injection patterns (optimized regex)
        sqli_patterns = [
            (r"(?i)(?:'|\")?\s*(?:or|and)\s+(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+", 0.95, "Boolean-based SQLi"),
            (r"(?i)union\s+(?:all\s+)?select", 0.98, "UNION SELECT"),
            # A bare SQL verb ("select an option", "update your profile", "delete this
            # message") is ordinary English, NOT SQLi — matching "keyword\s+" caused mass
            # false positives. But narrowing to structure-only silently opened a bypass
            # (id=1 EXEC xp_cmdshell), so this rule has THREE branches, each ReDoS-safe
            # (bounded lazy spans): (1) genuine statement structure; (2) DBA / dynamic-SQL
            # execution tokens that never occur as benign prose; (3) any DML verb sitting in
            # an INJECTION context — right after a quote, closing paren, ']', ';' or a
            # boolean operator — which prose ("please select") never is.
            (r"(?i)("
             r"\bselect\s+(?:.{0,120}?\bfrom\b|@@|\bsleep\b|\bbenchmark\b)"
             r"|insert\s+into\b|update\s+.{0,80}?\bset\b|delete\s+from\b"
             r"|drop\s+(?:table|database|schema|index|view|column)\b"
             r"|create\s+(?:table|database|schema)\b|alter\s+(?:table|database)\b"
             r"|(?:exec|execute)\s*(?:\(|@|xp_|sp_|\bmaster\b|\[)"
             r"|\bdeclare\s+@|\bwaitfor\s+delay\b"
             r"|(?:['\")\];]|\b(?:and|or)\b)\s+(?:select|insert|update|delete|drop|create|alter)\b"
             r")", 0.9, "SQL statement"),
            (r"(?i)(?:--|#|/\*|\*/)", 0.6, "SQL comment"),
            (r"(?i)(?:sleep|benchmark|waitfor)\s*\(", 0.95, "Time-based SQLi"),
            (r"(?i)(?:load_file|into\s+(?:out|dump)file)", 0.95, "File operation SQLi"),
            (r"(?i)information_schema", 0.9, "Schema enumeration"),
            (r"(?i)(?:char|chr|concat|substring|ascii)\s*\(", 0.7, "SQL function"),
            (r"(?i)(?:having|group\s+by|order\s+by)\s+\d+", 0.8, "Column enumeration"),
            (r"(?i)0x[0-9a-f]+", 0.5, "Hex encoding"),
        ]
        
        for pattern, severity, desc in sqli_patterns:
            self.patterns["SQLI"].append(PatternRule(
                rule_id=f"SQLI-{len(self.patterns['SQLI'])+1:03d}",
                category="SQLI",
                pattern=re.compile(pattern),
                severity=severity,
                description=desc,
                locations=["query", "body", "path"]
            ))
        
        # XSS patterns
        xss_patterns = [
            (r"<script[^>]*>", 0.95, "Script tag"),
            (r"(?i)javascript\s*:", 0.9, "JavaScript protocol"),
            (r"(?i)on(?:load|error|click|mouse|focus|blur|change|submit|key)\s*=", 0.9, "Event handler"),
            (r"(?i)<iframe[^>]*>", 0.85, "Iframe injection"),
            (r"(?i)<(?:img|svg|object|embed)[^>]+(?:onerror|onload)\s*=", 0.95, "Tag event XSS"),
            (r"(?i)(?:document|window)\s*\.", 0.7, "DOM access"),
            (r"(?i)(?:alert|confirm|prompt|eval)\s*\(", 0.8, "JS function call"),
            (r"(?i)data\s*:\s*text/html", 0.85, "Data URI XSS"),
            (r"(?i)<\s*style[^>]*>.*?expression\s*\(", 0.9, "CSS expression"),
        ]
        
        for pattern, severity, desc in xss_patterns:
            self.patterns["XSS"].append(PatternRule(
                rule_id=f"XSS-{len(self.patterns['XSS'])+1:03d}",
                category="XSS",
                pattern=re.compile(pattern),
                severity=severity,
                description=desc,
                locations=["query", "body", "headers"]
            ))
        
        # Command Injection / RCE patterns
        rce_patterns = [
            (r"(?:;|\||\|\||&&)\s*(?:cat|ls|dir|type|net|whoami|id|uname|pwd)", 0.95, "Command chaining"),
            (r"\$\(.*?\)", 0.8, "Command substitution"),
            (r"`[^`]+`", 0.8, "Backtick execution"),
            (r"(?i)(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", 0.95, "PHP RCE"),
            (r"(?i)(?:eval|assert|create_function|call_user_func)\s*\(", 0.9, "PHP code execution"),
            (r"(?:^|[;&|])\s*(?:nc|netcat|ncat)\s+", 0.95, "Netcat reverse shell"),
            (r"(?i)(?:bash|sh|cmd|powershell)(?:\s+-[a-z])?\s+", 0.7, "Shell invocation"),
            (r"/(?:etc/passwd|etc/shadow|proc/self)", 0.9, "Sensitive file access"),
            (r"(?i)\bping\s+-[nc]\s+\d+\s+", 0.7, "Ping command"),
            (r"(?i)\bcurl\s+.+\|.+(?:bash|sh)", 0.98, "Remote code execution"),
        ]
        
        for pattern, severity, desc in rce_patterns:
            self.patterns["RCE"].append(PatternRule(
                rule_id=f"RCE-{len(self.patterns['RCE'])+1:03d}",
                category="RCE",
                pattern=re.compile(pattern),
                severity=severity,
                description=desc,
                locations=["query", "body"]
            ))
        
        # Path Traversal / LFI patterns
        lfi_patterns = [
            (r"(?:\.\./|\.\.\\){2,}", 0.9, "Path traversal"),
            (r"(?i)(?:file|php|zip|phar|data|expect|input)://", 0.9, "PHP wrapper"),
            (r"(?i)/(?:etc|proc|var|usr|home|root)/", 0.7, "Unix path"),
            (r"(?i)[a-z]:\\(?:windows|system32|users)", 0.7, "Windows path"),
            (r"(?i)(?:boot\.ini|win\.ini|system\.ini)", 0.95, "Windows system file"),
            (r"%(?:00|2e|2f|5c)", 0.8, "Encoded traversal"),
        ]
        
        for pattern, severity, desc in lfi_patterns:
            self.patterns["LFI"].append(PatternRule(
                rule_id=f"LFI-{len(self.patterns['LFI'])+1:03d}",
                category="LFI",
                pattern=re.compile(pattern),
                severity=severity,
                description=desc,
                locations=["path", "query"]
            ))
        
        # SSRF patterns
        ssrf_patterns = [
            (r"(?i)(?:127\.0\.0\.1|localhost|0\.0\.0\.0)", 0.8, "Localhost access"),
            (r"(?i)(?:169\.254\.\d+\.\d+)", 0.9, "AWS metadata"),
            (r"(?i)(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)", 0.7, "Private IP"),
            (r"(?i)file:///", 0.95, "File protocol"),
            (r"(?i)gopher://", 0.95, "Gopher protocol"),
            (r"(?i)dict://", 0.9, "Dict protocol"),
            (r"@(?:127\.0\.0\.1|localhost)", 0.9, "URL auth bypass"),
        ]
        
        for pattern, severity, desc in ssrf_patterns:
            self.patterns["SSRF"].append(PatternRule(
                rule_id=f"SSRF-{len(self.patterns['SSRF'])+1:03d}",
                category="SSRF",
                pattern=re.compile(pattern),
                severity=severity,
                description=desc,
                locations=["query", "body"]
            ))
        
        # Scanner detection patterns
        scanner_patterns = [
            (r"(?i)(?:sqlmap|nikto|nmap|nessus|acunetix|burp|zap|w3af|skipfish)", 0.95, "Scanner UA"),
            (r"(?i)(?:masscan|gobuster|dirb|dirbuster|ffuf|wfuzz)", 0.95, "Directory scanner"),
            (r"(?i)python-requests/|curl/|wget/", 0.5, "Script UA"),
        ]
        
        for pattern, severity, desc in scanner_patterns:
            self.patterns["SCANNER"].append(PatternRule(
                rule_id=f"SCAN-{len(self.patterns['SCANNER'])+1:03d}",
                category="SCANNER",
                pattern=re.compile(pattern),
                severity=severity,
                description=desc,
                locations=["headers"]
            ))
    
    def _init_keywords(self):
        """Initialize quick-check keyword sets"""
        self.sqli_keywords = {
            'select', 'union', 'insert', 'update', 'delete', 'drop',
            'exec', 'execute', 'having', 'order', 'group', 'where',
            'from', 'into', 'values', 'table', 'database', 'schema',
            'information_schema', 'sleep', 'benchmark', 'waitfor',
            'cast', 'convert', 'char', 'concat', '--', '/*', '*/',
        }
        
        self.xss_keywords = {
            'script', 'javascript', 'onerror', 'onload', 'onclick',
            'onmouseover', 'onfocus', 'alert', 'confirm', 'prompt',
            'document', 'window', 'eval', 'iframe', 'svg', 'img',
        }
        
        self.rce_keywords = {
            'system', 'exec', 'shell', 'popen', 'passthru', 'eval',
            'cmd', 'bash', 'sh', 'powershell', 'nc', 'netcat',
            'curl', 'wget', 'ping', 'cat', 'ls', 'whoami', 'id',
        }
    
    def _init_known_signatures(self):
        """Load known malicious signatures into bloom filter"""
        # Add known malicious payloads
        known_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "1' AND '1'='1",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "; ls -la",
            "| cat /etc/passwd",
            "../../../etc/passwd",
            "{{constructor.constructor('return this')()}}",
            "${7*7}",
            "{{7*7}}",
            "<%=7*7%>",
        ]
        
        for payload in known_payloads:
            self.signature_bloom.add(payload.lower())
            # Also add normalized version
            normalized = self._normalize_payload(payload)
            self.signature_bloom.add(normalized)
    
    def _normalize_payload(self, payload: str) -> str:
        """Normalize payload for signature matching"""
        # Remove whitespace variations
        normalized = ' '.join(payload.lower().split())
        # Remove common obfuscation
        normalized = normalized.replace('/*', '').replace('*/', '')
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
                    if self.signature_bloom.contains(self._normalize_payload(value)):
                        return True, {"KNOWN_SIGNATURE"}
        
        # Quick keyword check - check full text and parts
        words = set(re.findall(r'\w+', text_lower))
        
        if words & self.sqli_keywords:
            categories.add("SQLI")
        if words & self.xss_keywords:
            categories.add("XSS")
        if words & self.rce_keywords:
            categories.add("RCE")
        
        # Quick character pattern checks
        if '../' in text or '..\\' in text:
            categories.add("LFI")
        if '<' in text and '>' in text:
            categories.add("XSS")
        if any(c in text for c in [';', '|', '`', '$(']):
            categories.add("RCE")
        if '&&' in text and 'javascript' not in text_lower:
            categories.add("RCE")
        
        # SQLi specific character patterns
        if "'" in text and any(kw in text_lower for kw in ['or', 'and', 'union', 'select', '--', '/*']):
            categories.add("SQLI")
        if '"' in text and any(kw in text_lower for kw in ['or', 'and', 'union', 'select']):
            categories.add("SQLI")
        
        # SSRF checks - look for internal/metadata IPs
        if '169.254.' in text or '127.0.0.1' in text or 'localhost' in text:
            categories.add("SSRF")
        if '10.' in text or '192.168.' in text or '172.16.' in text:
            categories.add("SSRF")
        if 'file://' in text_lower or 'gopher://' in text_lower or 'dict://' in text_lower:
            categories.add("SSRF")
        
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
                # Check if this rule applies to this location
                if location not in rule.locations:
                    continue
                
                # Run regex
                match = rule.pattern.search(text)
                if match:
                    matches.append((rule, match))
        
        return matches
    
    def scan_request(self, path: str, query: str, body: str, 
                     headers: Dict[str, str]) -> List[Tuple[PatternRule, re.Match, str]]:
        """
        Scan entire request
        Returns list of (rule, match, location)
        Target: < 1ms total
        """
        all_matches = []

        # ALWAYS check user-agent for scanner patterns first (even on benign traffic)
        # This is cheap and catches reconnaissance attempts
        ua = headers.get('user-agent', '')
        if ua:
            for rule, match in self.scan(ua, "headers", {"SCANNER"}):
                all_matches.append((rule, match, "headers"))

        # Combine for quick check
        combined = f"{path} {query} {body}"
        is_suspicious, potential_categories = self.quick_check(combined)

        if not is_suspicious:
            # Also check headers for scanner patterns in bloom filter
            header_suspicious, header_cats = self.quick_check(ua)
            if header_suspicious:
                is_suspicious = True
                potential_categories = header_cats

        if not is_suspicious:
            # If we found scanner patterns, return those
            if all_matches:
                return all_matches
            return []  # Fast path - nothing suspicious

        # When suspicious, scan ALL attack categories (not just quick_check hints)
        # Quick check is a pre-filter to skip benign traffic, not to limit scan scope
        scan_categories = {"SQLI", "XSS", "RCE", "LFI", "SSRF"}

        # Detailed scan on suspicious requests - check all attack types
        if path:
            for rule, match in self.scan(path, "path", scan_categories):
                all_matches.append((rule, match, "path"))

        if query:
            for rule, match in self.scan(query, "query", scan_categories):
                all_matches.append((rule, match, "query"))

        if body:
            for rule, match in self.scan(body, "body", scan_categories):
                all_matches.append((rule, match, "body"))

        return all_matches
    
    def add_dynamic_rule(self, rule: PatternRule):
        """
        Add a dynamically generated rule
        Called by the rule generator when ML detects a new pattern
        
        This is the feedback loop:
        ML Detection → Rule Generated → Added Here → Next time blocked at pattern stage
        """
        try:
            # Compile pattern if it's a string
            if isinstance(rule.pattern, str):
                rule.pattern = re.compile(rule.pattern, re.IGNORECASE)
            
            # Add to appropriate category
            self.patterns[rule.category].append(rule)
            
            # Add key terms to bloom filter for quick lookup
            # Extract alphanumeric tokens from the pattern string
            pattern_str = rule.pattern.pattern if hasattr(rule.pattern, 'pattern') else str(rule.pattern)
            tokens = re.findall(r'[a-zA-Z]{3,}', pattern_str)
            for token in tokens:
                self.signature_bloom.add(token.lower())
            
            return True
            
        except Exception as e:
            print(f"Failed to add dynamic rule: {e}")
            return False
    
    def get_dynamic_rules_count(self) -> Dict[str, int]:
        """Get count of rules by category"""
        return {cat: len(rules) for cat, rules in self.patterns.items()}

    @property
    def static_rules(self) -> List[Dict]:
        """Return all rules as dictionaries (for API compatibility)"""
        all_rules = []
        for category, rules in self.patterns.items():
            for rule in rules:
                all_rules.append({
                    "id": rule.rule_id,
                    "category": rule.category,
                    "severity": rule.severity,
                    "pattern": rule.pattern.pattern if hasattr(rule.pattern, 'pattern') else str(rule.pattern),
                    "description": rule.description,
                    "locations": rule.locations
                })
        return all_rules

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by its ID"""
        for category, rules in self.patterns.items():
            for i, rule in enumerate(rules):
                if rule.rule_id == rule_id:
                    rules.pop(i)
                    return True
        return False

# Singleton instance
pattern_engine = FastPatternEngine()
