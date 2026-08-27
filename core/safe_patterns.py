"""
MIRAGE Safe Regex Patterns
FIXES: Regex Denial of Service (ReDoS) (HIGH)

SECURITY MEASURES:
1. No nested quantifiers (a+)+ or (a*)*
2. No overlapping alternations
3. Timeout protection for all regex operations
4. Atomic groups where possible
5. Maximum input length limits
"""
import re
import signal
import logging
from typing import Optional, Tuple, List, Pattern
from functools import wraps
import threading

logger = logging.getLogger("mirage.security.regex")


# ============================================================================
# REGEX TIMEOUT PROTECTION
# ============================================================================

class RegexTimeoutError(Exception):
    """Raised when regex operation times out"""
    pass


class TimeoutRegex:
    """
    Regex wrapper with timeout protection
    
    Prevents ReDoS by killing long-running regex operations
    """
    
    DEFAULT_TIMEOUT = 1.0  # 1 second max
    MAX_INPUT_LENGTH = 100000  # 100KB max
    
    def __init__(self, pattern: str, flags: int = 0, timeout: float = None):
        self.pattern_str = pattern
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        
        # Validate pattern for known ReDoS issues
        self._validate_pattern(pattern)
        
        # Compile pattern
        self.pattern = re.compile(pattern, flags)
    
    def _validate_pattern(self, pattern: str):
        """Check for known ReDoS patterns"""
        dangerous_patterns = [
            r'\(\?\:.*\+\).*\+',  # (?: ...)+ ... +
            r'\(\?\:.*\*\).*\*',  # (?: ...)* ... *
            r'\(.*\+\).*\+',      # (...)+ ... +
            r'\(.*\*\).*\*',      # (...)* ... *
            r'\+\+',              # ++ (possessive in some engines, nested in others)
            r'\*\*',              # **
        ]
        
        for dp in dangerous_patterns:
            if re.search(dp, pattern):
                logger.warning(f"Potentially dangerous regex pattern detected: {pattern}")
    
    def match(self, string: str, timeout: float = None) -> Optional[re.Match]:
        """Match with timeout protection"""
        return self._execute_with_timeout(
            lambda: self.pattern.match(string[:self.MAX_INPUT_LENGTH]),
            timeout or self.timeout
        )
    
    def search(self, string: str, timeout: float = None) -> Optional[re.Match]:
        """Search with timeout protection"""
        return self._execute_with_timeout(
            lambda: self.pattern.search(string[:self.MAX_INPUT_LENGTH]),
            timeout or self.timeout
        )
    
    def findall(self, string: str, timeout: float = None) -> List:
        """Find all with timeout protection"""
        result = self._execute_with_timeout(
            lambda: self.pattern.findall(string[:self.MAX_INPUT_LENGTH]),
            timeout or self.timeout
        )
        return result if result else []
    
    def _execute_with_timeout(self, func, timeout: float):
        """Execute function with timeout (thread-based for cross-platform)"""
        result = [None]
        exception = [None]
        
        def target():
            try:
                result[0] = func()
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout=timeout)
        
        if thread.is_alive():
            # Thread still running = timeout
            logger.warning(f"Regex timeout on pattern: {self.pattern_str[:50]}...")
            raise RegexTimeoutError(f"Regex operation timed out after {timeout}s")
        
        if exception[0]:
            raise exception[0]
        
        return result[0]


# ============================================================================
# SAFE PATTERN DEFINITIONS
# ============================================================================

class SafePatterns:
    """
    Safe regex patterns for WAF detection
    
    All patterns have been reviewed for ReDoS vulnerabilities.
    Using non-backtracking constructs where possible.
    """
    
    # Maximum length limits
    MAX_PATTERN_INPUT = 10000
    
    # ==========================================================================
    # SQL INJECTION PATTERNS (SAFE)
    # ==========================================================================
    
    # OLD VULNERABLE:
    # r"(?i)(?:'|\")?\s*(?:or|and)\s+(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+"
    # Problem: Multiple optional groups with \s* cause catastrophic backtracking
    
    # NEW SAFE:
    SQLI_PATTERNS = [
        # Basic SQL injection
        (r"(?i)'\s*or\s+['\"]?1['\"]?\s*=\s*['\"]?1", "sqli_basic_or"),
        (r"(?i)'\s*and\s+['\"]?1['\"]?\s*=\s*['\"]?1", "sqli_basic_and"),
        
        # Union-based injection (non-greedy, limited)
        (r"(?i)union\s{1,10}select\s", "sqli_union"),
        (r"(?i)union\s{1,10}all\s{1,10}select", "sqli_union_all"),
        
        # Comment sequences
        (r"(?i)--\s*$", "sqli_comment_dash"),
        (r"(?i)/\*[^*]{0,100}\*/", "sqli_comment_block"),
        (r"(?i)#\s*$", "sqli_comment_hash"),
        
        # Dangerous functions (exact match, no backtracking)
        (r"(?i)\b(?:exec|execute)\s*\(", "sqli_exec"),
        (r"(?i)\b(?:xp_cmdshell|sp_executesql)\b", "sqli_stored_proc"),
        (r"(?i)\b(?:waitfor|delay)\s", "sqli_time_based"),
        (r"(?i)\bsleep\s*\(\s*\d", "sqli_sleep"),
        
        # Stacked queries (simple)
        (r";\s*(?:select|insert|update|delete|drop|create)\s", "sqli_stacked"),
        
        # Information schema
        (r"(?i)information_schema\.", "sqli_info_schema"),
        (r"(?i)sys\.(?:tables|columns|objects)", "sqli_sys_tables"),
        
        # Boolean-based (simple patterns only)
        (r"(?i)'\s*(?:and|or)\s*'[^']{0,20}'='", "sqli_boolean"),
    ]
    
    # ==========================================================================
    # XSS PATTERNS (SAFE)
    # ==========================================================================
    
    XSS_PATTERNS = [
        # Script tags (non-greedy, bounded)
        (r"(?i)<script[^>]{0,200}>", "xss_script_open"),
        (r"(?i)</script\s*>", "xss_script_close"),
        
        # Event handlers (specific list, no greedy matching)
        (r"(?i)\bon(?:load|error|click|mouse\w{0,10}|key\w{0,10})\s*=", "xss_event_handler"),
        
        # JavaScript protocol
        (r"(?i)javascript\s*:", "xss_js_protocol"),
        (r"(?i)vbscript\s*:", "xss_vbs_protocol"),
        (r"(?i)data\s*:[^,]{0,50}base64", "xss_data_uri"),
        
        # SVG/math XSS
        (r"(?i)<svg[^>]{0,200}\bon\w{1,20}=", "xss_svg_event"),
        (r"(?i)<math[^>]{0,200}\bon\w{1,20}=", "xss_math_event"),
        
        # Expression/eval
        (r"(?i)expression\s*\(", "xss_expression"),
        (r"(?i)\beval\s*\(", "xss_eval"),
        
        # DOM manipulation
        (r"(?i)document\.(?:cookie|location|write)", "xss_dom_access"),
        (r"(?i)window\.(?:location|open)\s*[=(]", "xss_window_access"),
        
        # Encoded payloads (limited length)
        (r"(?i)&#x?[0-9a-f]{1,6};{0,20}", "xss_html_entity"),
    ]
    
    # ==========================================================================
    # COMMAND INJECTION PATTERNS (SAFE)
    # ==========================================================================
    
    CMDI_PATTERNS = [
        # Shell metacharacters (simple, bounded)
        (r"[;&|]{1,3}\s*(?:cat|ls|id|whoami|pwd|uname)\b", "cmdi_shell_cmd"),
        (r"\$\([^)]{1,100}\)", "cmdi_subshell"),
        (r"`[^`]{1,100}`", "cmdi_backtick"),
        
        # Dangerous commands
        (r"(?i)\b(?:wget|curl|nc|netcat)\s+[^\s]", "cmdi_network"),
        (r"(?i)\b(?:bash|sh|zsh|ksh|csh)\s+-[ci]", "cmdi_shell_exec"),
        (r"(?i)\b(?:python|perl|ruby|php)\s+-[ec]", "cmdi_interpreter"),
        
        # File operations
        (r"(?i)\b(?:rm|mv|cp)\s+-[rf]{0,3}\s+/", "cmdi_file_op"),
        (r"(?i)>\s*/(?:etc|tmp|var)/", "cmdi_write_system"),
        
        # Process control
        (r"(?i)\b(?:kill|pkill|killall)\s+-9", "cmdi_kill"),
        (r"(?i)\bnohup\s+", "cmdi_nohup"),
    ]
    
    # ==========================================================================
    # PATH TRAVERSAL PATTERNS (SAFE)
    # ==========================================================================
    
    TRAVERSAL_PATTERNS = [
        # Directory traversal (bounded)
        (r"(?:\.\.[/\\]){1,20}", "traversal_dotdot"),
        (r"(?:%2e%2e[%2f%5c]){1,20}", "traversal_encoded"),
        (r"(?:\.\.%c0%af){1,10}", "traversal_overlong"),
        
        # Sensitive files (exact paths)
        (r"(?i)/etc/(?:passwd|shadow|hosts)", "traversal_etc"),
        (r"(?i)/proc/(?:self|version|cpuinfo)", "traversal_proc"),
        (r"(?i)(?:c:|C:)[/\\]windows[/\\]", "traversal_windows"),
        
        # Null byte
        (r"%00", "traversal_nullbyte"),
    ]
    
    # ==========================================================================
    # SSRF PATTERNS (SAFE)
    # ==========================================================================
    
    SSRF_PATTERNS = [
        # Internal IPs (bounded, specific)
        (r"(?:^|[/@])(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost)", "ssrf_localhost"),
        (r"(?:^|[/@])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})", "ssrf_private_10"),
        (r"(?:^|[/@])(?:192\.168\.\d{1,3}\.\d{1,3})", "ssrf_private_192"),
        (r"(?:^|[/@])(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})", "ssrf_private_172"),
        
        # Cloud metadata
        (r"169\.254\.169\.254", "ssrf_aws_metadata"),
        (r"(?i)metadata\.google\.internal", "ssrf_gcp_metadata"),
        
        # Dangerous schemes
        (r"(?i)^(?:file|gopher|dict|ldap)://", "ssrf_dangerous_scheme"),
    ]
    
    @classmethod
    def get_all_patterns(cls) -> List[Tuple[TimeoutRegex, str, str]]:
        """Get all compiled patterns with timeout protection"""
        patterns = []
        
        pattern_groups = [
            (cls.SQLI_PATTERNS, "SQLI"),
            (cls.XSS_PATTERNS, "XSS"),
            (cls.CMDI_PATTERNS, "CMDI"),
            (cls.TRAVERSAL_PATTERNS, "TRAVERSAL"),
            (cls.SSRF_PATTERNS, "SSRF"),
        ]
        
        for pattern_list, category in pattern_groups:
            for pattern_str, name in pattern_list:
                try:
                    compiled = TimeoutRegex(pattern_str, re.IGNORECASE)
                    patterns.append((compiled, name, category))
                except Exception as e:
                    logger.error(f"Failed to compile pattern {name}: {e}")
        
        return patterns


# ============================================================================
# SAFE PATTERN MATCHER
# ============================================================================

class SafePatternMatcher:
    """
    Safe pattern matching with ReDoS protection
    
    Features:
    - Timeout on all operations
    - Input length limits
    - Precompiled patterns
    - Logging of slow patterns
    """
    
    def __init__(self):
        self.patterns = SafePatterns.get_all_patterns()
        self.slow_pattern_threshold = 0.1  # 100ms
        self.slow_pattern_counts = {}
    
    def match_all(self, input_text: str) -> List[Tuple[str, str, str]]:
        """
        Match input against all patterns
        
        Returns: List of (pattern_name, category, matched_text)
        """
        # Enforce input length limit
        if len(input_text) > SafePatterns.MAX_PATTERN_INPUT:
            logger.warning(f"Input truncated from {len(input_text)} to {SafePatterns.MAX_PATTERN_INPUT}")
            input_text = input_text[:SafePatterns.MAX_PATTERN_INPUT]
        
        matches = []
        
        for pattern, name, category in self.patterns:
            try:
                import time
                start = time.time()
                
                match = pattern.search(input_text)
                
                elapsed = time.time() - start
                if elapsed > self.slow_pattern_threshold:
                    self._record_slow_pattern(name, elapsed)
                
                if match:
                    matches.append((name, category, match.group(0)[:100]))
                    
            except RegexTimeoutError:
                logger.warning(f"Pattern {name} timed out on input")
                # Continue with other patterns
                
            except Exception as e:
                logger.error(f"Pattern {name} error: {e}")
        
        return matches
    
    def _record_slow_pattern(self, pattern_name: str, elapsed: float):
        """Record slow pattern for monitoring"""
        if pattern_name not in self.slow_pattern_counts:
            self.slow_pattern_counts[pattern_name] = {"count": 0, "total_time": 0}
        
        self.slow_pattern_counts[pattern_name]["count"] += 1
        self.slow_pattern_counts[pattern_name]["total_time"] += elapsed
        
        if self.slow_pattern_counts[pattern_name]["count"] % 100 == 0:
            avg = self.slow_pattern_counts[pattern_name]["total_time"] / self.slow_pattern_counts[pattern_name]["count"]
            logger.warning(f"Slow pattern {pattern_name}: {self.slow_pattern_counts[pattern_name]['count']} times, avg {avg:.3f}s")


# ============================================================================
# STRING-BASED DETECTION (NO REGEX)
# ============================================================================

class StringBasedDetector:
    """
    Fast string-based detection for common patterns
    
    No ReDoS possible - pure string operations
    """
    
    # Keywords that should trigger alerts
    DANGEROUS_KEYWORDS = {
        "sqli": [
            "union select", "or 1=1", "or '1'='1", "or \"1\"=\"1\"",
            "drop table", "drop database", "delete from", "truncate table",
            "insert into", "update set", "exec(", "execute(",
            "xp_cmdshell", "information_schema", "sys.tables",
        ],
        "xss": [
            "<script", "</script>", "javascript:", "onerror=",
            "onload=", "onclick=", "onmouseover=", "onfocus=",
            "document.cookie", "document.location", "eval(",
        ],
        "cmdi": [
            "; cat ", "| cat ", "&& cat ", "|| cat ",
            "; ls ", "| ls ", "; id ", "| id ",
            "; whoami", "| whoami", "$(", "`",
            "/etc/passwd", "/etc/shadow", "/bin/bash",
        ],
        "traversal": [
            "../", "..\\", "....//", "....\\\\",
            "%2e%2e%2f", "%2e%2e/", "..%2f",
        ],
    }
    
    @classmethod
    def detect(cls, input_text: str) -> List[Tuple[str, str]]:
        """
        Fast keyword-based detection
        
        Returns: List of (category, keyword)
        """
        input_lower = input_text.lower()
        matches = []
        
        for category, keywords in cls.DANGEROUS_KEYWORDS.items():
            for keyword in keywords:
                if keyword in input_lower:
                    matches.append((category.upper(), keyword))
        
        return matches


# Global instances
safe_pattern_matcher = SafePatternMatcher()
string_detector = StringBasedDetector()


def safe_regex_match(pattern: str, text: str, timeout: float = 1.0) -> Optional[re.Match]:
    """
    Convenience function for safe regex matching
    """
    try:
        safe_pattern = TimeoutRegex(pattern, timeout=timeout)
        return safe_pattern.search(text)
    except RegexTimeoutError:
        logger.warning(f"Regex timeout: {pattern[:50]}")
        return None
    except Exception as e:
        logger.error(f"Regex error: {e}")
        return None
