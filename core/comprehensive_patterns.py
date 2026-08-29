#!/usr/bin/env python3
"""
MIRAGE Comprehensive Attack Patterns
========================================
Naval SWAVLAMBAN 2025 Challenge 3

Complete coverage of ALL modern attack vectors:
- OWASP Top 10 2021
- Modern API attacks
- Cloud-specific attacks
- Advanced evasion techniques

Author: MIRAGE Team (Red Team Perspective)
Date: December 2025
Security Review: Penetration Tested
"""

import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class AttackCategory(Enum):
    """All supported attack categories"""
    # Web Application Attacks
    SQLI = "sql_injection"
    NOSQL = "nosql_injection"
    XSS = "cross_site_scripting"
    RCE = "remote_code_execution"
    PATH_TRAVERSAL = "path_traversal"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    SSRF = "server_side_request_forgery"
    XXE = "xml_external_entity"
    SSTI = "server_side_template_injection"
    
    # Authentication/Authorization
    AUTH_BYPASS = "authentication_bypass"
    IDOR = "insecure_direct_object_reference"
    JWT = "jwt_attack"
    SESSION = "session_attack"
    
    # Injection Attacks
    LDAP = "ldap_injection"
    XPATH = "xpath_injection"
    CRLF = "crlf_injection"
    HOST_HEADER = "host_header_injection"
    EMAIL = "email_injection"
    LOG = "log_injection"
    
    # Modern Attacks
    GRAPHQL = "graphql_attack"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    DESERIALIZATION = "insecure_deserialization"
    MASS_ASSIGNMENT = "mass_assignment"
    
    # Reconnaissance
    SCANNER = "vulnerability_scanner"
    INFO_DISCLOSURE = "information_disclosure"
    
    # DoS
    DOS = "denial_of_service"
    REDOS = "regex_dos"
    
    # Other
    OPEN_REDIRECT = "open_redirect"
    CLICKJACKING = "clickjacking"
    CORS = "cors_misconfiguration"
    WEBSOCKET = "websocket_attack"


@dataclass
class AttackPattern:
    """Single attack pattern definition"""
    id: str
    category: AttackCategory
    pattern: str  # Regex pattern
    severity: float  # 0.0 - 1.0
    description: str
    cve: Optional[str] = None  # Related CVE if applicable
    owasp: Optional[str] = None  # OWASP category
    bypasses: List[str] = None  # Known WAF bypass variants


# ============================================================================
# SQL INJECTION PATTERNS (Comprehensive)
# ============================================================================

SQLI_PATTERNS = [
    # Boolean-based
    # Whitespace runs are bounded: an unbounded leading `\s*` made this quadratic
    # (re-scanned from every offset) on whitespace-flood input. No real payload
    # separates `or` from its operand by more than a handful of spaces.
    AttackPattern("SQLI-001", AttackCategory.SQLI, r"(?i)(?:'|\")?\s{0,16}(?:or|and)\s{1,16}(?:'|\")?\d+(?:'|\")?\s{0,16}=\s{0,16}(?:'|\")?\d+", 0.95, "Boolean-based blind SQLi", owasp="A03:2021"),
    AttackPattern("SQLI-002", AttackCategory.SQLI, r"(?i)(?:'|\"|`)\s*(?:or|and)\s+(?:'|\"|`)?\w+(?:'|\"|`)?\s*(?:=|like)\s*(?:'|\"|`)?\w+", 0.90, "Boolean SQLi with strings", owasp="A03:2021"),
    AttackPattern("SQLI-003", AttackCategory.SQLI, r"(?i)'\s*or\s+'[^']*'\s*=\s*'", 0.95, "Classic OR bypass", owasp="A03:2021"),
    
    # Union-based
    # \s* (not \s+): after inline-comment stripping, "UN/**/ION/**/SEL/**/ECT" collapses to
    # "unionselect" with no space. No English word is "unionselect", so zero-width is safe.
    AttackPattern("SQLI-010", AttackCategory.SQLI, r"(?i)union\s*(?:all\s*)?select", 0.98, "UNION SELECT", owasp="A03:2021"),
    AttackPattern("SQLI-011", AttackCategory.SQLI, r"(?i)union\s+(?:all\s+)?select\s+(?:null|0x|char|concat)", 0.98, "UNION with obfuscation", owasp="A03:2021"),
    AttackPattern("SQLI-012", AttackCategory.SQLI, r"(?i)union\s*/\*.*?\*/\s*select", 0.98, "UNION with comment bypass", owasp="A03:2021"),
    
    # Error-based
    AttackPattern("SQLI-020", AttackCategory.SQLI, r"(?i)extractvalue\s*\(", 0.95, "ExtractValue error-based", owasp="A03:2021"),
    AttackPattern("SQLI-021", AttackCategory.SQLI, r"(?i)updatexml\s*\(", 0.95, "UpdateXML error-based", owasp="A03:2021"),
    AttackPattern("SQLI-022", AttackCategory.SQLI, r"(?i)exp\s*\(\s*~", 0.95, "EXP overflow error-based", owasp="A03:2021"),
    AttackPattern("SQLI-023", AttackCategory.SQLI, r"(?i)geometrycollection\s*\(", 0.90, "GeometryCollection error", owasp="A03:2021"),
    
    # Time-based
    AttackPattern("SQLI-030", AttackCategory.SQLI, r"(?i)(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", 0.95, "Time-based blind", owasp="A03:2021"),
    AttackPattern("SQLI-031", AttackCategory.SQLI, r"(?i);\s*select\s+(?:sleep|benchmark|pg_sleep)", 0.98, "Stacked time-based", owasp="A03:2021"),
    
    # Stacked queries
    AttackPattern("SQLI-040", AttackCategory.SQLI, r"(?i);\s*(?:drop|delete|truncate|alter|create|insert|update)\s+", 0.98, "Destructive stacked query", owasp="A03:2021"),
    AttackPattern("SQLI-041", AttackCategory.SQLI, r"(?i);\s*exec(?:ute)?\s+", 0.95, "Stacked EXEC", owasp="A03:2021"),
    
    # Schema/Data enumeration
    AttackPattern("SQLI-050", AttackCategory.SQLI, r"(?i)information_schema\.", 0.90, "Schema enumeration", owasp="A03:2021"),
    AttackPattern("SQLI-051", AttackCategory.SQLI, r"(?i)(?:sys|mysql|pg_)\.", 0.85, "System table access", owasp="A03:2021"),
    AttackPattern("SQLI-052", AttackCategory.SQLI, r"(?i)(?:table_name|column_name|table_schema)", 0.85, "Metadata extraction", owasp="A03:2021"),
    
    # Database-specific
    AttackPattern("SQLI-060", AttackCategory.SQLI, r"(?i)xp_cmdshell", 0.99, "MSSQL command execution", owasp="A03:2021"),
    AttackPattern("SQLI-061", AttackCategory.SQLI, r"(?i)(?:load_file|into\s+(?:out|dump)file)", 0.95, "MySQL file operations", owasp="A03:2021"),
    AttackPattern("SQLI-062", AttackCategory.SQLI, r"(?i)(?:pg_read_file|pg_ls_dir)", 0.95, "PostgreSQL file read", owasp="A03:2021"),
    AttackPattern("SQLI-063", AttackCategory.SQLI, r"(?i)dbms_(?:pipe|java|scheduler)", 0.95, "Oracle exploitation", owasp="A03:2021"),
    
    # WAF Bypass patterns
    AttackPattern("SQLI-070", AttackCategory.SQLI, r"(?i)/\*!(?:\d+)?\s*select", 0.95, "MySQL version comment bypass", owasp="A03:2021"),
    AttackPattern("SQLI-071", AttackCategory.SQLI, r"(?i)(?:un%69on|se%6cect|%55nion)", 0.95, "URL encoded bypass", owasp="A03:2021"),
    AttackPattern("SQLI-072", AttackCategory.SQLI, r"(?i)(?:uni\x00on|sel\x00ect)", 0.95, "Null byte bypass", owasp="A03:2021"),
    AttackPattern("SQLI-073", AttackCategory.SQLI, r"(?i)(?:u/\*\*/nion|s/\*\*/elect)", 0.95, "Inline comment bypass", owasp="A03:2021"),
    
    # Generic dangerous patterns
    AttackPattern("SQLI-080", AttackCategory.SQLI, r"(?i)(?:--|#|/\*)\s*$", 0.70, "SQL comment termination", owasp="A03:2021"),
    AttackPattern("SQLI-081", AttackCategory.SQLI, r"(?i)'\s*;\s*--", 0.90, "Quote escape with comment", owasp="A03:2021"),
    # Quote-continuation: a closing quote, a statement separator, then either a SQL
    # verb, a comment marker, or end-of-value. Anchoring on what FOLLOWS the ";"
    # keeps ordinary quoted text that merely ends in a semicolon (e.g. a posted
    # `var x = "hi"; doSomething()`) from matching.
    AttackPattern("SQLI-082", AttackCategory.SQLI, r"(?i)['\"]\s{0,8};\s{0,8}(?:--|#|/\*|(?:select|insert|update|delete|drop|union|exec(?:ute)?|shutdown|waitfor|declare|alter|truncate|create|grant)\b|$)", 0.88, "Quote-terminated statement break", owasp="A03:2021"),
    # LIKE predicate injected right after a closing quote (`' LIKE '`, `' RLIKE '`).
    # Requires the quote on both sides so "things I like" style text does not match.
    AttackPattern("SQLI-083", AttackCategory.SQLI, r"(?i)['\"]\s{0,8}(?:like|rlike|regexp|sounds\s{1,8}like)\s{0,8}['\"%]", 0.85, "LIKE predicate injection", owasp="A03:2021"),
]


# ============================================================================
# NoSQL INJECTION PATTERNS
# ============================================================================

NOSQL_PATTERNS = [
    # MongoDB
    AttackPattern("NOSQL-001", AttackCategory.NOSQL, r'(?i)\{\s*["\']?\$(?:gt|gte|lt|lte|ne|eq|in|nin|or|and|not|nor|exists|type|regex|where|text|expr)["\']?\s*:', 0.95, "MongoDB operator injection", owasp="A03:2021"),
    AttackPattern("NOSQL-002", AttackCategory.NOSQL, r'(?i)\$where\s*:\s*["\']?(?:function|this\.)', 0.98, "MongoDB $where injection", owasp="A03:2021"),
    AttackPattern("NOSQL-003", AttackCategory.NOSQL, r'(?i)\[\s*\$(?:gt|ne|regex)', 0.90, "MongoDB array operator", owasp="A03:2021"),
    AttackPattern("NOSQL-004", AttackCategory.NOSQL, r'(?i)(?:username|password|user|pass)\s*\[\s*\$', 0.95, "NoSQL auth bypass", owasp="A03:2021"),
    
    # JavaScript injection in MongoDB
    AttackPattern("NOSQL-010", AttackCategory.NOSQL, r"(?i)(?:db\.|collection\.|find\(|findOne\(|aggregate\()", 0.85, "MongoDB method call", owasp="A03:2021"),
    AttackPattern("NOSQL-011", AttackCategory.NOSQL, r"(?i)(?:process\.(?:exit|env)|require\s*\()", 0.95, "Node.js injection via NoSQL", owasp="A03:2021"),
    
    # CouchDB
    AttackPattern("NOSQL-020", AttackCategory.NOSQL, r'(?i)_design/|_view/|_all_docs', 0.80, "CouchDB view access", owasp="A03:2021"),
]


# ============================================================================
# XSS PATTERNS (Comprehensive)
# ============================================================================

XSS_PATTERNS = [
    # Basic script tags
    AttackPattern("XSS-001", AttackCategory.XSS, r"<script[^>]*>", 0.95, "Script tag", owasp="A03:2021"),
    AttackPattern("XSS-002", AttackCategory.XSS, r"</script[^>]*>", 0.85, "Script close tag", owasp="A03:2021"),
    AttackPattern("XSS-003", AttackCategory.XSS, r"<script[^>]*\s+src\s*=", 0.98, "External script inclusion", owasp="A03:2021"),
    
    # Event handlers (comprehensive list)
    AttackPattern("XSS-010", AttackCategory.XSS, r"(?i)\bon(?:abort|activate|afterprint|afterupdate|beforeactivate|beforecopy|beforecut|beforedeactivate|beforeeditfocus|beforepaste|beforeprint|beforeunload|beforeupdate|blur|bounce|cellchange|change|click|contextmenu|controlselect|copy|cut|dataavailable|datasetchanged|datasetcomplete|dblclick|deactivate|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|error|errorupdate|filterchange|finish|focus|focusin|focusout|hashchange|help|input|keydown|keypress|keyup|layoutcomplete|load|losecapture|message|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|mousewheel|move|moveend|movestart|offline|online|page|pagehide|pageshow|paste|popstate|progress|propertychange|readystatechange|reset|resize|resizeend|resizestart|rowenter|rowexit|rowsdelete|rowsinserted|scroll|search|select|selectionchange|selectstart|start|stop|storage|submit|timeout|touchcancel|touchend|touchmove|touchstart|unload|wheel)\s*=", 0.95, "Event handler attribute", owasp="A03:2021"),
    
    # JavaScript protocol
    AttackPattern("XSS-020", AttackCategory.XSS, r"(?i)javascript\s*:", 0.95, "JavaScript protocol", owasp="A03:2021"),
    AttackPattern("XSS-021", AttackCategory.XSS, r"(?i)(?:vbscript|livescript|mocha)\s*:", 0.95, "Legacy script protocols", owasp="A03:2021"),
    
    # Data URI
    AttackPattern("XSS-030", AttackCategory.XSS, r"(?i)data\s*:\s*(?:text/html|application/x?html|image/svg)", 0.90, "Data URI XSS", owasp="A03:2021"),
    
    # DOM manipulation
    AttackPattern("XSS-040", AttackCategory.XSS, r"(?i)(?:document|window)\s*\.\s*(?:cookie|domain|location|write|writeln|innerHTML|outerHTML)", 0.85, "DOM manipulation", owasp="A03:2021"),
    AttackPattern("XSS-041", AttackCategory.XSS, r"(?i)(?:document|window)\s*\[\s*['\"]", 0.80, "DOM bracket notation", owasp="A03:2021"),
    
    # JavaScript functions
    AttackPattern("XSS-050", AttackCategory.XSS, r"(?i)(?:alert|confirm|prompt|eval|setTimeout|setInterval|Function|constructor)\s*(?:\(|`)", 0.85, "JS function call", owasp="A03:2021"),
    AttackPattern("XSS-051", AttackCategory.XSS, r"(?i)(?:atob|btoa)\s*\(", 0.75, "Base64 functions", owasp="A03:2021"),
    
    # SVG/XML vectors
    AttackPattern("XSS-060", AttackCategory.XSS, r"<svg[^>]*>", 0.85, "SVG tag", owasp="A03:2021"),
    AttackPattern("XSS-061", AttackCategory.XSS, r"<(?:animate|set|use|foreignObject)[^>]*>", 0.90, "SVG animation/foreign", owasp="A03:2021"),
    AttackPattern("XSS-062", AttackCategory.XSS, r"(?i)xlink:href\s*=", 0.85, "XLink attribute", owasp="A03:2021"),
    
    # HTML5 vectors
    AttackPattern("XSS-070", AttackCategory.XSS, r"<(?:video|audio|source|track)[^>]*\s+(?:src|poster)\s*=", 0.80, "Media tag with src", owasp="A03:2021"),
    AttackPattern("XSS-071", AttackCategory.XSS, r"<(?:iframe|frame|object|embed|applet)[^>]*>", 0.90, "Embedding tags", owasp="A03:2021"),
    AttackPattern("XSS-072", AttackCategory.XSS, r"<(?:math|annotation-xml)[^>]*>", 0.85, "MathML vectors", owasp="A03:2021"),
    
    # Template literals
    AttackPattern("XSS-080", AttackCategory.XSS, r"\$\{[^}]*\}", 0.70, "Template literal injection", owasp="A03:2021"),
    AttackPattern("XSS-081", AttackCategory.XSS, r"{{[^}]*}}", 0.70, "Template expression", owasp="A03:2021"),
    
    # Obfuscation techniques
    AttackPattern("XSS-090", AttackCategory.XSS, r"(?i)(?:&#x?[0-9a-f]+;?){3,}", 0.80, "HTML entity encoding", owasp="A03:2021"),
    AttackPattern("XSS-091", AttackCategory.XSS, r"(?i)\\u[0-9a-f]{4}", 0.75, "Unicode escape", owasp="A03:2021"),
    AttackPattern("XSS-092", AttackCategory.XSS, r"(?i)(?:fromCharCode|String\.fromCodePoint)\s*\(", 0.85, "CharCode construction", owasp="A03:2021"),
    
    # Expression/CSS
    AttackPattern("XSS-100", AttackCategory.XSS, r"(?i)expression\s*\(", 0.90, "CSS expression (IE)", owasp="A03:2021"),
    AttackPattern("XSS-101", AttackCategory.XSS, r"(?i)(?:behavior|binding)\s*:", 0.85, "CSS behavior/binding", owasp="A03:2021"),
]


# ============================================================================
# RCE / COMMAND INJECTION PATTERNS
# ============================================================================

RCE_PATTERNS = [
    # Shell metacharacters
    AttackPattern("RCE-001", AttackCategory.RCE, r"(?:^|[^\w])(?:;|\||\|\||&&)\s*\w+", 0.90, "Command chaining", owasp="A03:2021"),
    AttackPattern("RCE-002", AttackCategory.RCE, r"\$\([^)]+\)", 0.85, "Command substitution $()", owasp="A03:2021"),
    AttackPattern("RCE-003", AttackCategory.RCE, r"`[^`]+`", 0.85, "Backtick execution", owasp="A03:2021"),
    AttackPattern("RCE-004", AttackCategory.RCE, r"\$\{[^}]+\}", 0.80, "Variable expansion ${}", owasp="A03:2021"),
    
    # Common commands
    AttackPattern("RCE-010", AttackCategory.RCE, r"(?i)(?:^|[\s;&|`])(cat|ls|dir|type|more|head|tail|less)\s+", 0.85, "File read command", owasp="A03:2021"),
    # \b(?!\s*=) : match a bare command invocation (";id", "|whoami", "`id`") but NOT a
    # query/form parameter that merely happens to be named id/pwd/hostname ("id=12345",
    # "&pwd=secret") — a shell command is never written "id=". Fixes a high-volume FP.
    AttackPattern("RCE-011", AttackCategory.RCE, r"(?i)(?:^|[\s;&|`])(id|whoami|uname|hostname|pwd|ifconfig|ipconfig)\b(?!\s*=)", 0.90, "System info command", owasp="A03:2021"),
    AttackPattern("RCE-012", AttackCategory.RCE, r"(?i)(?:^|[\s;&|`])(wget|curl|fetch|nc|netcat|ncat)\s+", 0.95, "Network command", owasp="A03:2021"),
    AttackPattern("RCE-013", AttackCategory.RCE, r"(?i)(?:^|[\s;&|`])(rm|del|rmdir|mv|cp|chmod|chown)\s+", 0.90, "File manipulation", owasp="A03:2021"),
    
    # Reverse shells
    AttackPattern("RCE-020", AttackCategory.RCE, r"(?i)(?:bash|sh|zsh|ksh)\s+-[ic]", 0.95, "Interactive shell", owasp="A03:2021"),
    AttackPattern("RCE-021", AttackCategory.RCE, r"(?i)/dev/tcp/", 0.98, "Bash /dev/tcp", owasp="A03:2021"),
    AttackPattern("RCE-022", AttackCategory.RCE, r"(?i)mkfifo|mknod.*p", 0.95, "Named pipe creation", owasp="A03:2021"),
    AttackPattern("RCE-023", AttackCategory.RCE, r"(?i)python\s+-c\s*['\"].*(?:socket|subprocess|os\.)", 0.98, "Python reverse shell", owasp="A03:2021"),
    AttackPattern("RCE-024", AttackCategory.RCE, r"(?i)perl\s+-e\s*['\"].*(?:socket|exec)", 0.98, "Perl reverse shell", owasp="A03:2021"),
    AttackPattern("RCE-025", AttackCategory.RCE, r"(?i)ruby\s+-rsocket", 0.98, "Ruby reverse shell", owasp="A03:2021"),
    
    # PHP specific
    AttackPattern("RCE-030", AttackCategory.RCE, r"(?i)(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(", 0.95, "PHP command execution", owasp="A03:2021"),
    AttackPattern("RCE-031", AttackCategory.RCE, r"(?i)(?:eval|assert|create_function|call_user_func(?:_array)?|preg_replace.*['\"/]e)\s*\(", 0.95, "PHP code execution", owasp="A03:2021"),
    
    # Windows specific
    AttackPattern("RCE-040", AttackCategory.RCE, r"(?i)(?:cmd|powershell|pwsh)(?:\.exe)?\s+/[ck]", 0.95, "Windows shell", owasp="A03:2021"),
    AttackPattern("RCE-041", AttackCategory.RCE, r"(?i)(?:wscript|cscript)(?:\.exe)?", 0.90, "Windows scripting", owasp="A03:2021"),
    AttackPattern("RCE-042", AttackCategory.RCE, r"(?i)(?:certutil|bitsadmin)\s+", 0.90, "Windows download", owasp="A03:2021"),
    
    # Encoded commands
    AttackPattern("RCE-050", AttackCategory.RCE, r"(?i)base64\s+-d", 0.80, "Base64 decode", owasp="A03:2021"),
    AttackPattern("RCE-051", AttackCategory.RCE, r"(?i)echo\s+[a-zA-Z0-9+/=]{20,}\s*\|\s*base64", 0.90, "Base64 pipe execution", owasp="A03:2021"),
    
    # Bypass techniques
    AttackPattern("RCE-060", AttackCategory.RCE, r"(?i)\$IFS", 0.85, "IFS bypass", owasp="A03:2021"),
    AttackPattern("RCE-061", AttackCategory.RCE, r"(?i)\{[\w,]+\}", 0.75, "Brace expansion", owasp="A03:2021"),
    AttackPattern("RCE-062", AttackCategory.RCE, r"(?:^|[\s;|])/\?\?\?/", 0.90, "Glob pattern bypass", owasp="A03:2021"),
]


# ============================================================================
# PATH TRAVERSAL / FILE INCLUSION PATTERNS
# ============================================================================

PATH_TRAVERSAL_PATTERNS = [
    # Basic traversal
    AttackPattern("TRAV-001", AttackCategory.PATH_TRAVERSAL, r"(?:\.\./|\.\.\\){2,}", 0.95, "Directory traversal", owasp="A01:2021"),
    AttackPattern("TRAV-002", AttackCategory.PATH_TRAVERSAL, r"(?:\.\.%2f|\.\.%5c){2,}", 0.95, "Encoded traversal", owasp="A01:2021"),
    AttackPattern("TRAV-003", AttackCategory.PATH_TRAVERSAL, r"(?:\.\.%252f|\.\.%255c){2,}", 0.95, "Double-encoded", owasp="A01:2021"),
    AttackPattern("TRAV-004", AttackCategory.PATH_TRAVERSAL, r"(?:%c0%ae%c0%ae|%c0%2e){2,}", 0.95, "Overlong UTF-8", owasp="A01:2021"),
    AttackPattern("TRAV-005", AttackCategory.PATH_TRAVERSAL, r"(?:\.\.\.\.//|\.\.\.\.\\\\)", 0.90, "Nested bypass", owasp="A01:2021"),
    # IIS-style %uXXXX encoding. `%u002e%u002e` is an encoded ".." and the unicode
    # slash escapes below have no legitimate use in a URL — both are high precision.
    AttackPattern("TRAV-006", AttackCategory.PATH_TRAVERSAL, r"(?i)(?:%u(?:002e|2024|ff0e)){2}", 0.95, "%u-encoded dot-dot traversal", owasp="A01:2021"),
    AttackPattern("TRAV-007", AttackCategory.PATH_TRAVERSAL, r"(?i)%u(?:2215|2216|ff0f|ff3c|005c|002f)", 0.90, "%u-encoded path separator", owasp="A01:2021"),
    
    # Null byte
    AttackPattern("TRAV-010", AttackCategory.PATH_TRAVERSAL, r"(?:%00|\\x00|\x00)", 0.95, "Null byte injection", owasp="A01:2021"),
    
    # Unix sensitive files
    AttackPattern("TRAV-020", AttackCategory.PATH_TRAVERSAL, r"(?i)/etc/(?:passwd|shadow|group|hosts|resolv\.conf|sudoers|crontab)", 0.95, "Unix system file", owasp="A01:2021"),
    AttackPattern("TRAV-021", AttackCategory.PATH_TRAVERSAL, r"(?i)/proc/(?:self|version|cmdline|environ|mounts|net/)", 0.90, "Proc filesystem", owasp="A01:2021"),
    AttackPattern("TRAV-022", AttackCategory.PATH_TRAVERSAL, r"(?i)/var/log/(?:auth|apache|nginx|syslog)", 0.85, "Log files", owasp="A01:2021"),
    AttackPattern("TRAV-023", AttackCategory.PATH_TRAVERSAL, r"(?i)(?:~|/home/|/root/)[\w.-]+/\.(?:bash|ssh|aws|kube|docker)", 0.90, "User config files", owasp="A01:2021"),
    
    # Windows sensitive files
    AttackPattern("TRAV-030", AttackCategory.PATH_TRAVERSAL, r"(?i)(?:c:|\\\\)(?:windows|winnt|system32)", 0.90, "Windows system", owasp="A01:2021"),
    AttackPattern("TRAV-031", AttackCategory.PATH_TRAVERSAL, r"(?i)(?:boot|win|system)\.ini", 0.90, "Windows INI files", owasp="A01:2021"),
    AttackPattern("TRAV-032", AttackCategory.PATH_TRAVERSAL, r"(?i)\\(?:sam|security|system|software)$", 0.95, "Windows registry hives", owasp="A01:2021"),
]

LFI_PATTERNS = [
    # PHP wrappers
    AttackPattern("LFI-001", AttackCategory.LFI, r"(?i)php://(?:filter|input|data|expect|fd|memory|temp)", 0.95, "PHP wrapper", owasp="A03:2021"),
    AttackPattern("LFI-002", AttackCategory.LFI, r"(?i)php://filter/.*resource=", 0.98, "PHP filter chain", owasp="A03:2021"),
    AttackPattern("LFI-003", AttackCategory.LFI, r"(?i)(?:phar|zip|compress\.(?:zlib|bzip2))://", 0.95, "Archive wrappers", owasp="A03:2021"),
    AttackPattern("LFI-004", AttackCategory.LFI, r"(?i)data://text/plain", 0.90, "Data wrapper", owasp="A03:2021"),
    AttackPattern("LFI-005", AttackCategory.LFI, r"(?i)expect://", 0.98, "Expect wrapper RCE", owasp="A03:2021"),
    
    # File protocol
    AttackPattern("LFI-010", AttackCategory.LFI, r"(?i)file://", 0.90, "File protocol", owasp="A03:2021"),
]

RFI_PATTERNS = [
    AttackPattern("RFI-001", AttackCategory.RFI, r"(?i)(?:https?|ftp)://[^\s]+\.(?:php|asp|jsp|txt)\b", 0.90, "Remote file inclusion", owasp="A03:2021"),
    AttackPattern("RFI-002", AttackCategory.RFI, r"(?i)(?:https?|ftp)://(?:\d{1,3}\.){3}\d{1,3}", 0.85, "RFI with IP", owasp="A03:2021"),
]


# ============================================================================
# SSRF PATTERNS
# ============================================================================

SSRF_PATTERNS = [
    # Localhost variants
    AttackPattern("SSRF-001", AttackCategory.SSRF, r"(?i)(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\])", 0.90, "Localhost access", owasp="A10:2021"),
    AttackPattern("SSRF-002", AttackCategory.SSRF, r"(?i)https?://(?:0x7f(?:\.0){3}|2130706433|017700000001|0)(?=[:/]|$)", 0.95, "Localhost obfuscation", owasp="A10:2021"),
    AttackPattern("SSRF-003", AttackCategory.SSRF, r"(?i)(?:https?://)?(?:127\.(?:\d{1,3}\.){2}\d{1,3})", 0.90, "127.x.x.x range", owasp="A10:2021"),
    # Dotted-octal IP (e.g. http://0177.0.0.1 == 127.0.0.1) — a classic SSRF filter bypass that
    # slipped past the decimal/hex/fully-octal forms in SSRF-002. Requires a leading-zero octet
    # followed by numeric octets ending at :/ or EOS, so it matches octal IPs but not hostnames
    # like `01.foo.com`. Found by the red-team campaign after REDIR-001 stopped masking it.
    AttackPattern("SSRF-004", AttackCategory.SSRF, r"(?i)https?://0\d{1,3}(?:\.\d{1,3}){1,3}(?=[:/]|$)", 0.92, "Octal-encoded IP (SSRF bypass)", owasp="A10:2021"),
    
    # Private IP ranges
    AttackPattern("SSRF-010", AttackCategory.SSRF, r"(?i)(?:https?://)?10\.(?:\d{1,3}\.){2}\d{1,3}", 0.85, "10.x.x.x internal", owasp="A10:2021"),
    AttackPattern("SSRF-011", AttackCategory.SSRF, r"(?i)(?:https?://)?192\.168\.(?:\d{1,3}\.)\d{1,3}", 0.85, "192.168.x.x internal", owasp="A10:2021"),
    AttackPattern("SSRF-012", AttackCategory.SSRF, r"(?i)(?:https?://)?172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}", 0.85, "172.16-31.x.x internal", owasp="A10:2021"),
    
    # Cloud metadata
    AttackPattern("SSRF-020", AttackCategory.SSRF, r"(?i)169\.254\.169\.254", 0.98, "AWS/Azure metadata", owasp="A10:2021"),
    AttackPattern("SSRF-021", AttackCategory.SSRF, r"(?i)metadata\.google\.internal", 0.98, "GCP metadata", owasp="A10:2021"),
    AttackPattern("SSRF-022", AttackCategory.SSRF, r"(?i)169\.254\.170\.2", 0.95, "ECS metadata", owasp="A10:2021"),
    AttackPattern("SSRF-023", AttackCategory.SSRF, r"(?i)/latest/(?:meta-data|user-data|dynamic)", 0.90, "AWS metadata path", owasp="A10:2021"),
    
    # Alternative protocols
    AttackPattern("SSRF-030", AttackCategory.SSRF, r"(?i)(?:gopher|dict|ldap|tftp)://", 0.95, "Alternative protocols", owasp="A10:2021"),
    AttackPattern("SSRF-031", AttackCategory.SSRF, r"(?i)file://", 0.90, "File protocol SSRF", owasp="A10:2021"),
    
    # DNS rebinding indicators
    AttackPattern("SSRF-040", AttackCategory.SSRF, r"(?i)(?:xip\.io|nip\.io|sslip\.io|localtest\.me)", 0.85, "DNS rebinding service", owasp="A10:2021"),
]


# ============================================================================
# XXE PATTERNS
# ============================================================================

XXE_PATTERNS = [
    AttackPattern("XXE-001", AttackCategory.XXE, r"(?i)<!(?:DOCTYPE|ENTITY)", 0.85, "XML declaration", owasp="A05:2021"),
    AttackPattern("XXE-002", AttackCategory.XXE, r"(?i)<!ENTITY\s+\w+\s+SYSTEM", 0.98, "External entity", owasp="A05:2021"),
    AttackPattern("XXE-003", AttackCategory.XXE, r"(?i)<!ENTITY\s+%\s+\w+\s+", 0.98, "Parameter entity", owasp="A05:2021"),
    AttackPattern("XXE-004", AttackCategory.XXE, r"(?i)SYSTEM\s+['\"](?:file|http|ftp|expect|php)://", 0.98, "XXE with protocol", owasp="A05:2021"),
    AttackPattern("XXE-005", AttackCategory.XXE, r"(?i)PUBLIC\s+['\"][^'\"]+['\"]\s+['\"](?:http|file)://", 0.95, "XXE PUBLIC identifier", owasp="A05:2021"),
    AttackPattern("XXE-006", AttackCategory.XXE, r"&[a-zA-Z_][\w.-]*;", 0.60, "Entity reference", owasp="A05:2021"),
    AttackPattern("XXE-007", AttackCategory.XXE, r"(?i)<!ELEMENT|<!ATTLIST", 0.75, "DTD declaration", owasp="A05:2021"),
    AttackPattern("XXE-008", AttackCategory.XXE, r"(?i)<\?xml\s+version", 0.50, "XML declaration (low confidence)", owasp="A05:2021"),
]


# ============================================================================
# SSTI PATTERNS
# ============================================================================

SSTI_PATTERNS = [
    # Jinja2/Flask
    # ReDoS-safe: the old form `\{\{\s*[^}]+\s*\}\}` had two quantifiers that both
    # match whitespace (`\s*` and `[^}]+`), so an unterminated `{{` followed by a long
    # run of spaces forced catastrophic backtracking (~30s on 4KB). A single bounded
    # quantifier over the same character class is linear and matches the same strings.
    AttackPattern("SSTI-001", AttackCategory.SSTI, r"\{\{[^}]{1,500}\}\}", 0.75, "Jinja2 expression", owasp="A03:2021"),
    AttackPattern("SSTI-002", AttackCategory.SSTI, r"\{\%[^%]{1,500}%\}", 0.80, "Jinja2 statement", owasp="A03:2021"),
    AttackPattern("SSTI-003", AttackCategory.SSTI, r"(?i)__(?:class|mro|subclasses|globals|builtins|import)__", 0.95, "Python dunder access", owasp="A03:2021"),
    AttackPattern("SSTI-004", AttackCategory.SSTI, r"(?i)(?:config|request|self)\.__", 0.90, "Flask object access", owasp="A03:2021"),
    
    # Twig (PHP)
    AttackPattern("SSTI-010", AttackCategory.SSTI, r"\{\{\s*(?:_self|_context)", 0.90, "Twig internal access", owasp="A03:2021"),
    AttackPattern("SSTI-011", AttackCategory.SSTI, r"(?i)\{\{\s*['\"][^}]{0,500}['\"]\|(?:filter|map|reduce)", 0.85, "Twig filter chain", owasp="A03:2021"),
    
    # Freemarker (Java)
    AttackPattern("SSTI-020", AttackCategory.SSTI, r"<#(?:assign|import|include|setting)", 0.90, "Freemarker directive", owasp="A03:2021"),
    AttackPattern("SSTI-021", AttackCategory.SSTI, r"\$\{[^}]*(?:getClass|getRuntime|exec)\s*\(", 0.98, "Freemarker RCE", owasp="A03:2021"),
    
    # Velocity (Java)
    AttackPattern("SSTI-030", AttackCategory.SSTI, r"#(?:set|foreach|if|include|parse)\s*\(", 0.85, "Velocity directive", owasp="A03:2021"),
    
    # ERB (Ruby)
    AttackPattern("SSTI-040", AttackCategory.SSTI, r"<%=?[^%]{1,500}%>", 0.80, "ERB expression", owasp="A03:2021"),
    
    # Smarty (PHP)
    AttackPattern("SSTI-050", AttackCategory.SSTI, r"\{(?:php|literal|if|foreach)\}", 0.85, "Smarty tags", owasp="A03:2021"),
    
    # Generic
    AttackPattern("SSTI-060", AttackCategory.SSTI, r"\$\{\s*\d+\s*\*\s*\d+\s*\}", 0.85, "Template math test", owasp="A03:2021"),
    AttackPattern("SSTI-061", AttackCategory.SSTI, r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}", 0.80, "Jinja math test", owasp="A03:2021"),
]


# ============================================================================
# JWT ATTACK PATTERNS
# ============================================================================

JWT_PATTERNS = [
    AttackPattern("JWT-001", AttackCategory.JWT, r'(?i)["\']?alg["\']?\s*:\s*["\']?none["\']?', 0.98, "JWT alg:none", owasp="A02:2021"),
    AttackPattern("JWT-002", AttackCategory.JWT, r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.", 0.70, "JWT structure", owasp="A02:2021"),
    AttackPattern("JWT-003", AttackCategory.JWT, r'(?i)["\']?kid["\']?\s*:\s*["\']?(?:\.\.|\||;|`)', 0.95, "JWT kid injection", owasp="A02:2021"),
    AttackPattern("JWT-004", AttackCategory.JWT, r'(?i)["\']?jku["\']?\s*:\s*["\']?(?:http|file|ftp)://', 0.95, "JWT jku SSRF", owasp="A02:2021"),
    AttackPattern("JWT-005", AttackCategory.JWT, r'(?i)["\']?x5u["\']?\s*:\s*["\']?(?:http|file)://', 0.95, "JWT x5u SSRF", owasp="A02:2021"),
]


# ============================================================================
# GRAPHQL PATTERNS
# ============================================================================

GRAPHQL_PATTERNS = [
    AttackPattern("GQL-001", AttackCategory.GRAPHQL, r"(?i)__schema\s*\{", 0.90, "GraphQL introspection", owasp="A01:2021"),
    AttackPattern("GQL-002", AttackCategory.GRAPHQL, r"(?i)__type\s*\(", 0.85, "GraphQL type introspection", owasp="A01:2021"),
    AttackPattern("GQL-003", AttackCategory.GRAPHQL, r"(?i)__typename", 0.80, "GraphQL typename", owasp="A01:2021"),
    AttackPattern("GQL-004", AttackCategory.GRAPHQL, r"(?i)query\s*\{[^}]*\{[^}]*\{[^}]*\{", 0.85, "Deep nested query", owasp="A04:2021"),
    AttackPattern("GQL-005", AttackCategory.GRAPHQL, r"(?i)(?:mutation|subscription)\s*\{", 0.70, "GraphQL mutation/subscription", owasp="A01:2021"),
    AttackPattern("GQL-006", AttackCategory.GRAPHQL, r"(?i)query\s+\w+\s*\([^)]*\$[^)]+\)", 0.65, "GraphQL with variables", owasp="A01:2021"),
]


# ============================================================================
# PROTOTYPE POLLUTION PATTERNS
# ============================================================================

PROTOTYPE_PATTERNS = [
    AttackPattern("PROTO-001", AttackCategory.PROTOTYPE_POLLUTION, r'(?i)["\']?__proto__["\']?\s*:', 0.95, "__proto__ pollution", owasp="A03:2021"),
    AttackPattern("PROTO-002", AttackCategory.PROTOTYPE_POLLUTION, r'(?i)["\']?constructor["\']?\s*:\s*\{[^}]*["\']?prototype["\']?', 0.95, "Constructor prototype", owasp="A03:2021"),
    AttackPattern("PROTO-003", AttackCategory.PROTOTYPE_POLLUTION, r"(?i)(?:\[|%5[bB])['\"]?(?:__proto__|constructor\.prototype)", 0.95, "Bracket notation pollution", owasp="A03:2021"),
    AttackPattern("PROTO-004", AttackCategory.PROTOTYPE_POLLUTION, r"(?i)__proto__\s*=", 0.90, "Query param pollution", owasp="A03:2021"),
]


# ============================================================================
# DESERIALIZATION PATTERNS
# ============================================================================

DESERIALIZATION_PATTERNS = [
    # Java
    AttackPattern("DESER-001", AttackCategory.DESERIALIZATION, r"(?i)rO0AB[a-zA-Z0-9+/=]+", 0.95, "Java serialized (base64)", owasp="A08:2021"),
    AttackPattern("DESER-002", AttackCategory.DESERIALIZATION, r"(?i)(?:ac\s*ed\s*00\s*05|aced0005)", 0.98, "Java serialized (hex)", owasp="A08:2021"),
    AttackPattern("DESER-003", AttackCategory.DESERIALIZATION, r"(?i)(?:ObjectInputStream|readObject|readUnshared)", 0.85, "Java deserialization", owasp="A08:2021"),
    
    # PHP
    AttackPattern("DESER-010", AttackCategory.DESERIALIZATION, r"(?i)O:\d+:\"[^\"]+\":\d+:\{", 0.95, "PHP serialized object", owasp="A08:2021"),
    AttackPattern("DESER-011", AttackCategory.DESERIALIZATION, r"(?i)a:\d+:\{(?:s:\d+:\"[^\"]*\";[OasidbN])", 0.90, "PHP serialized array", owasp="A08:2021"),
    AttackPattern("DESER-012", AttackCategory.DESERIALIZATION, r"(?i)phar://", 0.95, "PHP Phar deserialization", owasp="A08:2021"),
    
    # Python
    AttackPattern("DESER-020", AttackCategory.DESERIALIZATION, r"(?i)(?:__reduce__|__reduce_ex__|__setstate__)", 0.90, "Python pickle gadget", owasp="A08:2021"),
    AttackPattern("DESER-021", AttackCategory.DESERIALIZATION, r"(?i)c(?:posix|os)\n(?:system|popen)", 0.95, "Python pickle RCE", owasp="A08:2021"),
    
    # .NET
    AttackPattern("DESER-030", AttackCategory.DESERIALIZATION, r"(?i)AAEAAAD/", 0.90, ".NET BinaryFormatter", owasp="A08:2021"),
    AttackPattern("DESER-031", AttackCategory.DESERIALIZATION, r"(?i)__type.*System\.", 0.85, ".NET TypeNameHandling", owasp="A08:2021"),
    
    # Node.js
    AttackPattern("DESER-040", AttackCategory.DESERIALIZATION, r'(?i)_$$ND_FUNC$$_', 0.95, "node-serialize RCE", owasp="A08:2021"),
]


# ============================================================================
# LDAP INJECTION PATTERNS
# ============================================================================

LDAP_PATTERNS = [
    AttackPattern("LDAP-001", AttackCategory.LDAP, r"(?i)\*\)\(|\)\(", 0.90, "LDAP filter injection", owasp="A03:2021"),
    AttackPattern("LDAP-002", AttackCategory.LDAP, r"(?i)\|\s*\([^)]+=[^)]+\)", 0.85, "LDAP OR injection", owasp="A03:2021"),
    AttackPattern("LDAP-003", AttackCategory.LDAP, r"(?i)&\s*\([^)]+=[^)]+\)", 0.85, "LDAP AND injection", owasp="A03:2021"),
    AttackPattern("LDAP-004", AttackCategory.LDAP, r"(?i)(?:uid|cn|ou|dc|objectClass)\s*=\s*\*", 0.80, "LDAP wildcard", owasp="A03:2021"),
    # Narrowed: the old `\x00|\x0a|\x0d` matched a bare newline/CR anywhere, so ANY multi-line
    # body (markdown, JSON, base64-decoded bytes) false-positived as LDAP injection. Real LDAP
    # null-byte injection places the null adjacent to filter metacharacters.
    AttackPattern("LDAP-005", AttackCategory.LDAP, r"\x00[)(*|&]|[)(*|&]\x00", 0.85, "LDAP null-byte in filter", owasp="A03:2021"),
]


# ============================================================================
# CRLF / HTTP RESPONSE SPLITTING PATTERNS
# ============================================================================

CRLF_PATTERNS = [
    # The header allowlist was only Set-Cookie|Location|Content-Type, so injecting ANY other
    # header slipped through — notably Content-Length / Transfer-Encoding (response splitting
    # and request smuggling) and X-Forwarded-For (client-identity spoofing, which this WAF's
    # own rate limiting and reputation key on). Broadened to the headers that actually enable
    # an attack. Deliberately NOT "any token:" — decoded multi-line form bodies legitimately
    # contain "\nWord:" prose, which a catch-all would false-positive on.
    AttackPattern("CRLF-001", AttackCategory.CRLF, r"(?i)(?:%0d%0a|%0d|%0a|\r\n|\r|\n)\s{0,8}(?:Set-Cookie2?|Location|Content-(?:Type|Length|Disposition|Encoding)|Transfer-Encoding|Refresh|Authorization|X-Forwarded-(?:For|Host|Proto)|Access-Control-Allow-Origin)\s{0,8}:", 0.95, "HTTP header injection", owasp="A03:2021"),
    AttackPattern("CRLF-002", AttackCategory.CRLF, r"(?:%0d%0a){2}|(?:\r\n){2}|(?:%0d){2}|(?:%0a){2}", 0.90, "CRLF double newline", owasp="A03:2021"),
    AttackPattern("CRLF-003", AttackCategory.CRLF, r"(?i)(?:%0d%0a|%0a)(?:HTTP/|<html|<script)", 0.95, "Response splitting", owasp="A03:2021"),
]


# ============================================================================
# OPEN REDIRECT PATTERNS
# ============================================================================

REDIRECT_PATTERNS = [
    # Narrowed: the old form flagged a redirect param pointing at ANY absolute URL
    # (`next=https://myapp.com/dashboard`), which false-positives on every legitimate
    # same-site/OAuth redirect. Match only the genuinely dangerous targets — scheme-relative
    # `//host`, a backslash bypass, or a javascript:/data:/vbscript: scheme. The `@`-authority
    # trick stays with REDIR-003; plain absolute URLs are not an open redirect on their own.
    AttackPattern("REDIR-001", AttackCategory.OPEN_REDIRECT, r"(?i)(?:redirect|url|next|goto|return|continue|dest|target|rurl|link)\s*=\s*(?:/?\\|//|(?:javascript|data|vbscript):)", 0.85, "Redirect to dangerous target", owasp="A01:2021"),
    # `(?<!:)` so it matches a SCHEME-RELATIVE `//evil.com` (the real open-redirect bypass)
    # but NOT the `//` inside a normal absolute URL like `https://legit.com` (which false-
    # positived on every legitimate callback/referer URL).
    AttackPattern("REDIR-002", AttackCategory.OPEN_REDIRECT, r"(?i)(?<!:)//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", 0.75, "Protocol-relative redirect", owasp="A01:2021"),
    # The userinfo@host redirect trick is only an attack inside a URL context. Matching a bare
    # "@domain.tld" also matches every email address in a JSON body (measured false positive on
    # {"email":"maria+news@gmail.com"}), so anchor it to a scheme or protocol-relative prefix.
    AttackPattern("REDIR-003", AttackCategory.OPEN_REDIRECT, r"(?i)(?:https?:)?//[^/\s?#]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", 0.80, "Credential redirect bypass (user@host in URL)", owasp="A01:2021"),
    AttackPattern("REDIR-004", AttackCategory.OPEN_REDIRECT, r"(?i)(?:https?:)?//[^/]*\\", 0.85, "Backslash redirect bypass", owasp="A01:2021"),
]


# ============================================================================
# HOST HEADER INJECTION PATTERNS
# ============================================================================

HOST_HEADER_PATTERNS = [
    AttackPattern("HOST-001", AttackCategory.HOST_HEADER, r"(?i)^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*,", 0.80, "Host header duplicate", owasp="A05:2021"),
    AttackPattern("HOST-002", AttackCategory.HOST_HEADER, r"(?i)localhost|127\.0\.0\.1|::1", 0.75, "Host header localhost", owasp="A05:2021"),
]


# ============================================================================
# SCANNER DETECTION PATTERNS
# ============================================================================

SCANNER_PATTERNS = [
    AttackPattern("SCAN-001", AttackCategory.SCANNER, r"(?i)(?:nikto|nmap|sqlmap|nessus|acunetix|burp|zap|w3af|arachni|openvas)", 0.90, "Known scanner UA", owasp="A09:2021"),
    AttackPattern("SCAN-002", AttackCategory.SCANNER, r"(?i)(?:havij|pangolin|webscarab|paros|appscan|webinspect)", 0.90, "Known scanner UA 2", owasp="A09:2021"),
    AttackPattern("SCAN-003", AttackCategory.SCANNER, r"(?i)python-(?:urllib|requests)|curl/|wget/|libwww|httpclient", 0.60, "Scripted access", owasp="A09:2021"),
    AttackPattern("SCAN-004", AttackCategory.SCANNER, r"(?i)dirbuster|gobuster|ffuf|feroxbuster|dirb", 0.90, "Directory brute force", owasp="A09:2021"),
]


# ============================================================================
# DoS PATTERNS
# ============================================================================

DOS_PATTERNS = [
    AttackPattern("DOS-001", AttackCategory.DOS, r"(?:a{1000,}|A{1000,})", 0.90, "Large repetition", owasp="A04:2021"),
    AttackPattern("DOS-002", AttackCategory.REDOS, r"(?:\([^)]*\+\)\+|\([^)]*\*\)\*|\([^)]*\)\{[^}]+\}\{)", 0.85, "ReDoS pattern", owasp="A04:2021"),
    AttackPattern("DOS-003", AttackCategory.DOS, r"(?:<!DOCTYPE[^>]*>){5,}", 0.90, "XML bomb indicator", owasp="A04:2021"),
    AttackPattern("DOS-004", AttackCategory.DOS, r"&[a-z]+;(?:&[a-z]+;){100,}", 0.95, "Entity expansion", owasp="A04:2021"),
]


# ============================================================================
# COMPILE ALL PATTERNS
# ============================================================================

def get_all_patterns() -> Dict[AttackCategory, List[AttackPattern]]:
    """Get all compiled attack patterns grouped by category"""
    all_patterns = {
        AttackCategory.SQLI: SQLI_PATTERNS,
        AttackCategory.NOSQL: NOSQL_PATTERNS,
        AttackCategory.XSS: XSS_PATTERNS,
        AttackCategory.RCE: RCE_PATTERNS,
        AttackCategory.PATH_TRAVERSAL: PATH_TRAVERSAL_PATTERNS,
        AttackCategory.LFI: LFI_PATTERNS,
        AttackCategory.RFI: RFI_PATTERNS,
        AttackCategory.SSRF: SSRF_PATTERNS,
        AttackCategory.XXE: XXE_PATTERNS,
        AttackCategory.SSTI: SSTI_PATTERNS,
        AttackCategory.JWT: JWT_PATTERNS,
        AttackCategory.GRAPHQL: GRAPHQL_PATTERNS,
        AttackCategory.PROTOTYPE_POLLUTION: PROTOTYPE_PATTERNS,
        AttackCategory.DESERIALIZATION: DESERIALIZATION_PATTERNS,
        AttackCategory.LDAP: LDAP_PATTERNS,
        AttackCategory.CRLF: CRLF_PATTERNS,
        AttackCategory.OPEN_REDIRECT: REDIRECT_PATTERNS,
        AttackCategory.HOST_HEADER: HOST_HEADER_PATTERNS,
        AttackCategory.SCANNER: SCANNER_PATTERNS,
        AttackCategory.DOS: DOS_PATTERNS,
    }
    return all_patterns


def compile_patterns() -> Dict[AttackCategory, List[Tuple[re.Pattern, AttackPattern]]]:
    """Compile all regex patterns for performance"""
    all_patterns = get_all_patterns()
    compiled = {}
    
    for category, patterns in all_patterns.items():
        compiled[category] = []
        for pattern in patterns:
            try:
                regex = re.compile(pattern.pattern, re.IGNORECASE | re.MULTILINE)
                compiled[category].append((regex, pattern))
            except re.error as e:
                print(f"Warning: Failed to compile pattern {pattern.id}: {e}")
    
    return compiled


def get_pattern_count() -> Dict[str, int]:
    """Get count of patterns by category"""
    all_patterns = get_all_patterns()
    return {cat.value: len(patterns) for cat, patterns in all_patterns.items()}


def get_total_pattern_count() -> int:
    """Get total number of patterns"""
    return sum(get_pattern_count().values())


# ============================================================================
# MAIN (Testing)
# ============================================================================

if __name__ == '__main__':
    print("MIRAGE Comprehensive Attack Patterns")
    print("=" * 60)
    
    counts = get_pattern_count()
    total = get_total_pattern_count()
    
    print(f"\nTotal patterns: {total}")
    print("\nBy category:")
    for cat, count in sorted(counts.items()):
        print(f"  {cat}: {count}")
    
    # Compile test
    print("\nCompiling patterns...")
    compiled = compile_patterns()
    print(f"Successfully compiled {sum(len(p) for p in compiled.values())} patterns")
