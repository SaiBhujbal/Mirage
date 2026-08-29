"""
MIRAGE Advanced Protection Module
Handles edge cases, novel attacks, and ML bypass scenarios
"""
import re
import json
import base64
import hashlib
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import urllib.parse
import html
from collections import defaultdict
import time
import threading

class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class AdvancedDetection:
    """Result from advanced detection"""
    threat_level: ThreatLevel
    category: str
    description: str
    confidence: float
    raw_evidence: str = ""

# ============================================================================
# MULTI-LAYER ENCODING DETECTOR
# ============================================================================

class EncodingChainDetector:
    """
    Detects multi-layer encoding bypass attempts
    Attackers use: URL -> HTML -> Base64 -> Hex chains
    """
    
    MAX_DECODE_DEPTH = 10
    
    def __init__(self):
        self.decode_functions = [
            ("url", self._url_decode),
            ("html", self._html_decode),
            ("base64", self._base64_decode),
            ("hex", self._hex_decode),
            ("unicode", self._unicode_decode),
            ("double_url", self._double_url_decode),
        ]
    
    def detect_and_decode(self, payload: str) -> Tuple[str, List[str], int]:
        """
        Recursively decode payload, return (decoded, encoding_chain, depth)
        """
        encoding_chain = []
        current = payload
        depth = 0
        
        while depth < self.MAX_DECODE_DEPTH:
            decoded = False
            
            for name, decode_fn in self.decode_functions:
                try:
                    result = decode_fn(current)
                    if result and result != current:
                        current = result
                        encoding_chain.append(name)
                        decoded = True
                        depth += 1
                        break
                except:
                    continue
            
            if not decoded:
                break
        
        return current, encoding_chain, depth
    
    def is_evasion_attempt(self, payload: str) -> Tuple[bool, AdvancedDetection]:
        """Check if payload uses encoding to evade detection"""
        decoded, chain, depth = self.detect_and_decode(payload)
        
        # Multiple encoding layers is suspicious
        if depth >= 2:
            return True, AdvancedDetection(
                threat_level=ThreatLevel.HIGH,
                category="ENCODING_EVASION",
                description=f"Multi-layer encoding detected: {' -> '.join(chain)}",
                confidence=min(0.5 + depth * 0.15, 0.95),
                raw_evidence=f"Original: {payload[:100]}, Decoded: {decoded[:100]}"
            )
        
        # Check if decoded version is more suspicious
        if decoded != payload:
            # Look for attack patterns in decoded
            attack_patterns = [
                r"<script", r"javascript:", r"onerror", r"onload",
                r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'",
                r";\s*(?:ls|cat|whoami|id)", r"\.\./\.\./",
            ]
            
            for pattern in attack_patterns:
                if re.search(pattern, decoded, re.IGNORECASE):
                    return True, AdvancedDetection(
                        threat_level=ThreatLevel.HIGH,
                        category="ENCODED_ATTACK",
                        description=f"Attack payload hidden in {chain[0] if chain else 'encoding'}",
                        confidence=0.9,
                        raw_evidence=decoded[:200]
                    )
        
        return False, None
    
    def _url_decode(self, s: str) -> str:
        if '%' in s:
            return urllib.parse.unquote(s)
        return s
    
    def _double_url_decode(self, s: str) -> str:
        if '%25' in s:
            return urllib.parse.unquote(urllib.parse.unquote(s))
        return s
    
    def _html_decode(self, s: str) -> str:
        if '&' in s and ';' in s:
            return html.unescape(s)
        return s
    
    def _base64_decode(self, s: str) -> str:
        # Check if it looks like base64
        if re.match(r'^[A-Za-z0-9+/]+=*$', s) and len(s) >= 4:
            try:
                decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
                if decoded.isprintable() or any(c in decoded for c in '<>"\''):
                    return decoded
            except:
                pass
        return s
    
    def _hex_decode(self, s: str) -> str:
        # Match \xNN or 0xNN patterns
        if '\\x' in s or '0x' in s:
            def replace_hex(m):
                try:
                    return chr(int(m.group(1), 16))
                except:
                    return m.group(0)
            
            result = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, s)
            result = re.sub(r'0x([0-9a-fA-F]{2})', replace_hex, result)
            return result
        return s
    
    def _unicode_decode(self, s: str) -> str:
        # Handle \uNNNN and %uNNNN
        if '\\u' in s or '%u' in s:
            def replace_unicode(m):
                try:
                    return chr(int(m.group(1), 16))
                except:
                    return m.group(0)
            
            result = re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, s)
            result = re.sub(r'%u([0-9a-fA-F]{4})', replace_unicode, result)
            return result
        return s


# ============================================================================
# XXE (XML External Entity) DETECTOR
# ============================================================================

class XXEDetector:
    """Detects XML External Entity attacks"""
    
    XXE_PATTERNS = [
        # DOCTYPE with ENTITY
        r'<!DOCTYPE[^>]*\[.*<!ENTITY',
        r'<!ENTITY\s+\w+\s+SYSTEM',
        r'<!ENTITY\s+\w+\s+PUBLIC',
        
        # External entity references
        r'file:///etc/passwd',
        r'file:///c:/windows',
        r'http://[^/]*@',  # URL with credentials
        r'expect://id',
        r'php://filter',
        
        # Parameter entities
        r'<!ENTITY\s+%\s+\w+',
        r'%\w+;',  # Parameter entity reference in DOCTYPE
        
        # Billion laughs / entity expansion
        r'<!ENTITY\s+\w+\s+"&\w+;&\w+;',
    ]
    
    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.XXE_PATTERNS]
    
    def detect(self, content: str) -> Tuple[bool, Optional[AdvancedDetection]]:
        """Detect XXE attacks in content"""
        
        # Quick check - must have XML-like content
        if '<!DOCTYPE' not in content.upper() and '<!ENTITY' not in content.upper():
            # Check for entity references without DOCTYPE (blind XXE)
            if '&xxe;' in content.lower() or re.search(r'&[a-z]+;', content, re.IGNORECASE):
                pass  # Continue checking
            else:
                return False, None
        
        for pattern in self.patterns:
            match = pattern.search(content)
            if match:
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.CRITICAL,
                    category="XXE",
                    description="XML External Entity injection detected",
                    confidence=0.95,
                    raw_evidence=match.group(0)[:200]
                )
        
        # Check for entity expansion attacks (Billion Laughs)
        entity_count = content.count('<!ENTITY')
        if entity_count > 3:
            return True, AdvancedDetection(
                threat_level=ThreatLevel.CRITICAL,
                category="XXE_EXPANSION",
                description=f"Possible entity expansion attack ({entity_count} entities)",
                confidence=0.85,
                raw_evidence=content[:200]
            )
        
        return False, None


# ============================================================================
# GRAPHQL ATTACK DETECTOR
# ============================================================================

class GraphQLDetector:
    """Detects GraphQL-specific attacks"""
    
    def __init__(self):
        self.introspection_patterns = [
            r'__schema\s*{',
            r'__type\s*\(',
            r'__typename',
            r'queryType\s*{',
            r'mutationType\s*{',
        ]
        
        self.dos_indicators = [
            # Deep nesting
            (r'{\s*\w+\s*{\s*\w+\s*{\s*\w+\s*{\s*\w+\s*{', "deep_nesting"),
            # Alias bombing
            (r'(\w+\d+:\s*\w+\s*){5,}', "alias_bombing"),
            # Field duplication
            (r'(\w+\s+){10,}', "field_duplication"),
            # Circular fragments
            (r'fragment\s+\w+\s+on\s+\w+\s*{[^}]*\.\.\.\w+', "circular_fragment"),
        ]
    
    def detect(self, content: str, path: str = "") -> Tuple[bool, Optional[AdvancedDetection]]:
        """Detect GraphQL attacks"""
        
        # Check if this is a GraphQL request
        if '/graphql' not in path.lower() and 'query' not in content.lower():
            return False, None
        
        # Check for introspection (info disclosure)
        for pattern in self.introspection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.MEDIUM,
                    category="GRAPHQL_INTROSPECTION",
                    description="GraphQL schema introspection attempt",
                    confidence=0.8,
                    raw_evidence=content[:200]
                )
        
        # Check for DoS patterns
        for pattern, attack_type in self.dos_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.HIGH,
                    category="GRAPHQL_DOS",
                    description=f"GraphQL DoS attempt: {attack_type}",
                    confidence=0.85,
                    raw_evidence=content[:200]
                )
        
        # Check query depth
        depth = self._calculate_depth(content)
        if depth > 10:
            return True, AdvancedDetection(
                threat_level=ThreatLevel.HIGH,
                category="GRAPHQL_DEPTH",
                description=f"Excessive query depth: {depth}",
                confidence=0.9,
                raw_evidence=content[:200]
            )
        
        return False, None
    
    def _calculate_depth(self, query: str) -> int:
        """Calculate nesting depth of GraphQL query"""
        max_depth = 0
        current_depth = 0
        
        for char in query:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        
        return max_depth


# ============================================================================
# JWT/OAuth ATTACK DETECTOR
# ============================================================================

class JWTDetector:
    """Detects JWT and OAuth attacks"""
    
    def __init__(self):
        self.jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*')
    
    def detect(self, content: str, headers: Dict[str, str] = None) -> Tuple[bool, Optional[AdvancedDetection]]:
        """Detect JWT attacks"""
        
        headers = headers or {}
        
        # Check Authorization header
        auth_header = headers.get('authorization', '') or headers.get('Authorization', '')
        
        # Find JWT tokens
        jwt_matches = self.jwt_pattern.findall(content + ' ' + auth_header)
        
        for jwt in jwt_matches:
            detection = self._analyze_jwt(jwt)
            if detection:
                return True, detection
        
        # Check for OAuth attacks
        oauth_detection = self._check_oauth_attacks(content, headers)
        if oauth_detection:
            return True, oauth_detection
        
        return False, None
    
    def _analyze_jwt(self, token: str) -> Optional[AdvancedDetection]:
        """Analyze JWT for attacks"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            # Check for algorithm confusion attacks
            alg = header.get('alg', '').upper()
            
            if alg == 'NONE':
                return AdvancedDetection(
                    threat_level=ThreatLevel.CRITICAL,
                    category="JWT_ALG_NONE",
                    description="JWT with 'none' algorithm - authentication bypass",
                    confidence=0.98,
                    raw_evidence=token[:50] + "..."
                )
            
            if alg in ('HS256', 'HS384', 'HS512'):
                # Check if this might be algorithm confusion (using RSA public key as HMAC secret)
                # This is a heuristic - would need more context in real scenario
                pass
            
            # Check for JKU/X5U injection
            if 'jku' in header or 'x5u' in header:
                jku = header.get('jku', '') or header.get('x5u', '')
                if any(x in jku.lower() for x in ['localhost', '127.0.0.1', '169.254', 'internal']):
                    return AdvancedDetection(
                        threat_level=ThreatLevel.CRITICAL,
                        category="JWT_JKU_INJECTION",
                        description="JWT with suspicious JKU/X5U header - SSRF attempt",
                        confidence=0.95,
                        raw_evidence=f"jku/x5u: {jku}"
                    )
            
            # Check for KID injection
            kid = header.get('kid', '')
            if kid and any(c in kid for c in ['/', '..', ';', '|', '$']):
                return AdvancedDetection(
                    threat_level=ThreatLevel.HIGH,
                    category="JWT_KID_INJECTION",
                    description="JWT with suspicious KID - path traversal/injection",
                    confidence=0.9,
                    raw_evidence=f"kid: {kid}"
                )
            
        except Exception:
            pass
        
        return None
    
    def _check_oauth_attacks(self, content: str, headers: Dict) -> Optional[AdvancedDetection]:
        """Check for OAuth-specific attacks"""
        
        content_lower = content.lower()
        
        # Open redirect in redirect_uri
        if 'redirect_uri=' in content_lower:
            match = re.search(r'redirect_uri=([^&\s]+)', content, re.IGNORECASE)
            if match:
                uri = urllib.parse.unquote(match.group(1))
                # Check for open redirect patterns
                if any(x in uri for x in ['@', '//', '\\\\', 'javascript:', 'data:']):
                    return AdvancedDetection(
                        threat_level=ThreatLevel.HIGH,
                        category="OAUTH_REDIRECT",
                        description="OAuth open redirect attempt",
                        confidence=0.85,
                        raw_evidence=uri[:100]
                    )
        
        # CSRF via state parameter.
        # ADVISORY ONLY (confidence below the 0.5 enforcement threshold). A short `state` is a
        # weakness in YOUR OWN OAuth implementation, not an attack by the client sending it:
        # blocking it 403s the legitimate user mid-login for a flaw on the server side, breaking
        # every sign-in through that provider. Measured: this blocked 285/4000 legitimate OAuth
        # callbacks. It is reported so you can fix the state generation, never enforced.
        if 'state=' in content_lower:
            match = re.search(r'state=([^&\s]*)', content, re.IGNORECASE)
            if match and len(match.group(1)) < 8:
                return AdvancedDetection(
                    threat_level=ThreatLevel.LOW,
                    category="OAUTH_WEAK_STATE",
                    description="Weak OAuth state parameter - CSRF risk (advisory: fix state generation)",
                    confidence=0.45,
                    raw_evidence=match.group(0)
                )
        
        return None


# ============================================================================
# FILE UPLOAD DETECTOR
# ============================================================================

class FileUploadDetector:
    """Detects malicious file upload attempts"""
    
    # Magic bytes for dangerous file types
    DANGEROUS_MAGIC = {
        b'\x4d\x5a': 'exe',  # Windows executable
        b'\x7f\x45\x4c\x46': 'elf',  # Linux executable
        b'\xca\xfe\xba\xbe': 'java_class',  # Java class
        b'PK\x03\x04': 'zip',  # ZIP (could be jar, docx with macros, etc.)
        b'\xd0\xcf\x11\xe0': 'ole',  # OLE (doc, xls with macros)
        b'%PDF': 'pdf',  # PDF (can contain JS)
        b'<svg': 'svg',  # SVG (can contain JS)
        b'<?xml': 'xml',  # XML (XXE risk)
        b'GIF89a': 'gif',  # GIF
        b'\x89PNG': 'png',  # PNG
        b'\xff\xd8\xff': 'jpeg',  # JPEG
    }
    
    # Polyglot patterns
    POLYGLOT_PATTERNS = [
        (b'GIF89a<?php', 'PHP in GIF'),
        (b'\xff\xd8\xff<?php', 'PHP in JPEG'),
        (b'%PDF-1.<?php', 'PHP in PDF'),
        (b'<svg.*?<script', 'JS in SVG'),
    ]
    
    DANGEROUS_EXTENSIONS = {
        'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
        'asp', 'aspx', 'ashx', 'asmx',
        'jsp', 'jspx',
        'exe', 'dll', 'so', 'dylib',
        'sh', 'bash', 'bat', 'cmd', 'ps1',
        'py', 'pyc', 'pyo',
        'pl', 'pm', 'cgi',
        'jar', 'war', 'ear',
        'htaccess', 'htpasswd',
        'svg', 'xml', 'xsl', 'xslt',
    }
    
    def detect(self, filename: str, content: bytes, content_type: str = "") -> Tuple[bool, Optional[AdvancedDetection]]:
        """Detect malicious file upload"""
        
        # Check extension
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        # Double extension bypass
        if filename.count('.') >= 2:
            parts = filename.lower().split('.')
            for part in parts[:-1]:
                if part in self.DANGEROUS_EXTENSIONS:
                    return True, AdvancedDetection(
                        threat_level=ThreatLevel.HIGH,
                        category="UPLOAD_DOUBLE_EXT",
                        description=f"Double extension bypass attempt: {filename}",
                        confidence=0.9,
                        raw_evidence=filename
                    )
        
        # Null byte injection
        if '\x00' in filename or '%00' in filename:
            return True, AdvancedDetection(
                threat_level=ThreatLevel.CRITICAL,
                category="UPLOAD_NULL_BYTE",
                description="Null byte injection in filename",
                confidence=0.98,
                raw_evidence=filename[:50]
            )
        
        # Check dangerous extension
        if ext in self.DANGEROUS_EXTENSIONS:
            return True, AdvancedDetection(
                threat_level=ThreatLevel.CRITICAL,
                category="UPLOAD_DANGEROUS_EXT",
                description=f"Dangerous file extension: .{ext}",
                confidence=0.95,
                raw_evidence=filename
            )
        
        # Check magic bytes
        if content:
            for magic, ftype in self.DANGEROUS_MAGIC.items():
                if content.startswith(magic):
                    # If extension doesn't match magic, it's suspicious
                    if ftype in ('exe', 'elf', 'java_class', 'ole'):
                        return True, AdvancedDetection(
                            threat_level=ThreatLevel.CRITICAL,
                            category="UPLOAD_EXECUTABLE",
                            description=f"Executable file detected: {ftype}",
                            confidence=0.95,
                            raw_evidence=f"Magic: {magic.hex()}"
                        )
            
            # Check polyglot patterns
            for pattern, desc in self.POLYGLOT_PATTERNS:
                if isinstance(pattern, bytes):
                    if pattern in content[:1000]:
                        return True, AdvancedDetection(
                            threat_level=ThreatLevel.CRITICAL,
                            category="UPLOAD_POLYGLOT",
                            description=f"Polyglot file detected: {desc}",
                            confidence=0.95,
                            raw_evidence=content[:50].hex()
                        )
            
            # Check for PHP in image files
            if ext in ('gif', 'png', 'jpg', 'jpeg'):
                php_patterns = [b'<?php', b'<?=', b'<script language="php"']
                for pattern in php_patterns:
                    if pattern in content:
                        return True, AdvancedDetection(
                            threat_level=ThreatLevel.CRITICAL,
                            category="UPLOAD_PHP_IN_IMAGE",
                            description="PHP code embedded in image file",
                            confidence=0.98,
                            raw_evidence=f"Found: {pattern}"
                        )
        
        return False, None


# ============================================================================
# HTTP/2 ATTACK DETECTOR  
# ============================================================================

class HTTP2Detector:
    """Detects HTTP/2 specific attacks"""
    
    def detect(self, headers: Dict[str, str], pseudo_headers: Dict[str, str] = None) -> Tuple[bool, Optional[AdvancedDetection]]:
        """Detect HTTP/2 attacks"""
        
        pseudo_headers = pseudo_headers or {}
        
        # Check for HPACK bombing (large header values)
        total_header_size = sum(len(k) + len(v) for k, v in headers.items())
        if total_header_size > 16384:  # 16KB
            return True, AdvancedDetection(
                threat_level=ThreatLevel.HIGH,
                category="HTTP2_HEADER_BOMB",
                description=f"Excessive header size: {total_header_size} bytes",
                confidence=0.85,
                raw_evidence=f"Total headers: {total_header_size}B"
            )
        
        # Check for header count
        if len(headers) > 100:
            return True, AdvancedDetection(
                threat_level=ThreatLevel.HIGH,
                category="HTTP2_HEADER_FLOOD",
                description=f"Too many headers: {len(headers)}",
                confidence=0.8,
                raw_evidence=f"Header count: {len(headers)}"
            )
        
        # Check pseudo-header smuggling
        for key in headers:
            if key.startswith(':'):
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.HIGH,
                    category="HTTP2_PSEUDO_SMUGGLE",
                    description="Pseudo-header in regular headers",
                    confidence=0.9,
                    raw_evidence=key
                )
        
        return False, None


# ============================================================================
# ADVERSARIAL ML DETECTOR
# ============================================================================

class AdversarialMLDetector:
    """Detects attempts to evade ML model"""
    
    def __init__(self):
        # Patterns that attackers use to confuse ML
        self.padding_patterns = [
            # Lots of benign-looking content to dilute attack
            r'(?:lorem\s+ipsum|hello\s+world|test\s+data){3,}',
            # Repeated safe characters
            r'[a-z]{50,}',
            # Comment padding
            r'(?:/\*[^*]*\*/){3,}',
            r'(?:<!--[^>]*-->){3,}',
        ]
        
        # Track payload mutations
        self.mutation_history: Dict[str, List[str]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def detect(self, payload: str, client_ip: str, ml_score: float) -> Tuple[bool, Optional[AdvancedDetection]]:
        """Detect ML evasion attempts"""
        
        # Handle None ml_score
        if ml_score is None:
            ml_score = 0.0
        
        # Check for padding attacks
        for pattern in self.padding_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                # If there's padding AND something suspicious
                suspicious = any(c in payload for c in ['<', '>', "'", '"', ';', '|', '&'])
                if suspicious:
                    return True, AdvancedDetection(
                        threat_level=ThreatLevel.HIGH,
                        category="ML_PADDING_EVASION",
                        description="Suspected ML evasion via payload padding",
                        confidence=0.75,
                        raw_evidence=payload[:100]
                    )
        
        # Track mutations from same IP (probing behavior)
        with self.lock:
            history = self.mutation_history[client_ip]
            history.append(payload[:100])
            
            # Keep last 20 requests
            if len(history) > 20:
                history.pop(0)
            
            # Check for systematic probing
            if len(history) >= 5:
                # If payloads are similar but with small variations
                unique_chars = set()
                for h in history:
                    unique_chars.update(set(h))
                
                # High variation with suspicious characters = probing.
                # ADVISORY ONLY (confidence below the 0.5 block threshold): the chars
                # <>'";|& occur in ordinary JSON, URLs and markdown, so this per-IP signal
                # false-positives on busy or shared (NAT/CGNAT/LB-without-XFF) clients and
                # would otherwise block their benign traffic once any request from that IP
                # tripped it. Real attacks are already blocked by the signature tier; this
                # only corroborates. Surface it for monitoring, do not 403 on it alone.
                if len(unique_chars) > 50 and any(c in unique_chars for c in '<>\'";|&'):
                    return True, AdvancedDetection(
                        threat_level=ThreatLevel.LOW,
                        category="ML_PROBING",
                        description="Systematic payload mutation detected (ML probing, advisory)",
                        confidence=0.45,
                        raw_evidence=f"Variants from {client_ip}: {len(history)}"
                    )
        
        # Borderline ML scores are suspicious if payload has attack chars
        if 0.4 <= ml_score <= 0.6:
            attack_chars = sum(1 for c in payload if c in '<>\'";|&$`')
            if attack_chars >= 3:
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.MEDIUM,
                    category="ML_BORDERLINE",
                    description="Borderline ML score with suspicious characters",
                    confidence=0.65,
                    raw_evidence=f"ML score: {ml_score:.2f}, attack chars: {attack_chars}"
                )
        
        return False, None


# ============================================================================
# MASTER ADVANCED PROTECTION ENGINE
# ============================================================================


# ============================================================================
# SERVER-SIDE TEMPLATE INJECTION (SSTI) DETECTOR
# ============================================================================

class SSTIDetector:
    """Detects Server-Side Template Injection attacks"""

    def __init__(self):
        self.ssti_patterns = [
            # Jinja2 / Twig / Nunjucks
            # ReDoS-safe: the old forms `{{\s*.*?\s*}}` etc. had `\s*` overlapping the
            # inner `.*?` on whitespace under re.DOTALL, so an unterminated `{{` followed
            # by a long space run forced catastrophic backtracking (measured ~120s at 8KB
            # in advanced_protection.analyze). Bounded single-quantifier negated classes
            # match the same payloads in linear time.
            r'{{[^}]{0,1000}}}',
            r'{%[^%]{0,1000}%}',
            # Java (FreeMarker, Velocity)
            r'\$\{[^}]{0,1000}\}',
            r'#\{[^}]{0,1000}\}',
            r'#evaluate\(',
            # Spring EL
            r'T\([a-zA-Z0-9_.]+\)',
            # Smarty
            r'{php}.*?{/php}',
            # Ruby ERB
            r'<%.*?%>',
            # General payload markers
            r'\.class\.classLoader',
            r'\.getClass\(\)',
            r'java\.lang\.Runtime',
            r'java\.lang\.ProcessBuilder',
        ]
        self.patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.ssti_patterns]

    def detect(self, content: str) -> Tuple[bool, Optional[AdvancedDetection]]:
        if not content:
            return False, None

        # Check for typical math evaluation payloads
        if re.search(r'{{\s*7\s*\*\s*7\s*}}', content) or re.search(r'\${\s*7\s*\*\s*7\s*}', content):
            return True, AdvancedDetection(
                threat_level=ThreatLevel.CRITICAL,
                category="SSTI",
                description="SSTI math evaluation payload detected",
                confidence=0.98,
                raw_evidence=content[:200]
            )

        for pattern in self.patterns:
            match = pattern.search(content)
            if match:
                # Check if it looks like an actual code execution/evaluation context
                suspicious_keywords = ['runtime', 'exec', 'system', 'popen', 'eval', 'processbuilder', 'import', 'classloader']
                is_suspicious = any(kw in match.group(0).lower() for kw in suspicious_keywords)

                # We flag high confidence if suspicious keywords are found inside template tags
                if is_suspicious:
                    return True, AdvancedDetection(
                        threat_level=ThreatLevel.CRITICAL,
                        category="SSTI",
                        description="Server-Side Template Injection (SSTI) detected",
                        confidence=0.95,
                        raw_evidence=match.group(0)[:200]
                    )
                # Lower confidence for generic curly braces
                elif len(match.group(0)) > 6:
                    return True, AdvancedDetection(
                        threat_level=ThreatLevel.HIGH,
                        category="SSTI_SUSPICIOUS",
                        description="Possible Server-Side Template Injection (SSTI) syntax",
                        confidence=0.75,
                        raw_evidence=match.group(0)[:200]
                    )
        return False, None

# ============================================================================
# HTTP REQUEST SMUGGLING DETECTOR
# ============================================================================

class RequestSmugglingDetector:
    """Detects HTTP Request Smuggling attacks (CL.TE, TE.CL)"""

    def detect(self, headers: Dict[str, str], body: str) -> Tuple[bool, Optional[AdvancedDetection]]:
        headers_lower = {k.lower(): v for k, v in headers.items()}

        has_cl = 'content-length' in headers_lower
        has_te = 'transfer-encoding' in headers_lower

        # Multiple Content-Length headers
        if isinstance(headers.get('content-length'), list) or ',' in str(headers.get('content-length', '')):
             return True, AdvancedDetection(
                threat_level=ThreatLevel.CRITICAL,
                category="HTTP_SMUGGLING",
                description="Multiple Content-Length headers detected",
                confidence=0.95,
                raw_evidence=str(headers.get('content-length'))
            )

        # Both CL and TE present (CL.TE or TE.CL vulnerability)
        if has_cl and has_te:
            te_val = str(headers_lower['transfer-encoding']).lower()
            if 'chunked' in te_val:
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.CRITICAL,
                    category="HTTP_SMUGGLING_CL_TE",
                    description="Both Content-Length and Transfer-Encoding headers present",
                    confidence=0.95,
                    raw_evidence="CL and TE headers present"
                )

        # Check for obfuscated Transfer-Encoding
        for key in headers:
            # e.g., 'Transfer-Encoding ', ' Transfer-Encoding'
            if key.strip().lower() == 'transfer-encoding' and key.lower() != 'transfer-encoding':
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.CRITICAL,
                    category="HTTP_SMUGGLING_OBFUSCATED",
                    description="Obfuscated Transfer-Encoding header",
                    confidence=0.95,
                    raw_evidence=key
                )

        # Check for smuggled request in body (basic heuristic)
        if body:
            # Looking for a new HTTP request hidden in the body
            if re.search(r'^(GET|POST|PUT|DELETE|OPTIONS|HEAD|TRACE|CONNECT)\s+/[^\s]*\s+HTTP/1\.[01]', body, re.MULTILINE | re.IGNORECASE):
                 return True, AdvancedDetection(
                    threat_level=ThreatLevel.CRITICAL,
                    category="HTTP_SMUGGLING_BODY",
                    description="Smuggled HTTP request found in body",
                    confidence=0.90,
                    raw_evidence=body[:200]
                )

        return False, None

# ============================================================================
# INSECURE DESERIALIZATION DETECTOR
# ============================================================================

class DeserializationDetector:
    """Detects Java, Python, PHP, and Node.js insecure deserialization"""

    def __init__(self):
        self.patterns = [
            # Java Object Serialization (magic bytes: AC ED 00 05)
            r'\xac\xed\x00\x05',
            r'rO0AB', # Base64 of Java serialized object
            # PHP Serialization
            r'O:[0-9]+:"[a-zA-Z0-9_]+":[0-9]+:{',
            # Python Pickle (basic heuristic for opcode streams loading suspicious modules)
            r'c__builtin__\n(?:eval|exec|system|file)',
            r'cposix\nsystem',
            r'cos\nsystem',
            r'csubprocess\nPopen',
            # Node.js node-serialize
            r'_\$\$ND_FUNC\$\$_'
        ]
        self.compiled_patterns = [re.compile(p) for p in self.patterns]

    def detect(self, content: str, body_bytes: bytes = None) -> Tuple[bool, Optional[AdvancedDetection]]:
        if body_bytes and b'\xac\xed\x00\x05' in body_bytes:
             return True, AdvancedDetection(
                threat_level=ThreatLevel.CRITICAL,
                category="DESERIALIZATION_JAVA",
                description="Java serialized object detected (Magic Bytes AC ED 00 05)",
                confidence=0.95,
                raw_evidence="AC ED 00 05"
            )

        if not content:
            return False, None

        for pattern in self.compiled_patterns:
            if pattern.search(content):
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.CRITICAL,
                    category="DESERIALIZATION",
                    description="Insecure deserialization payload detected",
                    confidence=0.90,
                    raw_evidence=content[:200]
                )
        return False, None


# ============================================================================
# ADVANCED SSRF DETECTOR
# ============================================================================

class AdvancedSSRFDetector:
    """Detects SSRF bypass techniques like IP encoding, cloud metadata, etc."""

    def __init__(self):
        self.patterns = [
            # Decimal IP for 127.0.0.1
            r'2130706433',
            r'0x7f000001',
            # Decimal IP for 169.254.169.254
            r'2852039166',
            r'0xa9fea9fe',
            # Octal
            r'0177\.0\.0\.01',
            # Missing dots
            r'127\.1',
            # Cloud metadata exact paths
            r'latest/meta-data',
            r'metadata\.google\.internal',
            # Alternative schemes
            r'(dict|gopher|ldap|tftp|sftp)://'
        ]
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.patterns]

    def detect(self, content: str) -> Tuple[bool, Optional[AdvancedDetection]]:
        if not content:
            return False, None

        for pattern in self.compiled_patterns:
            if pattern.search(content):
                return True, AdvancedDetection(
                    threat_level=ThreatLevel.HIGH,
                    category="SSRF_ADVANCED",
                    description="Advanced SSRF evasion technique detected",
                    confidence=0.85,
                    raw_evidence=content[:200]
                )
        return False, None

class AdvancedProtectionEngine:
    """Orchestrates all advanced protection modules"""
    
    def __init__(self):
        self.encoding_detector = EncodingChainDetector()
        self.xxe_detector = XXEDetector()
        self.graphql_detector = GraphQLDetector()
        self.jwt_detector = JWTDetector()
        self.upload_detector = FileUploadDetector()
        self.http2_detector = HTTP2Detector()
        self.adversarial_detector = AdversarialMLDetector()
        self.ssti_detector = SSTIDetector()
        self.smuggling_detector = RequestSmugglingDetector()
        self.deserialization_detector = DeserializationDetector()
        self.advanced_ssrf_detector = AdvancedSSRFDetector()
    
    def analyze(self, 
                path: str,
                query: str,
                body: str,
                headers: Dict[str, str],
                client_ip: str,
                ml_score: float = 0.0,
                filename: str = None,
                file_content: bytes = None) -> List[AdvancedDetection]:
        """Run all advanced detections"""
        
        detections = []
        
        # Combine all text content for analysis
        full_content = f"{path} {query} {body}"
        
        # 1. Encoding evasion
        is_evasion, detection = self.encoding_detector.is_evasion_attempt(full_content)
        if is_evasion:
            detections.append(detection)
        
        # 2. XXE attacks
        is_xxe, detection = self.xxe_detector.detect(body)
        if is_xxe:
            detections.append(detection)
        
        # 3. GraphQL attacks
        is_graphql, detection = self.graphql_detector.detect(body, path)
        if is_graphql:
            detections.append(detection)
        
        # 4. JWT/OAuth attacks
        is_jwt, detection = self.jwt_detector.detect(full_content, headers)
        if is_jwt:
            detections.append(detection)
        
        # 5. File upload attacks
        if filename and file_content:
            content_type = headers.get('content-type', '')
            is_upload, detection = self.upload_detector.detect(filename, file_content, content_type)
            if is_upload:
                detections.append(detection)
        
        # 6. HTTP/2 attacks
        is_http2, detection = self.http2_detector.detect(headers)
        if is_http2:
            detections.append(detection)
        
        # 7. Adversarial ML evasion
        is_adversarial, detection = self.adversarial_detector.detect(full_content, client_ip, ml_score)
        if is_adversarial:
            detections.append(detection)
        

        # 8. SSTI attacks
        is_ssti, detection = self.ssti_detector.detect(full_content)
        if is_ssti:
            detections.append(detection)

        # 9. Request Smuggling attacks
        is_smuggling, detection = self.smuggling_detector.detect(headers, body)
        if is_smuggling:
            detections.append(detection)

        # 10. Deserialization attacks
        is_deserialization, detection = self.deserialization_detector.detect(full_content, file_content)
        if is_deserialization:
            detections.append(detection)

        # 11. Advanced SSRF
        is_ssrf, detection = self.advanced_ssrf_detector.detect(full_content)
        if is_ssrf:
            detections.append(detection)
        return detections
    
    def get_max_threat_level(self, detections: List[AdvancedDetection]) -> ThreatLevel:
        """Get highest threat level from detections"""
        if not detections:
            return ThreatLevel.NONE
        return max(d.threat_level for d in detections)


# Global instance
advanced_protection = AdvancedProtectionEngine()
