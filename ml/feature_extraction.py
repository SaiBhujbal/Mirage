"""
MIRAGE Feature Extraction Pipeline
Optimized for real-time feature computation
Target: < 0.5ms for feature extraction
"""
import math
import re
from typing import Dict, List, Tuple, Optional
from collections import Counter
from dataclasses import dataclass
import hashlib
import numpy as np

from core.models import RequestContext

@dataclass
class FeatureVector:
    """47-dimensional feature vector for ML model"""
    features: np.ndarray
    feature_names: List[str]
    
    def to_dict(self) -> Dict[str, float]:
        return dict(zip(self.feature_names, self.features.tolist()))

class FeatureExtractor:
    """
    High-performance feature extraction
    Computes 47 features for ML model
    """
    
    # Feature names (order matters for model)
    FEATURE_NAMES = [
        # Request basics (7)
        "method_encoded",
        "path_length",
        "path_depth",
        "query_length",
        "body_length",
        "header_count",
        "content_type_encoded",
        
        # Entropy features (4)
        "path_entropy",
        "query_entropy",
        "body_entropy",
        "combined_entropy",
        
        # Character distribution (8)
        "special_char_ratio",
        "uppercase_ratio",
        "digit_ratio",
        "whitespace_ratio",
        "non_ascii_ratio",
        "hex_char_ratio",
        "base64_char_ratio",
        "punctuation_density",
        
        # Payload indicators (12)
        "sql_keyword_count",
        "xss_pattern_count",
        "rce_pattern_count",
        "path_traversal_count",
        "encoding_layers",
        "nested_brackets",
        "quote_imbalance",
        "comment_indicators",
        "null_byte_present",
        "unicode_escapes",
        "hex_encoding_count",
        "length_anomaly_score",
        
        # Structural features (8)
        "param_count",
        "max_param_length",
        "avg_param_length",
        "duplicate_params",
        "array_params",
        "nested_json_depth",
        "url_in_param",
        "file_extension_present",
        
        # Behavioral (8)
        "request_rate_1m",
        "unique_paths_1h",
        "error_rate_1h",
        "session_duration",
        "requests_per_session",
        "avg_body_size",
        "method_variety",
        "ua_consistency",
    ]
    
    # Method encoding
    METHOD_MAP = {
        "GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
        "PATCH": 4, "HEAD": 5, "OPTIONS": 6, "TRACE": 7,
        "CONNECT": 8
    }
    
    # Content-type encoding
    CONTENT_TYPE_MAP = {
        "": 0,
        "application/json": 1,
        "application/x-www-form-urlencoded": 2,
        "multipart/form-data": 3,
        "text/plain": 4,
        "text/html": 5,
        "application/xml": 6,
        "text/xml": 7,
    }
    
    # SQL keywords for counting
    SQL_KEYWORDS = {
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'exec', 'execute', 'having', 'order', 'group', 'from',
        'where', 'and', 'or', 'null', 'like', 'between', 'join',
        'table', 'database', 'schema', 'information_schema',
        'sleep', 'benchmark', 'waitfor', 'delay', 'cast', 'convert'
    }
    
    # XSS patterns
    XSS_PATTERNS = [
        r'<script', r'javascript:', r'onerror\s*=', r'onload\s*=',
        r'onclick\s*=', r'onmouseover\s*=', r'<iframe', r'<svg',
        r'<img\s+[^>]*on\w+\s*=', r'expression\s*\('
    ]
    
    # RCE patterns
    RCE_PATTERNS = [
        r';\s*\w+', r'\|\s*\w+', r'\$\(', r'`[^`]+`',
        r'system\s*\(', r'exec\s*\(', r'eval\s*\('
    ]
    
    def __init__(self):
        # Pre-compile regex patterns for speed
        self._xss_patterns = [re.compile(p, re.I) for p in self.XSS_PATTERNS]
        self._rce_patterns = [re.compile(p, re.I) for p in self.RCE_PATTERNS]
        
        # Session state cache (would be Redis in production)
        self._session_cache: Dict[str, Dict] = {}
    
    def extract(self, ctx: RequestContext, 
                session_state: Optional[Dict] = None) -> FeatureVector:
        """
        Extract all features from request context
        Target: < 0.5ms
        """
        features = np.zeros(len(self.FEATURE_NAMES), dtype=np.float32)
        
        # Request basics (7 features)
        features[0] = self.METHOD_MAP.get(ctx.method.upper(), 8)
        features[1] = min(len(ctx.path), 2000) / 2000  # Normalized
        features[2] = len(ctx.path_segments)
        features[3] = min(len(ctx.query_string), 4000) / 4000
        features[4] = min(len(ctx.body), 100000) / 100000
        features[5] = min(len(ctx.headers), 50) / 50
        features[6] = self._encode_content_type(ctx.content_type)
        
        # Combine text for analysis
        combined = f"{ctx.path} {ctx.query_string} {ctx.body_str}"
        
        # Entropy features (4 features)
        features[7] = self._shannon_entropy(ctx.path)
        features[8] = self._shannon_entropy(ctx.query_string)
        features[9] = self._shannon_entropy(ctx.body_str[:2000])  # Limit for speed
        features[10] = self._shannon_entropy(combined[:3000])
        
        # Character distribution (8 features)
        char_dist = self._char_distribution(combined)
        features[11] = char_dist['special']
        features[12] = char_dist['uppercase']
        features[13] = char_dist['digit']
        features[14] = char_dist['whitespace']
        features[15] = char_dist['non_ascii']
        features[16] = char_dist['hex']
        features[17] = char_dist['base64']
        features[18] = char_dist['punctuation']
        
        # Payload indicators (12 features)
        features[19] = self._count_sql_keywords(combined)
        features[20] = self._count_xss_patterns(combined)
        features[21] = self._count_rce_patterns(combined)
        features[22] = combined.count('../') + combined.count('..\\')
        features[23] = self._count_encoding_layers(combined)
        features[24] = self._count_nested_brackets(combined)
        features[25] = self._quote_imbalance(combined)
        features[26] = self._count_comments(combined)
        features[27] = 1.0 if '\x00' in combined else 0.0
        features[28] = len(re.findall(r'\\u[0-9a-fA-F]{4}', combined))
        features[29] = len(re.findall(r'0x[0-9a-fA-F]+', combined))
        features[30] = self._length_anomaly_score(ctx)
        
        # Structural features (8 features)
        struct = self._structural_features(ctx)
        features[31] = struct['param_count']
        features[32] = struct['max_param_length']
        features[33] = struct['avg_param_length']
        features[34] = struct['duplicate_params']
        features[35] = struct['array_params']
        features[36] = struct['json_depth']
        features[37] = struct['url_in_param']
        features[38] = struct['file_extension']
        
        # Behavioral features (8 features) - from session state
        if session_state:
            features[39] = min(session_state.get('request_rate_1m', 0), 100) / 100
            features[40] = min(session_state.get('unique_paths_1h', 0), 100) / 100
            features[41] = session_state.get('error_rate_1h', 0)
            features[42] = min(session_state.get('session_duration', 0), 3600) / 3600
            features[43] = min(session_state.get('requests_per_session', 0), 1000) / 1000
            features[44] = min(session_state.get('avg_body_size', 0), 10000) / 10000
            features[45] = session_state.get('method_variety', 0)
            features[46] = session_state.get('ua_consistency', 1.0)
        else:
            # Default behavioral features
            features[39:47] = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
        
        return FeatureVector(features=features, feature_names=self.FEATURE_NAMES)
    
    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Limit text length for speed
        text = text[:2000]
        
        freq = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return min(entropy / 8.0, 1.0)  # Normalize to [0, 1]
    
    def _encode_content_type(self, content_type: str) -> float:
        """Encode content type to numeric value"""
        ct_lower = content_type.lower().split(';')[0].strip()
        return self.CONTENT_TYPE_MAP.get(ct_lower, 8) / 8.0
    
    def _char_distribution(self, text: str) -> Dict[str, float]:
        """Calculate character type distribution"""
        if not text:
            return {k: 0.0 for k in ['special', 'uppercase', 'digit', 
                                      'whitespace', 'non_ascii', 'hex', 
                                      'base64', 'punctuation']}
        
        length = len(text)
        
        special = sum(1 for c in text if c in "!@#$%^&*(){}[]|\\:;<>?,./~`")
        uppercase = sum(1 for c in text if c.isupper())
        digit = sum(1 for c in text if c.isdigit())
        whitespace = sum(1 for c in text if c.isspace())
        non_ascii = sum(1 for c in text if ord(c) > 127)
        hex_chars = sum(1 for c in text if c in '0123456789abcdefABCDEF')
        base64_chars = sum(1 for c in text if c.isalnum() or c in '+/=')
        punctuation = sum(1 for c in text if c in '.,;:!?')
        
        return {
            'special': special / length,
            'uppercase': uppercase / length,
            'digit': digit / length,
            'whitespace': whitespace / length,
            'non_ascii': non_ascii / length,
            'hex': hex_chars / length,
            'base64': base64_chars / length,
            'punctuation': punctuation / length,
        }
    
    def _count_sql_keywords(self, text: str) -> float:
        """Count SQL keywords in text"""
        words = set(re.findall(r'\w+', text.lower()))
        count = len(words & self.SQL_KEYWORDS)
        return min(count / 10.0, 1.0)
    
    def _count_xss_patterns(self, text: str) -> float:
        """Count XSS pattern matches"""
        count = sum(1 for p in self._xss_patterns if p.search(text))
        return min(count / len(self._xss_patterns), 1.0)
    
    def _count_rce_patterns(self, text: str) -> float:
        """Count RCE pattern matches"""
        count = sum(1 for p in self._rce_patterns if p.search(text))
        return min(count / len(self._rce_patterns), 1.0)
    
    def _count_encoding_layers(self, text: str) -> float:
        """Estimate encoding layers (URL encoding, base64, etc.)"""
        layers = 0
        
        # Check for URL encoding
        if '%' in text:
            layers += text.count('%') / 50
        
        # Check for double encoding
        if '%25' in text:
            layers += 1
        
        # Check for base64
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text):
            layers += 0.5
        
        # Check for hex encoding
        if re.search(r'\\x[0-9a-fA-F]{2}', text):
            layers += 0.5
        
        return min(layers, 1.0)
    
    def _count_nested_brackets(self, text: str) -> float:
        """Count nesting depth of brackets"""
        max_depth = 0
        depth = 0
        
        for c in text:
            if c in '([{<':
                depth += 1
                max_depth = max(max_depth, depth)
            elif c in ')]}>' and depth > 0:
                depth -= 1
        
        return min(max_depth / 10.0, 1.0)
    
    def _quote_imbalance(self, text: str) -> float:
        """Calculate quote imbalance (indicator of injection)"""
        single = text.count("'")
        double = text.count('"')
        
        # Odd number of quotes suggests injection attempt
        imbalance = (single % 2) + (double % 2)
        
        return imbalance / 2.0
    
    def _count_comments(self, text: str) -> float:
        """Count SQL/code comment indicators"""
        indicators = ['--', '/*', '*/', '#', '//', '<!--']
        count = sum(text.count(ind) for ind in indicators)
        return min(count / 5.0, 1.0)
    
    def _length_anomaly_score(self, ctx: RequestContext) -> float:
        """Calculate how anomalous the request lengths are"""
        score = 0.0
        
        # Very long URL
        if len(ctx.path) > 500:
            score += 0.3
        
        # Very long query
        if len(ctx.query_string) > 1000:
            score += 0.3
        
        # Unusual body size for method
        if ctx.method == "GET" and len(ctx.body) > 0:
            score += 0.2
        
        # Very long headers
        header_len = sum(len(k) + len(v) for k, v in ctx.headers.items())
        if header_len > 4000:
            score += 0.2
        
        return min(score, 1.0)
    
    def _structural_features(self, ctx: RequestContext) -> Dict[str, float]:
        """Extract structural features from request"""
        params = ctx.query_params
        
        param_lengths = [len(str(v)) for v in params.values()]
        
        # Check for URLs in parameters
        url_pattern = re.compile(r'https?://', re.I)
        url_count = sum(1 for v in params.values() if url_pattern.search(str(v)))
        
        # Check for file extensions
        ext_pattern = re.compile(r'\.\w{2,4}$')
        has_extension = any(ext_pattern.search(str(v)) for v in params.values())
        
        # Check JSON depth
        json_depth = 0
        if ctx.content_type and 'json' in ctx.content_type.lower():
            json_depth = self._estimate_json_depth(ctx.body_str)
        
        # Check for duplicate params
        duplicates = len(params) - len(set(params.keys()))
        
        # Check for array params (param[])
        array_params = sum(1 for k in params.keys() if '[' in k)
        
        return {
            'param_count': min(len(params) / 20.0, 1.0),
            'max_param_length': min(max(param_lengths) if param_lengths else 0, 1000) / 1000,
            'avg_param_length': min(sum(param_lengths) / len(param_lengths) if param_lengths else 0, 500) / 500,
            'duplicate_params': min(duplicates / 5.0, 1.0),
            'array_params': min(array_params / 5.0, 1.0),
            'json_depth': min(json_depth / 10.0, 1.0),
            'url_in_param': min(url_count / 3.0, 1.0),
            'file_extension': 1.0 if has_extension else 0.0,
        }
    
    def _estimate_json_depth(self, text: str) -> int:
        """Estimate JSON nesting depth without full parsing"""
        max_depth = 0
        depth = 0
        
        for c in text[:5000]:  # Limit for speed
            if c in '{[':
                depth += 1
                max_depth = max(max_depth, depth)
            elif c in '}]':
                depth = max(0, depth - 1)
        
        return max_depth

# Singleton instance
feature_extractor = FeatureExtractor()
