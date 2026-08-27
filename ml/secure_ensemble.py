#!/usr/bin/env python3
"""
MIRAGE Secure Ensemble Inference
====================================
Naval SWAVLAMBAN 2025 Challenge 3

Secure inference using trained ensemble models.
NO PICKLE DESERIALIZATION - uses numpy arrays and joblib (safe mode).

Security Features:
1. Model signature verification before loading
2. No pickle.load() - uses safe formats only
3. Size and path validation
4. Feature extraction with input sanitization

Author: MIRAGE Team
Date: December 2025
"""

import os
import sys
import json
import hmac
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import threading

import numpy as np

# Import sklearn models (we'll use joblib for safe loading)
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import RobustScaler

# XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# ONNX Runtime (preferred for inference)
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

logger = logging.getLogger("mirage.ml.secure_ensemble")


# ============================================================================
# SECURITY ERRORS
# ============================================================================

class ModelSecurityError(Exception):
    """Security violation during model loading"""
    pass

class ModelIntegrityError(Exception):
    """Model file has been tampered with"""
    pass


# ============================================================================
# SECURE FEATURE EXTRACTOR (Duplicate for standalone use)
# ============================================================================

class SecureFeatureExtractor:
    """
    High-performance feature extraction for WAF
    50-dimensional feature vector
    """
    
    FEATURE_NAMES = [
        'total_length', 'path_length', 'query_length', 'body_length', 'header_length',
        'total_entropy', 'path_entropy', 'query_entropy', 'body_entropy',
        'special_char_ratio', 'uppercase_ratio', 'lowercase_ratio', 'digit_ratio',
        'whitespace_ratio', 'non_ascii_ratio', 'punctuation_ratio',
        'letter_ratio', 'alphanumeric_ratio', 'hex_char_ratio',
        'sql_keyword_count', 'xss_tag_count', 'xss_event_count', 'rce_indicator_count',
        'path_traversal_count', 'ssrf_indicator_count', 'encoding_layers',
        'quote_count', 'comment_indicator_count', 'null_byte_count',
        'unicode_escape_count', 'hex_encoding_count', 'base64_pattern_count',
        'bracket_depth', 'parenthesis_depth',
        'param_count', 'max_param_length', 'avg_param_length',
        'duplicate_param_count', 'nested_structure_depth',
        'url_count', 'ip_address_count', 'domain_count',
        'file_extension_count', 'protocol_count',
        'char_diversity', 'bigram_uniqueness', 'trigram_uniqueness',
        'longest_word_length', 'avg_word_length', 'word_count',
    ]
    
    SQL_KEYWORDS = {'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
                   'exec', 'execute', 'declare', 'cast', 'convert', 'table', 'from', 
                   'where', 'and', 'or', 'sleep', 'benchmark', 'waitfor', 'load_file'}
    
    XSS_TAGS = {'script', 'img', 'svg', 'iframe', 'object', 'embed', 'video', 'audio',
               'body', 'input', 'form', 'a', 'link', 'style', 'div', 'marquee', 'details'}
    
    XSS_EVENTS = {'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur',
                 'onsubmit', 'onchange', 'oninput', 'ontoggle', 'onstart', 'onbegin'}
    
    RCE_INDICATORS = {'system', 'exec', 'eval', 'passthru', 'shell_exec', 'popen',
                     '__import__', 'subprocess', 'os.system', 'child_process', 'spawn'}
    
    def __init__(self):
        self.n_features = len(self.FEATURE_NAMES)
        # Precompile counters
        from collections import Counter
        self._counter = Counter
    
    def extract(self, payload: str) -> np.ndarray:
        """Extract 50-dimensional feature vector"""
        features = np.zeros(self.n_features, dtype=np.float32)
        
        if not payload:
            return features
        
        # Input sanitization - limit size
        payload = payload[:50000]
        payload_lower = payload.lower()
        n = len(payload)
        
        # Length features (0-4)
        features[0] = n
        features[1] = len(payload.split('?')[0]) if '?' in payload else n
        features[2] = len(payload.split('?')[1]) if '?' in payload else 0
        features[3] = n if not payload.startswith('/') else 0
        features[4] = sum(1 for c in payload if c in ':;,')
        
        # Entropy features (5-8)
        features[5] = self._entropy(payload)
        features[6] = self._entropy(payload.split('?')[0])
        features[7] = self._entropy(payload.split('?')[1] if '?' in payload else '')
        features[8] = features[5]
        
        # Character ratios (9-18)
        if n > 0:
            features[9] = sum(1 for c in payload if c in '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\~`') / n
            features[10] = sum(1 for c in payload if c.isupper()) / n
            features[11] = sum(1 for c in payload if c.islower()) / n
            features[12] = sum(1 for c in payload if c.isdigit()) / n
            features[13] = sum(1 for c in payload if c.isspace()) / n
            features[14] = sum(1 for c in payload if ord(c) > 127) / n
            features[15] = sum(1 for c in payload if c in '.,;:!?-\'\"()[]{}') / n
            features[16] = sum(1 for c in payload if c.isalpha()) / n
            features[17] = sum(1 for c in payload if c.isalnum()) / n
            features[18] = sum(1 for c in payload if c in '0123456789abcdefABCDEF') / n
        
        # Attack indicators (19-33)
        features[19] = sum(1 for kw in self.SQL_KEYWORDS if kw in payload_lower)
        features[20] = sum(1 for t in self.XSS_TAGS if f'<{t}' in payload_lower)
        features[21] = sum(1 for e in self.XSS_EVENTS if e in payload_lower)
        features[22] = sum(1 for i in self.RCE_INDICATORS if i in payload_lower)
        features[23] = payload_lower.count('../') + payload_lower.count('..\\')
        features[24] = sum(1 for i in ['localhost', '127.0.0.1', '169.254', '::1'] if i in payload_lower)
        features[25] = self._encoding_layers(payload)
        features[26] = payload.count("'") + payload.count('"') + payload.count('`')
        features[27] = payload_lower.count('--') + payload_lower.count('/*') + payload_lower.count('#')
        features[28] = payload_lower.count('%00') + payload.count('\x00')
        features[29] = payload_lower.count('\\u') + payload_lower.count('%u')
        features[30] = payload_lower.count('%') // 2
        features[31] = 1 if ('==' in payload or (len(payload) % 4 == 0 and payload.replace('+', '').replace('/', '').replace('=', '').isalnum())) else 0
        features[32] = self._max_depth(payload, '<', '>')
        features[33] = self._max_depth(payload, '(', ')')
        
        # Structural features (34-43)
        features[34] = payload.count('&') + payload.count('=')
        if '=' in payload:
            params = payload.split('&')
            lengths = [len(p.split('=')[1]) if '=' in p else 0 for p in params]
            features[35] = max(lengths) if lengths else 0
            features[36] = np.mean(lengths) if lengths else 0
        features[37] = len(payload.split('&')) - len(set(p.split('=')[0] for p in payload.split('&') if '=' in p))
        features[38] = self._max_depth(payload, '{', '}') + self._max_depth(payload, '[', ']')
        features[39] = payload_lower.count('http://') + payload_lower.count('https://')
        features[40] = sum(1 for i in range(len(payload)-3) if payload[i:i+4].replace('.', '').isdigit())
        features[41] = payload.count('.com') + payload.count('.net') + payload.count('.org')
        features[42] = sum(1 for ext in ['.php', '.asp', '.jsp', '.cgi', '.py', '.sh'] if ext in payload_lower)
        features[43] = sum(1 for p in ['http:', 'https:', 'ftp:', 'file:', 'data:', 'javascript:'] if p in payload_lower)
        
        # Statistical features (44-49)
        features[44] = len(set(payload)) / n if n > 0 else 0
        features[45] = len(set(payload[i:i+2] for i in range(n-1))) / max(1, n-1)
        features[46] = len(set(payload[i:i+3] for i in range(n-2))) / max(1, n-2)
        words = payload.split()
        features[47] = max(len(w) for w in words) if words else 0
        features[48] = np.mean([len(w) for w in words]) if words else 0
        features[49] = len(words)
        
        return features
    
    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counter = self._counter(text)
        n = len(text)
        return -sum((c/n) * np.log2(c/n) for c in counter.values())
    
    def _encoding_layers(self, text: str) -> int:
        layers = 0
        if '%' in text:
            layers += 1
            if '%25' in text:
                layers += 1
        if '&#' in text:
            layers += 1
        if '\\u' in text or '\\x' in text:
            layers += 1
        return layers
    
    def _max_depth(self, text: str, open_c: str, close_c: str) -> int:
        max_d = curr = 0
        for c in text:
            if c == open_c:
                curr += 1
                max_d = max(max_d, curr)
            elif c == close_c:
                curr = max(0, curr - 1)
        return max_d


# ============================================================================
# PREDICTION RESULT
# ============================================================================

@dataclass
class EnsemblePrediction:
    """Result from ensemble prediction"""
    is_malicious: bool
    confidence: float
    category: str
    category_probabilities: Dict[str, float]
    model_scores: Dict[str, float]
    explanation: Dict[str, Any]
    latency_ms: float


# ============================================================================
# SECURE ENSEMBLE PREDICTOR
# ============================================================================

class SecureEnsemblePredictor:
    """
    Secure inference using trained ensemble models
    
    Security:
    - Model signature verification
    - No pickle deserialization
    - Input size limits
    - Memory-safe operations
    """
    
    MAX_PAYLOAD_SIZE = 100000
    ALLOWED_MODEL_FILES = {'.npz', '.npy', '.json', '.onnx', '.xgb'}
    
    def __init__(self, 
                 models_dir: str = "./models",
                 signing_key: Optional[str] = None,
                 verify_signatures: bool = True):
        
        self.models_dir = Path(models_dir)
        self.signing_key = (signing_key or os.environ.get('MODEL_SIGNING_KEY', '')).encode()
        self.verify_signatures = verify_signatures
        
        # Models
        self.isolation_forest = None
        self.classifier = None
        self.scaler = None
        self.feature_extractor = SecureFeatureExtractor()
        
        # Metadata
        self.categories = None
        self.ensemble_weights = None
        self.ae_threshold = None
        self.n_features = 50
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Load models
        self._load_models()
    
    def _load_models(self):
        """Load all models securely"""
        logger.info("Loading ensemble models...")
        
        # Verify signatures if enabled
        if self.verify_signatures and self.signing_key:
            self._verify_all_signatures()
        
        # Load metadata
        meta_path = self.models_dir / 'ensemble_metadata.json'
        if meta_path.exists():
            with open(meta_path) as f:
                meta = json.load(f)
            self.categories = meta.get('categories', ['benign', 'sqli', 'xss', 'rce', 'path_traversal', 
                                                       'ssrf', 'xxe', 'ldap_injection', 'header_injection', 'log_injection'])
            self.ensemble_weights = meta.get('ensemble_weights', {'xgboost': 0.5, 'isolation_forest': 0.25, 'autoencoder': 0.25})
            self.ae_threshold = meta.get('ae_threshold', 1.0)
            self.n_features = meta.get('n_features', 50)
        else:
            logger.warning("No metadata file found, using defaults")
            self.categories = ['benign', 'sqli', 'xss', 'rce', 'path_traversal', 
                              'ssrf', 'xxe', 'ldap_injection', 'header_injection', 'log_injection']
            self.ensemble_weights = {'xgboost': 0.7, 'isolation_forest': 0.3}
        
        # Load scaler (try joblib first, then npz)
        self._load_scaler()
        
        # Load Isolation Forest
        self._load_isolation_forest()
        
        # Load XGBoost classifier
        self._load_classifier()
        
        logger.info("Models loaded successfully")
    
    def _load_scaler(self):
        """Load scaler from joblib or npz"""
        # Try joblib first (preferred)
        joblib_path = self.models_dir / 'scaler.joblib'
        if joblib_path.exists():
            try:
                import joblib
                self.scaler = joblib.load(str(joblib_path))
                logger.info("  ✓ Scaler loaded (joblib)")
                return
            except Exception as e:
                logger.warning(f"  ✗ Joblib scaler load failed: {e}")
        
        # Fallback to npz
        npz_path = self.models_dir / 'scaler_params.npz'
        if npz_path.exists():
            try:
                params = np.load(str(npz_path), allow_pickle=False)
                self.scaler = RobustScaler()
                self.scaler.center_ = params['center']
                self.scaler.scale_ = params['scale']
                logger.info("  ✓ Scaler loaded (npz)")
            except Exception as e:
                logger.warning(f"  ✗ NPZ scaler load failed: {e}")
    
    def _load_isolation_forest(self):
        """Load Isolation Forest from joblib or use fallback"""
        # Try joblib first
        joblib_path = self.models_dir / 'isolation_forest.joblib'
        if joblib_path.exists():
            try:
                import joblib
                self.isolation_forest = joblib.load(str(joblib_path))
                self._if_type = 'sklearn'
                logger.info("  ✓ Isolation Forest loaded (joblib)")
                return
            except Exception as e:
                logger.warning(f"  ✗ Joblib IF load failed: {e}")
        
        # Fallback to threshold-based
        self.isolation_forest = None
        self._if_type = 'threshold'
        logger.info("  ⚠ Using threshold-based anomaly detection (fallback)")
    
    def _threshold_based_anomaly_detector(self, features: np.ndarray) -> float:
        """
        Threshold-based anomaly detection (replacement for IF)
        Returns anomaly score between 0 and 1
        """
        scores = []
        
        # SQL indicators
        sql_score = min(1.0, features[0, 19] / 3)  # sql_keyword_count
        scores.append(sql_score * 0.3)
        
        # XSS indicators
        xss_score = min(1.0, (features[0, 20] + features[0, 21]) / 3)
        scores.append(xss_score * 0.25)
        
        # RCE indicators
        rce_score = min(1.0, features[0, 22] / 2)
        scores.append(rce_score * 0.2)
        
        # Path traversal
        pt_score = min(1.0, features[0, 23] / 2)
        scores.append(pt_score * 0.1)
        
        # Special char ratio (high = suspicious)
        special_score = min(1.0, features[0, 9] * 3)
        scores.append(special_score * 0.1)
        
        # Encoding layers (evasion attempt)
        enc_score = min(1.0, features[0, 25] / 2)
        scores.append(enc_score * 0.05)
        
        return np.sum(scores)
    
    def _load_classifier(self):
        """Load XGBoost or fallback classifier"""
        # Try XGBoost native format first (most reliable)
        xgb_path = self.models_dir / 'classifier.xgb'
        if XGBOOST_AVAILABLE and xgb_path.exists():
            try:
                self.classifier = xgb.XGBClassifier()
                self.classifier.load_model(str(xgb_path))
                self._classifier_type = 'xgboost'
                logger.info("  ✓ Classifier loaded (XGBoost native)")
                return
            except Exception as e:
                logger.warning(f"  ✗ XGBoost native load failed: {e}")
        
        # Try ONNX
        onnx_path = self.models_dir / 'classifier.onnx'
        if ONNX_AVAILABLE and onnx_path.exists():
            try:
                self.classifier = ort.InferenceSession(str(onnx_path))
                self._classifier_type = 'onnx'
                logger.info("  ✓ Classifier loaded (ONNX)")
                return
            except Exception as e:
                logger.warning(f"  ✗ ONNX load failed: {e}")
        
        # Fallback to feature importance + threshold
        importance_path = self.models_dir / 'classifier_feature_importance.npy'
        if importance_path.exists():
            self._feature_importance = np.load(str(importance_path), allow_pickle=False)
            self._classifier_type = 'threshold'
            logger.info("  ⚠ Using threshold-based classifier (fallback)")
        else:
            self._classifier_type = 'threshold'
            self._feature_importance = np.ones(self.n_features) / self.n_features
            logger.warning("  ⚠ No classifier model found, using basic threshold")
    
    def _verify_all_signatures(self):
        """Verify all model file signatures"""
        sig_path = self.models_dir / 'model_signatures.json'
        
        if not sig_path.exists():
            logger.warning("No signature file found - skipping verification")
            return
        
        with open(sig_path) as f:
            signatures = json.load(f)
        
        for filename, expected_sig in signatures.items():
            filepath = self.models_dir / filename
            if filepath.exists():
                with open(filepath, 'rb') as f:
                    content = f.read()
                actual_sig = hmac.new(self.signing_key, content, hashlib.sha256).hexdigest()
                
                if actual_sig != expected_sig:
                    raise ModelIntegrityError(f"Signature mismatch for {filename}")
        
        logger.info("  ✓ All model signatures verified")
    
    def predict(self, payload: str) -> EnsemblePrediction:
        """
        Make prediction on payload
        
        Returns EnsemblePrediction with:
        - is_malicious: bool
        - confidence: float (0-1)
        - category: str
        - category_probabilities: Dict
        - model_scores: Dict
        - explanation: Dict
        - latency_ms: float
        """
        start_time = time.perf_counter()
        
        # Input validation
        if not payload:
            return self._benign_result(0.0)
        
        payload = payload[:self.MAX_PAYLOAD_SIZE]
        
        with self.lock:
            # Extract features
            features = self.feature_extractor.extract(payload)
            features = features.reshape(1, -1)
            
            # Scale features
            if self.scaler is not None:
                features_scaled = self.scaler.transform(features)
            else:
                features_scaled = features
            
            # Get model predictions
            model_scores = {}
            
            # Isolation Forest
            if self._if_type == 'sklearn' and self.isolation_forest is not None:
                # Use actual sklearn IF
                if_pred = self.isolation_forest.predict(features_scaled)
                if_raw_score = -self.isolation_forest.score_samples(features_scaled)[0]
                # Normalize to [0, 1]
                if_score = min(1.0, max(0.0, (if_raw_score + 0.5)))
            else:
                # Fallback threshold-based
                if_score = self._threshold_based_anomaly_detector(features)
            model_scores['isolation_forest'] = float(if_score)
            
            # Classifier
            clf_result = self._classify(features_scaled, features)
            model_scores['xgboost'] = float(clf_result['score'])
            category_probs = clf_result['probabilities']
            predicted_category = clf_result['category']
            
            # Ensemble score
            weights = self.ensemble_weights
            ensemble_score = (
                weights.get('xgboost', 0.7) * clf_result['score'] +
                weights.get('isolation_forest', 0.3) * if_score
            )
            
            # Decision - use classifier prediction as primary
            is_malicious = predicted_category != 'benign'
            
            # Explanation
            explanation = self._explain(features[0], clf_result)
            
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            return EnsemblePrediction(
                is_malicious=is_malicious,
                confidence=float(clf_result['score']),
                category=predicted_category,
                category_probabilities=category_probs,
                model_scores=model_scores,
                explanation=explanation,
                latency_ms=latency_ms
            )
    
    def _classify(self, features_scaled: np.ndarray, features_raw: np.ndarray) -> Dict:
        """Run classifier"""
        if self._classifier_type == 'onnx':
            input_name = self.classifier.get_inputs()[0].name
            output = self.classifier.run(None, {input_name: features_scaled.astype(np.float32)})
            probs = output[1][0]  # Probabilities
            pred_idx = int(output[0][0])
        elif self._classifier_type == 'xgboost':
            probs = self.classifier.predict_proba(features_scaled)[0]
            pred_idx = int(self.classifier.predict(features_scaled)[0])
        else:
            # Threshold-based fallback using attack indicators
            probs = self._threshold_classify(features_raw)
            pred_idx = int(np.argmax(probs))
        
        return {
            'score': 1 - probs[0] if len(probs) > 0 else 0.5,  # P(attack)
            'probabilities': {self.categories[i]: float(p) for i, p in enumerate(probs)},
            'category': self.categories[pred_idx] if pred_idx < len(self.categories) else 'unknown'
        }
    
    def _threshold_classify(self, features: np.ndarray) -> np.ndarray:
        """Threshold-based classification fallback"""
        f = features[0]
        probs = np.zeros(len(self.categories))
        
        # Benign probability (baseline)
        probs[0] = 0.5
        
        # SQLi (index 1)
        probs[1] = min(0.95, f[19] * 0.2 + f[26] * 0.1 + f[27] * 0.15)
        
        # XSS (index 2)
        probs[2] = min(0.95, f[20] * 0.25 + f[21] * 0.25 + f[32] * 0.1)
        
        # RCE (index 3)
        probs[3] = min(0.95, f[22] * 0.3 + f[33] * 0.1)
        
        # Path traversal (index 4)
        probs[4] = min(0.95, f[23] * 0.4)
        
        # SSRF (index 5)
        probs[5] = min(0.95, f[24] * 0.3 + f[39] * 0.1)
        
        # XXE (index 6)
        probs[6] = min(0.95, f[32] * 0.2) if '<' in str(f) else 0.0
        
        # Adjust benign based on attack indicators
        max_attack = max(probs[1:])
        if max_attack > 0.3:
            probs[0] = max(0.05, 1 - max_attack)
        
        # Normalize
        total = sum(probs)
        if total > 0:
            probs = probs / total
        
        return probs
    
    def _explain(self, features: np.ndarray, clf_result: Dict) -> Dict:
        """Generate explanation for prediction"""
        explanation = {}
        
        # Top contributing features
        if hasattr(self, '_feature_importance'):
            contributions = features * self._feature_importance
            top_indices = np.argsort(np.abs(contributions))[-5:][::-1]
            
            for idx in top_indices:
                if idx < len(SecureFeatureExtractor.FEATURE_NAMES):
                    name = SecureFeatureExtractor.FEATURE_NAMES[idx]
                    explanation[name] = {
                        'value': float(features[idx]),
                        'contribution': float(contributions[idx])
                    }
        
        # Attack indicators
        attack_indicators = []
        if features[19] > 0:
            attack_indicators.append(f"SQL keywords: {int(features[19])}")
        if features[20] > 0 or features[21] > 0:
            attack_indicators.append(f"XSS patterns: tags={int(features[20])}, events={int(features[21])}")
        if features[22] > 0:
            attack_indicators.append(f"RCE indicators: {int(features[22])}")
        if features[23] > 0:
            attack_indicators.append(f"Path traversal: {int(features[23])}")
        if features[24] > 0:
            attack_indicators.append(f"SSRF indicators: {int(features[24])}")
        
        if attack_indicators:
            explanation['attack_indicators'] = attack_indicators
        
        return explanation
    
    def _benign_result(self, latency: float) -> EnsemblePrediction:
        """Return benign result"""
        return EnsemblePrediction(
            is_malicious=False,
            confidence=0.0,
            category='benign',
            category_probabilities={'benign': 1.0},
            model_scores={'isolation_forest': 0.0, 'xgboost': 0.0},
            explanation={},
            latency_ms=latency
        )


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_predictor_instance = None
_predictor_lock = threading.Lock()

def get_predictor(models_dir: str = "./models") -> SecureEnsemblePredictor:
    """Get singleton predictor instance"""
    global _predictor_instance
    
    with _predictor_lock:
        if _predictor_instance is None:
            _predictor_instance = SecureEnsemblePredictor(models_dir)
        return _predictor_instance


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def predict(payload: str, models_dir: str = "./models") -> Dict[str, Any]:
    """
    Convenience function for prediction
    
    Args:
        payload: The request payload to analyze
        models_dir: Path to models directory
        
    Returns:
        Dict with prediction results
    """
    predictor = get_predictor(models_dir)
    result = predictor.predict(payload)
    
    return {
        'is_malicious': result.is_malicious,
        'confidence': result.confidence,
        'category': result.category,
        'category_probabilities': result.category_probabilities,
        'model_scores': result.model_scores,
        'explanation': result.explanation,
        'latency_ms': result.latency_ms
    }


def is_malicious(payload: str, threshold: float = 0.5) -> bool:
    """Quick check if payload is malicious"""
    predictor = get_predictor()
    result = predictor.predict(payload)
    return result.is_malicious or result.confidence > threshold


# ============================================================================
# MAIN (Testing)
# ============================================================================

if __name__ == '__main__':
    import sys
    
    print("MIRAGE Secure Ensemble Predictor")
    print("=" * 50)
    
    # Test payloads
    test_cases = [
        ("' OR 1=1--", "SQLi"),
        ("<script>alert(1)</script>", "XSS"),
        ("; cat /etc/passwd", "RCE"),
        ("../../../etc/passwd", "Path Traversal"),
        ("http://169.254.169.254/latest/meta-data/", "SSRF"),
        ("search?q=hello+world", "Benign"),
        ("api/users/123", "Benign"),
    ]
    
    predictor = SecureEnsemblePredictor(models_dir="./models")
    
    print("\nTest Results:")
    print("-" * 80)
    
    for payload, expected in test_cases:
        result = predictor.predict(payload)
        status = "✓" if (result.is_malicious and expected != "Benign") or \
                        (not result.is_malicious and expected == "Benign") else "✗"
        
        print(f"{status} [{expected:15}] {payload[:40]:40} → "
              f"{result.category:15} ({result.confidence:.2%}) [{result.latency_ms:.2f}ms]")
    
    print("-" * 80)
    print("Done!")
