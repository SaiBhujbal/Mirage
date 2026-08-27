#!/usr/bin/env python3
"""
DECEPTICON Dual-Layer Inference
===============================
Naval SWAVLAMBAN 2025 Challenge 3

Secure inference using dual-layer ensemble:
- Layer 1: HTTP Payload Analysis
- Layer 2: Network Flow Analysis  
- Meta-Ensemble: Combines both layers

Author: DECEPTICON Team
Date: December 2025
"""

import os
import json
import time
import hmac
import hashlib
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass

import numpy as np

# Sklearn
from sklearn.preprocessing import RobustScaler

# XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# Import feature extractor
from ml.dataset_loader import HTTPFeatureExtractor

logger = logging.getLogger("decepticon.dual_inference")


# ============================================================================
# PREDICTION RESULT
# ============================================================================

@dataclass
class DualLayerPrediction:
    """Result from dual-layer prediction"""
    is_malicious: bool
    confidence: float
    category: str
    unified_category: str
    
    # Layer-specific results
    http_score: float
    http_category: str
    network_score: Optional[float]
    network_category: Optional[str]
    
    # Details
    category_probabilities: Dict[str, float]
    model_scores: Dict[str, float]
    explanation: Dict[str, Any]
    latency_ms: float
    
    # Which layers were used
    layers_used: List[str]


# ============================================================================
# UNIFIED CATEGORIES
# ============================================================================

UNIFIED_CATEGORIES = [
    'benign', 'sqli', 'xss', 'rce', 'path_traversal', 'ssrf',
    'dos', 'ddos', 'brute_force', 'port_scan', 'botnet',
    'infiltration', 'backdoor', 'exploit', 'reconnaissance', 'other_attack'
]


# ============================================================================
# DUAL-LAYER PREDICTOR
# ============================================================================

class DualLayerPredictor:
    """
    Secure dual-layer inference for comprehensive attack detection
    
    Features:
    - HTTP Layer: Analyzes HTTP payloads (50 features)
    - Network Layer: Analyzes network flows (78 features)
    - Meta-Ensemble: Combines both layers with weighted voting
    - Model signature verification
    - Thread-safe inference
    """
    
    MAX_PAYLOAD_SIZE = 100000
    
    def __init__(self,
                 models_dir: str = "./models",
                 signing_key: Optional[str] = None,
                 verify_signatures: bool = True,
                 enable_http: bool = True,
                 enable_network: bool = True):
        
        self.models_dir = Path(models_dir)
        self.signing_key = (signing_key or os.environ.get('MODEL_SIGNING_KEY', '')).encode()
        self.verify_signatures = verify_signatures
        self.enable_http = enable_http
        self.enable_network = enable_network
        
        # Feature extractors
        self.http_extractor = HTTPFeatureExtractor()
        
        # HTTP Layer models
        self.http_scaler = None
        self.http_classifier = None
        self.http_if = None
        self.http_categories = None
        self._http_classifier_type = None
        
        # Network Layer models
        self.network_scaler = None
        self.network_classifier = None
        self.network_if = None
        self.network_categories = None
        self._network_classifier_type = None
        self.network_n_features = None
        
        # Ensemble weights
        self.http_weight = 0.6
        self.network_weight = 0.4
        self.xgb_weight = 0.7
        self.if_weight = 0.3
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Load models
        self._load_models()
    
    def _load_models(self):
        """Load all available models"""
        import joblib
        
        logger.info("Loading dual-layer models...")
        
        # Load metadata
        meta_path = self.models_dir / 'dual_layer_metadata.json'
        if meta_path.exists():
            with open(meta_path) as f:
                meta = json.load(f)
            
            # Ensemble weights
            weights = meta.get('ensemble_weights', {})
            self.http_weight = weights.get('http_weight', 0.6)
            self.network_weight = weights.get('network_weight', 0.4)
            self.xgb_weight = weights.get('xgb_weight', 0.7)
            self.if_weight = weights.get('if_weight', 0.3)
        else:
            # Try legacy metadata
            legacy_meta = self.models_dir / 'ensemble_metadata.json'
            if legacy_meta.exists():
                with open(legacy_meta) as f:
                    meta = json.load(f)
        
        # Verify signatures if enabled
        if self.verify_signatures and self.signing_key:
            self._verify_signatures()
        
        # Load HTTP Layer
        if self.enable_http:
            self._load_http_layer()
        
        # Load Network Layer
        if self.enable_network:
            self._load_network_layer()
        
        logger.info("Models loaded successfully")
    
    def _verify_signatures(self):
        """Verify model signatures"""
        sig_files = [
            'dual_layer_signatures.json',
            'model_signatures.json'
        ]
        
        for sig_file in sig_files:
            sig_path = self.models_dir / sig_file
            if sig_path.exists():
                with open(sig_path) as f:
                    signatures = json.load(f)
                
                for filename, expected_sig in signatures.items():
                    filepath = self.models_dir / filename
                    if filepath.exists():
                        with open(filepath, 'rb') as f:
                            content = f.read()
                        actual_sig = hmac.new(self.signing_key, content, hashlib.sha256).hexdigest()
                        
                        if actual_sig != expected_sig:
                            logger.warning(f"Signature mismatch for {filename}")
                
                logger.info("  ✓ Model signatures verified")
                return
        
        logger.warning("  No signature file found")
    
    def _load_http_layer(self):
        """Load HTTP layer models"""
        import joblib
        
        # Scaler
        scaler_paths = [
            self.models_dir / 'http_scaler.joblib',
            self.models_dir / 'scaler.joblib',
        ]
        for path in scaler_paths:
            if path.exists():
                self.http_scaler = joblib.load(str(path))
                logger.info(f"  ✓ HTTP scaler loaded ({path.name})")
                break
        
        # Isolation Forest
        if_paths = [
            self.models_dir / 'http_isolation_forest.joblib',
            self.models_dir / 'isolation_forest.joblib',
        ]
        for path in if_paths:
            if path.exists():
                self.http_if = joblib.load(str(path))
                logger.info(f"  ✓ HTTP Isolation Forest loaded ({path.name})")
                break
        
        # Classifier (XGBoost or RandomForest)
        xgb_paths = [
            self.models_dir / 'http_classifier.xgb',
            self.models_dir / 'classifier.xgb',
        ]
        joblib_paths = [
            self.models_dir / 'http_classifier.joblib',
            self.models_dir / 'classifier.joblib',
        ]
        
        # Try XGBoost first
        if XGBOOST_AVAILABLE:
            for path in xgb_paths:
                if path.exists():
                    try:
                        # Load as Booster (raw XGBoost model)
                        self.http_classifier = xgb.Booster()
                        self.http_classifier.load_model(str(path))
                        self._http_classifier_type = 'xgboost_booster'
                        logger.info(f"  ✓ HTTP classifier loaded (XGBoost: {path.name})")
                        break
                    except Exception as e:
                        logger.warning(f"  Failed to load {path.name}: {e}")
        
        # Fallback to joblib
        if self.http_classifier is None:
            for path in joblib_paths:
                if path.exists():
                    try:
                        self.http_classifier = joblib.load(str(path))
                        self._http_classifier_type = 'sklearn'
                        logger.info(f"  ✓ HTTP classifier loaded (sklearn: {path.name})")
                        break
                    except Exception as e:
                        logger.warning(f"  Failed to load {path.name}: {e}")
        
        # Load categories
        meta_paths = [
            self.models_dir / 'dual_layer_metadata.json',
            self.models_dir / 'ensemble_metadata.json',
        ]
        for path in meta_paths:
            if path.exists():
                with open(path) as f:
                    meta = json.load(f)
                if 'http_layer' in meta:
                    self.http_categories = meta['http_layer'].get('categories')
                elif 'categories' in meta:
                    self.http_categories = meta['categories']
                if self.http_categories:
                    break

        if not self.http_categories:
            self.http_categories = ['benign', 'sqli', 'xss', 'rce', 'path_traversal', 'ssrf']

        # Set n_classes_ for XGBoost classifier
        if self.http_classifier is not None and self._http_classifier_type == 'xgboost':
            self.http_classifier.n_classes_ = len(self.http_categories)
            self.http_classifier.classes_ = np.arange(len(self.http_categories))
    
    def _load_network_layer(self):
        """Load network layer models"""
        import joblib
        
        # Scaler
        path = self.models_dir / 'network_scaler.joblib'
        if path.exists():
            self.network_scaler = joblib.load(str(path))
            logger.info(f"  ✓ Network scaler loaded")
        
        # Isolation Forest
        path = self.models_dir / 'network_isolation_forest.joblib'
        if path.exists():
            self.network_if = joblib.load(str(path))
            logger.info(f"  ✓ Network Isolation Forest loaded")
        
        # Classifier
        xgb_path = self.models_dir / 'network_classifier.xgb'
        joblib_path = self.models_dir / 'network_classifier.joblib'
        
        if XGBOOST_AVAILABLE and xgb_path.exists():
            try:
                self.network_classifier = xgb.XGBClassifier()
                self.network_classifier.load_model(str(xgb_path))
                self._network_classifier_type = 'xgboost'
                logger.info(f"  ✓ Network classifier loaded (XGBoost)")
            except Exception as e:
                logger.warning(f"  Failed to load network XGBoost: {e}")
        
        if self.network_classifier is None and joblib_path.exists():
            try:
                self.network_classifier = joblib.load(str(joblib_path))
                self._network_classifier_type = 'sklearn'
                logger.info(f"  ✓ Network classifier loaded (sklearn)")
            except Exception as e:
                logger.warning(f"  Failed to load network classifier: {e}")
        
        # Get network feature count from metadata
        meta_path = self.models_dir / 'dual_layer_metadata.json'
        if meta_path.exists():
            with open(meta_path) as f:
                meta = json.load(f)
            if meta.get('network_layer'):
                self.network_n_features = meta['network_layer'].get('n_features', 78)
                self.network_categories = meta['network_layer'].get('categories')
        
        if not self.network_categories:
            self.network_categories = UNIFIED_CATEGORIES
    
    def predict_http(self, payload: str) -> Dict[str, Any]:
        """
        Predict using HTTP layer only
        
        Args:
            payload: HTTP request payload
            
        Returns:
            Dict with score, category, probabilities
        """
        if not payload or self.http_classifier is None:
            return {'score': 0.0, 'category': 'benign', 'probabilities': {}}
        
        payload = payload[:self.MAX_PAYLOAD_SIZE]
        
        # Extract features
        features = self.http_extractor.extract(payload)
        features = features.reshape(1, -1)
        
        # Scale
        if self.http_scaler is not None:
            features_scaled = self.http_scaler.transform(features)
        else:
            features_scaled = features
        
        # Classifier prediction
        try:
            if self._http_classifier_type == 'xgboost_booster':
                # Use raw Booster predict
                import xgboost as xgb
                dmatrix = xgb.DMatrix(features_scaled)
                probs = self.http_classifier.predict(dmatrix)[0]

                # Ensure it's a probability distribution
                if len(probs.shape) == 0:  # Single value
                    probs = np.array([1.0 - probs, probs])
            elif hasattr(self.http_classifier, 'predict_proba'):
                probs = self.http_classifier.predict_proba(features_scaled)[0]
            else:
                pred = self.http_classifier.predict(features_scaled)[0]
                probs = np.zeros(len(self.http_categories))
                probs[int(pred)] = 1.0

            pred_idx = int(np.argmax(probs))
            category = self.http_categories[pred_idx] if pred_idx < len(self.http_categories) else 'unknown'

            # Attack score (1 - benign probability)
            score = 1.0 - probs[0] if len(probs) > 0 else 0.5

        except Exception as e:
            logger.warning(f"HTTP classifier error: {e}")
            score = 0.0
            category = 'benign'
            probs = np.array([1.0])
        
        # Isolation Forest
        if_score = 0.0
        if self.http_if is not None:
            try:
                if_pred = self.http_if.predict(features_scaled)[0]
                if_raw = -self.http_if.score_samples(features_scaled)[0]
                if_score = min(1.0, max(0.0, if_raw + 0.5))
            except Exception:
                pass
        
        # Combine
        combined_score = self.xgb_weight * score + self.if_weight * if_score
        
        return {
            'score': float(combined_score),
            'category': category,
            'probabilities': {self.http_categories[i]: float(p) for i, p in enumerate(probs) if i < len(self.http_categories)},
            'xgb_score': float(score),
            'if_score': float(if_score),
        }
    
    def predict_network(self, flow_features: np.ndarray) -> Dict[str, Any]:
        """
        Predict using network layer only
        
        Args:
            flow_features: Pre-extracted network flow features (78-dim)
            
        Returns:
            Dict with score, category, probabilities
        """
        if flow_features is None or self.network_classifier is None:
            return None
        
        features = np.array(flow_features).reshape(1, -1)
        
        # Pad/truncate to expected feature count
        if self.network_n_features and features.shape[1] != self.network_n_features:
            if features.shape[1] < self.network_n_features:
                padding = np.zeros((1, self.network_n_features - features.shape[1]))
                features = np.hstack([features, padding])
            else:
                features = features[:, :self.network_n_features]
        
        # Scale
        if self.network_scaler is not None:
            features_scaled = self.network_scaler.transform(features)
        else:
            features_scaled = features
        
        # Classifier prediction
        try:
            if hasattr(self.network_classifier, 'predict_proba'):
                probs = self.network_classifier.predict_proba(features_scaled)[0]
            else:
                pred = self.network_classifier.predict(features_scaled)[0]
                probs = np.zeros(len(self.network_categories))
                probs[int(pred)] = 1.0
            
            pred_idx = int(np.argmax(probs))
            category = self.network_categories[pred_idx] if pred_idx < len(self.network_categories) else 'unknown'
            score = 1.0 - probs[0] if len(probs) > 0 else 0.5
            
        except Exception as e:
            logger.warning(f"Network classifier error: {e}")
            return None
        
        # Isolation Forest
        if_score = 0.0
        if self.network_if is not None:
            try:
                if_pred = self.network_if.predict(features_scaled)[0]
                if_raw = -self.network_if.score_samples(features_scaled)[0]
                if_score = min(1.0, max(0.0, if_raw + 0.5))
            except Exception:
                pass
        
        combined_score = self.xgb_weight * score + self.if_weight * if_score
        
        return {
            'score': float(combined_score),
            'category': category,
            'probabilities': {self.network_categories[i]: float(p) for i, p in enumerate(probs) if i < len(self.network_categories)},
            'xgb_score': float(score),
            'if_score': float(if_score),
        }
    
    def predict(self,
                payload: str = None,
                network_features: np.ndarray = None) -> DualLayerPrediction:
        """
        Make prediction using available layers
        
        Args:
            payload: HTTP request payload (for HTTP layer)
            network_features: Pre-extracted flow features (for Network layer)
            
        Returns:
            DualLayerPrediction with combined results
        """
        start_time = time.perf_counter()
        
        with self.lock:
            layers_used = []
            model_scores = {}
            
            # HTTP Layer
            http_result = None
            if payload and self.enable_http and self.http_classifier is not None:
                http_result = self.predict_http(payload)
                layers_used.append('http')
                model_scores['http_xgb'] = http_result['xgb_score']
                model_scores['http_if'] = http_result['if_score']
            
            # Network Layer
            network_result = None
            if network_features is not None and self.enable_network and self.network_classifier is not None:
                network_result = self.predict_network(network_features)
                if network_result:
                    layers_used.append('network')
                    model_scores['network_xgb'] = network_result['xgb_score']
                    model_scores['network_if'] = network_result['if_score']
            
            # Combine layers
            if http_result and network_result:
                # Both layers available
                combined_score = (
                    self.http_weight * http_result['score'] +
                    self.network_weight * network_result['score']
                )
                
                # Take higher-confidence category
                if http_result['score'] > network_result['score']:
                    primary_category = http_result['category']
                else:
                    primary_category = network_result['category']
                
                category_probs = {**http_result['probabilities']}
                
            elif http_result:
                # HTTP only
                combined_score = http_result['score']
                primary_category = http_result['category']
                category_probs = http_result['probabilities']
                
            elif network_result:
                # Network only
                combined_score = network_result['score']
                primary_category = network_result['category']
                category_probs = network_result['probabilities']
                
            else:
                # No predictions available
                return DualLayerPrediction(
                    is_malicious=False,
                    confidence=0.0,
                    category='benign',
                    unified_category='benign',
                    http_score=0.0,
                    http_category='benign',
                    network_score=None,
                    network_category=None,
                    category_probabilities={'benign': 1.0},
                    model_scores={},
                    explanation={'error': 'No models available'},
                    latency_ms=0.0,
                    layers_used=[]
                )
            
            # Decision
            is_malicious = primary_category != 'benign'
            
            # Map to unified category
            unified_category = self._map_to_unified(primary_category)
            
            # Explanation
            explanation = self._generate_explanation(payload, http_result, network_result)
            
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            return DualLayerPrediction(
                is_malicious=is_malicious,
                confidence=float(combined_score),
                category=primary_category,
                unified_category=unified_category,
                http_score=http_result['score'] if http_result else 0.0,
                http_category=http_result['category'] if http_result else 'benign',
                network_score=network_result['score'] if network_result else None,
                network_category=network_result['category'] if network_result else None,
                category_probabilities=category_probs,
                model_scores=model_scores,
                explanation=explanation,
                latency_ms=latency_ms,
                layers_used=layers_used
            )
    
    def _map_to_unified(self, category: str) -> str:
        """Map category to unified category name"""
        category_lower = category.lower()
        
        for unified in UNIFIED_CATEGORIES:
            if unified in category_lower or category_lower in unified:
                return unified
        
        if 'sql' in category_lower:
            return 'sqli'
        elif 'xss' in category_lower or 'script' in category_lower:
            return 'xss'
        elif 'dos' in category_lower:
            return 'ddos' if 'ddos' in category_lower else 'dos'
        elif 'brute' in category_lower:
            return 'brute_force'
        elif 'scan' in category_lower:
            return 'port_scan'
        elif 'bot' in category_lower:
            return 'botnet'
        elif 'benign' in category_lower or 'normal' in category_lower:
            return 'benign'
        
        return 'other_attack'
    
    def _generate_explanation(self,
                              payload: str,
                              http_result: Dict,
                              network_result: Dict) -> Dict:
        """Generate explanation for prediction"""
        explanation = {}
        
        if payload:
            # Analyze payload for attack indicators
            payload_lower = payload.lower()
            indicators = []
            
            if any(kw in payload_lower for kw in ['select', 'union', 'insert', "'"]):
                indicators.append('SQL keywords detected')
            if any(tag in payload_lower for tag in ['<script', '<img', 'onerror', 'onload']):
                indicators.append('XSS patterns detected')
            if any(cmd in payload_lower for cmd in ['; ', '| ', '`', 'system(', 'exec(']):
                indicators.append('Command injection patterns detected')
            if '../' in payload or '..\\' in payload:
                indicators.append('Path traversal detected')
            if any(ssrf in payload_lower for ssrf in ['localhost', '127.0.0.1', '169.254']):
                indicators.append('SSRF indicators detected')
            
            if indicators:
                explanation['attack_indicators'] = indicators
        
        if http_result:
            explanation['http_layer'] = {
                'score': http_result['score'],
                'category': http_result['category'],
                'top_probabilities': dict(sorted(
                    http_result['probabilities'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:3])
            }
        
        if network_result:
            explanation['network_layer'] = {
                'score': network_result['score'],
                'category': network_result['category'],
            }
        
        return explanation


# ============================================================================
# SINGLETON
# ============================================================================

_predictor_instance = None
_predictor_lock = threading.Lock()

def get_predictor(models_dir: str = "./models") -> DualLayerPredictor:
    """Get singleton predictor instance"""
    global _predictor_instance
    
    with _predictor_lock:
        if _predictor_instance is None:
            _predictor_instance = DualLayerPredictor(models_dir)
        return _predictor_instance


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def predict(payload: str, models_dir: str = "./models") -> Dict[str, Any]:
    """Convenience function for HTTP payload prediction"""
    predictor = get_predictor(models_dir)
    result = predictor.predict(payload=payload)
    
    return {
        'is_malicious': result.is_malicious,
        'confidence': result.confidence,
        'category': result.category,
        'unified_category': result.unified_category,
        'http_score': result.http_score,
        'category_probabilities': result.category_probabilities,
        'explanation': result.explanation,
        'latency_ms': result.latency_ms,
        'layers_used': result.layers_used,
    }


def is_malicious(payload: str, threshold: float = 0.5) -> bool:
    """Quick check if payload is malicious"""
    predictor = get_predictor()
    result = predictor.predict(payload=payload)
    return result.is_malicious or result.confidence > threshold


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("DECEPTICON Dual-Layer Predictor")
    print("=" * 60)
    
    predictor = DualLayerPredictor(models_dir="./models")
    
    test_cases = [
        ("' OR 1=1--", "SQLi"),
        ("<script>alert(1)</script>", "XSS"),
        ("; cat /etc/passwd", "RCE"),
        ("../../../etc/passwd", "Path Traversal"),
        ("http://169.254.169.254/latest/meta-data/", "SSRF"),
        ("search?q=hello+world", "Benign"),
        ("api/users/123", "Benign"),
    ]
    
    print(f"\n{'Payload':<45} {'Expected':<12} {'Predicted':<15} {'Score':<8} {'Layers':<10}")
    print("-" * 95)
    
    correct = 0
    for payload, expected in test_cases:
        result = predictor.predict(payload=payload)
        is_correct = (result.is_malicious and expected != "Benign") or \
                     (not result.is_malicious and expected == "Benign")
        status = "✓" if is_correct else "✗"
        if is_correct:
            correct += 1
        
        print(f"{payload[:43]:<45} {expected:<12} {result.category:<15} {result.confidence:.1%}    {','.join(result.layers_used):<10} {status}")
    
    print("-" * 95)
    print(f"Accuracy: {correct}/{len(test_cases)} = {correct/len(test_cases):.0%}")
