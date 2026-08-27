"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  LEGACY — BROKEN ON PURPOSE-KEPT.  See ../LEGACY.md                          ║
║                                                                              ║
║  This module returns  malicious=True confidence=0.992  for EVERY input,       ║
║  including benign traffic — verified, reproducible in one command (LEGACY.md).║
║  Cause: it computes a DIFFERENT 50-feature vector than the trainer did, and   ║
║  never applies the scaler, so the model sees out-of-distribution input and    ║
║  collapses to a near-constant.                                               ║
║                                                                              ║
║  The live serving path is  ml/detector_v2.py, which shares one feature module ║
║  (ml/canonical_features.py) with training, making skew structurally           ║
║  impossible. Do NOT use this module for inference.                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

DECEPTICON Secure ML Inference (legacy)
FIXES: Remote Code Execution via Pickle Deserialization (CRITICAL)

THIS MODULE REPLACES ml/inference.py

SECURITY MEASURES:
1. NO PICKLE - Uses ONNX or numpy-only formats
2. Model signature verification before loading
3. Size and path validation
4. Safe feature extraction
"""
import os
import json
import time
import hashlib
import logging
import pickle
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("decepticon.ml.secure_inference")

# --- train/serve feature contract -------------------------------------------
# This module's own 50-dim vector (binary has_* flags, no headers) is NOT the
# vector the trainers produce; that divergence is the documented cause of the
# recall collapse (see the banner above and ../LEGACY.md). SafeFeatureExtractor
# now defaults to the canonical contract shared with training, and every contract
# is hashed so a mismatch is machine-detectable instead of silent.
from ml.canonical_features import lexical_features, LEXICAL_FEATURE_NAMES  # noqa: E402


def _contract_hash(names) -> str:
    """Same formula as ml/detector_v2.serving_contract_hash()."""
    return hashlib.sha256(",".join(names).encode()).hexdigest()[:16]


CANONICAL_CONTRACT_HASH = _contract_hash(LEXICAL_FEATURE_NAMES)


# ============================================================================
# SECURITY ERROR
# ============================================================================

class ModelSecurityError(Exception):
    """Security violation in model loading"""
    pass


class RestrictedUnpickler(pickle.Unpickler):
    """
    A safe unpickler that only allows a strict allowlist of modules and classes.
    This prevents Remote Code Execution (RCE) via malicious pickle files.
    """
    SAFE_MODULES = {
        'numpy', 'numpy.core.multiarray', 'numpy.core', 'numpy.dtype',
        'sklearn', 'sklearn.ensemble', 'sklearn.tree', 'sklearn.linear_model',
        'sklearn.svm', 'sklearn.neighbors', 'sklearn.preprocessing',
        'joblib', 'collections'
    }

    def find_class(self, module, name):
        # Only allow modules in our allowlist
        if module.split('.')[0] in self.SAFE_MODULES or module in self.SAFE_MODULES:
            return super().find_class(module, name)

        # For everything else, raise a security error
        raise ModelSecurityError(f"Security Violation: Deserialization of '{module}.{name}' is forbidden")


# ============================================================================
# SECURE MODEL FORMATS
# ============================================================================

@dataclass
class ModelPrediction:
    """Prediction result from ML model"""
    is_malicious: bool
    confidence: float
    category: str
    features_used: int
    attack_probabilities: Dict[str, float] = None  # Optional: probabilities per attack type
    # Enforcement contract, mirroring ml/detector_v2.MLResult.enforce. This legacy
    # module never proves a train/serve contract match, so it is always False:
    # callers may LOG these verdicts but must not BLOCK on them.
    enforce: bool = False
    enforce_reason: str = "legacy inference path — shadow only, never enforce"

    def __post_init__(self):
        if self.attack_probabilities is None:
            self.attack_probabilities = {}
        # Defence in depth: no code path may flip this on.
        self.enforce = False


class SecureModelFormat:
    """
    Safe model storage format using only numpy arrays
    
    Structure:
    - model_params.npz: Numpy arrays for model parameters
    - model_meta.json: Model metadata (type, features, classes)
    - model_sig.json: HMAC signature for verification
    """
    
    ALLOWED_EXTENSIONS = {'.npz', '.json', '.onnx'}
    MAX_MODEL_SIZE = 100 * 1024 * 1024  # 100MB
    
    def __init__(self, models_dir: str = "./models", signing_key: bytes = None):
        self.models_dir = Path(models_dir)
        self.signing_key = signing_key or os.environ.get('MODEL_SIGNING_KEY', '').encode() or os.urandom(32)
    
    def verify_and_load(self, model_name: str) -> Dict[str, Any]:
        """
        Securely load model with verification
        
        Returns: Model parameters dict
        """
        params_path = self.models_dir / f"{model_name}_params.npz"
        meta_path = self.models_dir / f"{model_name}_meta.json"
        sig_path = self.models_dir / f"{model_name}_sig.json"
        
        # Security check 1: Path validation
        for path in [params_path, meta_path]:
            self._validate_path(path)
        
        # Security check 2: File size
        for path in [params_path, meta_path]:
            if path.exists() and path.stat().st_size > self.MAX_MODEL_SIZE:
                raise ModelSecurityError(f"Model file too large: {path}")
        
        # Security check 3: Signature verification (if sig exists)
        if sig_path.exists():
            if not self._verify_signature(params_path, meta_path, sig_path):
                raise ModelSecurityError("Model signature verification failed!")
        else:
            logger.warning(f"No signature file for {model_name} - consider signing models")
        
        # Load parameters (safe - no pickle!)
        if params_path.exists():
            params = dict(np.load(str(params_path), allow_pickle=False))
        else:
            params = {}
        
        # Load metadata
        if meta_path.exists():
            with open(meta_path, 'r') as f:
                meta = json.load(f)
        else:
            meta = {}
        
        return {**params, **meta}
    
    def _validate_path(self, path: Path):
        """Validate path is within models directory"""
        try:
            path.resolve().relative_to(self.models_dir.resolve())
        except ValueError:
            raise ModelSecurityError(f"Path traversal detected: {path}")
    
    def _verify_signature(self, params_path: Path, meta_path: Path, sig_path: Path) -> bool:
        """Verify HMAC signature of model files"""
        import hmac
        
        try:
            with open(sig_path, 'r') as f:
                sig_data = json.load(f)
            
            # Compute hash of files
            hasher = hashlib.sha256()
            
            if params_path.exists():
                with open(params_path, 'rb') as f:
                    hasher.update(f.read())
            
            if meta_path.exists():
                with open(meta_path, 'rb') as f:
                    hasher.update(f.read())
            
            file_hash = hasher.hexdigest()
            
            # Verify HMAC
            expected_sig = hmac.new(self.signing_key, file_hash.encode(), hashlib.sha256).hexdigest()
            
            return hmac.compare_digest(expected_sig, sig_data.get("signature", ""))
            
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False
    
    def sign_model(self, model_name: str):
        """Create signature for model files"""
        import hmac
        
        params_path = self.models_dir / f"{model_name}_params.npz"
        meta_path = self.models_dir / f"{model_name}_meta.json"
        sig_path = self.models_dir / f"{model_name}_sig.json"
        
        hasher = hashlib.sha256()
        
        if params_path.exists():
            with open(params_path, 'rb') as f:
                hasher.update(f.read())
        
        if meta_path.exists():
            with open(meta_path, 'rb') as f:
                hasher.update(f.read())
        
        file_hash = hasher.hexdigest()
        signature = hmac.new(self.signing_key, file_hash.encode(), hashlib.sha256).hexdigest()
        
        sig_data = {
            "signature": signature,
            "file_hash": file_hash,
            "timestamp": time.time(),
            "algorithm": "HMAC-SHA256"
        }
        
        with open(sig_path, 'w') as f:
            json.dump(sig_data, f)
        
        logger.info(f"Signed model: {model_name}")


# ============================================================================
# SAFE FEATURE EXTRACTION
# ============================================================================

class SafeFeatureExtractor:
    """
    Extract features from request data safely

    No arbitrary code execution, bounded operations.

    Two contracts:
      - "canonical" (DEFAULT): delegates to ml.canonical_features.lexical_features,
        i.e. the SAME code the trainers use. Choosing this by default is the fix for
        train/serve skew — this class used to compute a divergent vector (binary
        has_* flags, headers excluded) while training computed integer counts over
        path+query+body+headers.
      - "legacy": the historical divergent vector, kept only so an artifact that was
        genuinely trained against it can still be scored. It is skewed w.r.t. every
        current trainer and callers must treat its output as non-enforceable.

    `contract_hash` identifies the vector; compare it to the hash the model artifact
    recorded at training time before acting on any score.
    """

    # Feature limits
    MAX_INPUT_LENGTH = 100000
    MAX_FEATURES = 100

    def __init__(self, contract: str = "canonical"):
        if contract not in ("canonical", "legacy"):
            raise ValueError(f"unknown feature contract: {contract!r}")
        self.contract = contract
        self.is_canonical = contract == "canonical"
        self.legacy_feature_names = self._legacy_feature_names()
        if self.is_canonical:
            self.feature_names = list(LEXICAL_FEATURE_NAMES)
        else:
            self.feature_names = list(self.legacy_feature_names)
            logger.warning(
                "SafeFeatureExtractor(contract='legacy') — this vector diverges from "
                "training (ml/canonical_features.py). Scores from it are NOT calibrated.")
        self.contract_hash = _contract_hash(self.feature_names)

    @staticmethod
    def _legacy_feature_names():
        return [
            # Length features (4)
            "total_length",
            "query_length",
            "body_length",
            "path_length",

            # Character ratio features (4)
            "special_char_ratio",
            "digit_ratio",
            "uppercase_ratio",
            "whitespace_ratio",

            # Specific character counts (13)
            "quote_count",
            "angle_bracket_count",
            "semicolon_count",
            "pipe_count",
            "backtick_count",
            "slash_count",
            "dot_count",
            "equals_count",
            "ampersand_count",
            "percent_count",
            "hash_count",
            "at_sign_count",
            "dollar_count",

            # Pattern indicators - SQL (7)
            "has_sql_keywords",
            "has_union",
            "has_select",
            "has_insert",
            "has_update",
            "has_delete",
            "has_drop",

            # Pattern indicators - XSS (8)
            "has_script_tag",
            "has_iframe",
            "has_onerror",
            "has_onload",
            "has_eval",
            "has_alert",
            "has_document",
            "has_cookie",

            # Pattern indicators - RCE (3)
            "has_cmd",
            "has_bash",
            "has_exec",

            # Pattern indicators - Other (6)
            "has_traversal",
            "has_encoded_chars",
            "has_base64",
            "has_decode",
            "has_unescape",
            "url_encoded_count",

            # Entropy (1)
            "entropy",

            # Padding to reach 50 (4 more)
            "paren_count",
            "curly_brace_count",
            "square_bracket_count",
            "colon_count",
        ]
    
    def extract(self,
                query = "",
                body: str = "",
                path: str = "",
                headers: Dict = None) -> np.ndarray:
        """
        Extract features from request, using this instance's feature contract.

        Args:
            query: Either a RequestContext object or query string
            body: Body string (ignored if query is RequestContext)
            path: Path string (ignored if query is RequestContext)
            headers: Headers dict (ignored if query is RequestContext)

        Returns: numpy array of features (contract == self.contract)
        """
        method = "GET"
        # Handle RequestContext object
        if hasattr(query, 'query_string'):
            # query is actually a RequestContext object
            ctx = query
            query = ctx.query_string if ctx.query_string else ""
            body = ctx.body_str if ctx.body_str else ""
            path = ctx.path if ctx.path else ""
            headers = ctx.headers if ctx.headers else {}
            method = getattr(ctx, "method", "GET") or "GET"

        # Enforce length limits (DoS protection)
        query = str(query)[:self.MAX_INPUT_LENGTH]
        body = str(body)[:self.MAX_INPUT_LENGTH]
        path = str(path)[:self.MAX_INPUT_LENGTH]
        if not isinstance(headers, dict):
            headers = {}

        if self.is_canonical:
            # ONE extractor shared with training — skew is structurally impossible.
            return lexical_features(method, path, query, body, headers)
        return self._extract_legacy(query, body, path)

    def _extract_legacy(self, query: str, body: str, path: str) -> np.ndarray:
        """The historical, divergent 50-dim vector. Retained for artifacts trained
        against it; NOT compatible with anything trained on canonical_features."""
        combined = f"{path} {query} {body}".lower()

        features = []

        # Length features (4)
        features.append(len(combined))
        features.append(len(query))
        features.append(len(body))
        features.append(len(path))

        # Character ratio features (4)
        if len(combined) > 0:
            features.append(sum(1 for c in combined if not c.isalnum() and not c.isspace()) / len(combined))
            features.append(sum(1 for c in combined if c.isdigit()) / len(combined))
            features.append(sum(1 for c in combined if c.isupper()) / len(combined))
            features.append(sum(1 for c in combined if c.isspace()) / len(combined))
        else:
            features.extend([0, 0, 0, 0])

        # Specific character counts (13)
        features.append(combined.count("'") + combined.count('"'))  # quote_count
        features.append(combined.count("<") + combined.count(">"))  # angle_bracket_count
        features.append(combined.count(";"))  # semicolon_count
        features.append(combined.count("|"))  # pipe_count
        features.append(combined.count("`"))  # backtick_count
        features.append(combined.count("/"))  # slash_count
        features.append(combined.count("."))  # dot_count
        features.append(combined.count("="))  # equals_count
        features.append(combined.count("&"))  # ampersand_count
        features.append(combined.count("%"))  # percent_count
        features.append(combined.count("#"))  # hash_count
        features.append(combined.count("@"))  # at_sign_count
        features.append(combined.count("$"))  # dollar_count

        # Pattern indicators - SQL (7)
        sql_keywords = ["select", "union", "insert", "update", "delete", "drop", "exec"]
        features.append(1 if any(kw in combined for kw in sql_keywords) else 0)  # has_sql_keywords
        features.append(1 if "union" in combined else 0)  # has_union
        features.append(1 if "select" in combined else 0)  # has_select
        features.append(1 if "insert" in combined else 0)  # has_insert
        features.append(1 if "update" in combined else 0)  # has_update
        features.append(1 if "delete" in combined else 0)  # has_delete
        features.append(1 if "drop" in combined else 0)  # has_drop

        # Pattern indicators - XSS (8)
        features.append(1 if "<script" in combined or "javascript:" in combined else 0)  # has_script_tag
        features.append(1 if "<iframe" in combined else 0)  # has_iframe
        features.append(1 if "onerror" in combined else 0)  # has_onerror
        features.append(1 if "onload" in combined else 0)  # has_onload
        features.append(1 if "eval(" in combined else 0)  # has_eval
        features.append(1 if "alert(" in combined else 0)  # has_alert
        features.append(1 if "document." in combined else 0)  # has_document
        features.append(1 if "cookie" in combined else 0)  # has_cookie

        # Pattern indicators - RCE (3)
        features.append(1 if "cmd" in combined or "/bin/" in combined else 0)  # has_cmd
        features.append(1 if "bash" in combined or "sh -c" in combined else 0)  # has_bash
        features.append(1 if "exec" in combined else 0)  # has_exec

        # Pattern indicators - Other (6)
        features.append(1 if "../" in combined or "..\\" in combined else 0)  # has_traversal
        features.append(1 if "%" in combined else 0)  # has_encoded_chars
        features.append(1 if "base64" in combined else 0)  # has_base64
        features.append(1 if "decode" in combined or "atob(" in combined else 0)  # has_decode
        features.append(1 if "unescape" in combined else 0)  # has_unescape
        features.append(combined.count("%"))  # url_encoded_count

        # Entropy (1)
        features.append(self._calculate_entropy(combined))

        # Padding to reach 50 (4)
        features.append(combined.count("(") + combined.count(")"))  # paren_count
        features.append(combined.count("{") + combined.count("}"))  # curly_brace_count
        features.append(combined.count("[") + combined.count("]"))  # square_bracket_count
        features.append(combined.count(":"))  # colon_count

        return np.array(features, dtype=np.float32)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy


# ============================================================================
# SECURE ML PREDICTOR
# ============================================================================

class SecureMLPredictor:
    """
    Secure ML prediction without pickle
    
    Options:
    1. ONNX Runtime (recommended for production)
    2. Simple threshold-based model (fallback)
    3. Numpy-only model (for simple cases)
    """
    
    # Logical signal -> feature name under each contract. Lets the fallback model
    # address features BY NAME instead of by hardcoded index (the old code indexed
    # 13/14/15/17 as has_sql_keywords/has_script_tag/has_traversal/entropy, which
    # were actually slash/dot/equals/percent counts — a silent mis-scoring bug).
    _SIGNAL_FEATURES = {
        "canonical": {"special_char_ratio": "r_special", "entropy": "ent_total",
                      "quote_count": "n_quote", "angle_bracket_count": "n_angle",
                      "sql": "c_sql", "xss": "c_xss", "traversal": "c_traversal"},
        "legacy": {"special_char_ratio": "special_char_ratio", "entropy": "entropy",
                   "quote_count": "quote_count", "angle_bracket_count": "angle_bracket_count",
                   "sql": "has_sql_keywords", "xss": "has_script_tag",
                   "traversal": "has_traversal"},
    }

    def __init__(self, models_dir: str = "./models", contract: str = "canonical"):
        self.models_dir = Path(models_dir)
        self.model_format = SecureModelFormat(models_dir)
        self.feature_extractor = SafeFeatureExtractor(contract=contract)
        names = self.feature_extractor.feature_names
        self._idx = {sig: names.index(fname)
                     for sig, fname in self._SIGNAL_FEATURES[contract].items()
                     if fname in names}

        # Enforcement posture. This module is the LEGACY path: its artifacts carry
        # no feature-contract hash, so nothing it produces has a proven train/serve
        # match and nothing it produces may be blocked on. Predictions are
        # shadow-only (ModelPrediction.enforce is always False). Use
        # ml/detector_v2.py for any enforcing deployment.
        self.contract_verified = False
        self.enforceable = False

        # Model state
        self.model = None
        self.model_type = None
        self.thresholds = {}

        # Performance metrics
        self._cache_hits = 0
        self._cache_misses = 0
        self._total_latency_ms = 0.0
        self._prediction_count = 0
        
        # Try to load model
        self._load_model()
    
    @property
    def cache_hit_rate(self) -> float:
        """Return cache hit rate (0.0 if no caching implemented)"""
        total = self._cache_hits + self._cache_misses
        return self._cache_hits / total if total > 0 else 0.0
    
    @property
    def avg_latency_ms(self) -> float:
        """Return average prediction latency in milliseconds"""
        return self._total_latency_ms / self._prediction_count if self._prediction_count > 0 else 0.0
    
    def _load_model(self):
        """Load model using safe methods only"""

        # Option 1: Try trained ONNX model (safest for production)
        onnx_path = self.models_dir / "http_classifier.onnx"
        if onnx_path.exists():
            self._load_onnx_model(onnx_path)
            return

        # Fallback: Try old classifier.onnx name for backward compatibility
        onnx_path_old = self.models_dir / "classifier.onnx"
        if onnx_path_old.exists():
            logger.warning("Using legacy classifier.onnx - please rename to http_classifier.onnx")
            self._load_onnx_model(onnx_path_old)
            return

        # Option 2: Try numpy-based model
        numpy_model = self.models_dir / "classifier_params.npz"
        if numpy_model.exists():
            self._load_numpy_model()
            return

        # Option 3: Use threshold-based fallback
        logger.warning("No ML model found - using threshold-based detection")
        self._use_threshold_model()
    
    def _load_onnx_model(self, path: Path):
        """Load ONNX model (safe - no arbitrary code)"""
        try:
            import onnxruntime as ort
            
            # Validate path
            if not str(path.resolve()).startswith(str(self.models_dir.resolve())):
                raise ModelSecurityError("Path traversal detected")
            
            # Validate size
            if path.stat().st_size > 500 * 1024 * 1024:
                raise ModelSecurityError("Model too large")
            
            self.model = ort.InferenceSession(str(path))
            self.model_type = "onnx"
            logger.info(f"Loaded ONNX model: {path}")
            
        except ImportError:
            logger.warning("ONNX Runtime not installed - falling back to threshold model")
            self._use_threshold_model()
        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}")
            self._use_threshold_model()
    
    def _load_numpy_model(self):
        """Load numpy-based model parameters"""
        try:
            params = self.model_format.verify_and_load("classifier")
            
            self.model = {
                "weights": params.get("weights"),
                "bias": params.get("bias"),
                "threshold": params.get("threshold", 0.5),
            }
            self.model_type = "numpy"
            logger.info("Loaded numpy-based model")
            
        except Exception as e:
            logger.error(f"Failed to load numpy model: {e}")
            self._use_threshold_model()
    
    def _use_threshold_model(self):
        """Use simple threshold-based detection"""
        self.model_type = "threshold"
        self.thresholds = {
            "special_char_ratio": 0.3,
            "entropy": 4.5,
            "quote_count": 5,
            "angle_bracket_count": 3,
        }
        logger.info("Using threshold-based detection")
    
    def predict(self,
                query: str = "",
                body: str = "",
                path: str = "",
                headers: Dict = None) -> ModelPrediction:
        """
        Make prediction on request data
        """
        import time
        start_time = time.perf_counter()
        
        # Extract features
        features = self.feature_extractor.extract(query, body, path, headers)
        
        # Predict based on model type
        if self.model_type == "onnx":
            result = self._predict_onnx(features)
        elif self.model_type == "numpy":
            result = self._predict_numpy(features)
        else:
            result = self._predict_threshold(features)
        
        # Track latency metrics
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        self._total_latency_ms += elapsed_ms
        self._prediction_count += 1
        self._cache_misses += 1  # No caching implemented yet
        
        return result
    
    def _predict_onnx(self, features: np.ndarray) -> ModelPrediction:
        """ONNX model prediction"""
        try:
            input_name = self.model.get_inputs()[0].name
            outputs = self.model.run(None, {input_name: features.reshape(1, -1)})

            # XGBoost ONNX format: [predicted_class, [probabilities_dict]]
            if isinstance(outputs, list) and len(outputs) == 2:
                predicted_class = int(outputs[0][0])
                probs_list = outputs[1]

                # Class 0 = benign, others = attacks
                is_malicious = predicted_class > 0

                # Extract probabilities dict (may be wrapped in a list)
                if isinstance(probs_list, list) and len(probs_list) > 0:
                    probs_dict = probs_list[0]
                elif isinstance(probs_list, dict):
                    probs_dict = probs_list
                else:
                    probs_dict = {}

                # Get confidence as sum of all attack class probabilities
                if isinstance(probs_dict, dict):
                    # Sum all non-benign class probabilities
                    attack_prob = sum(v for k, v in probs_dict.items() if k > 0)
                    probability = attack_prob

                    # Map class IDs to attack names for attack_probabilities
                    class_names = {
                        0: "benign", 1: "sqli", 2: "xss", 3: "rce", 4: "path_traversal",
                        5: "ssrf", 6: "xxe", 7: "ssti", 8: "nosql", 9: "jwt",
                        10: "graphql", 11: "ldap", 12: "deserialization",
                        13: "prototype_pollution", 14: "crlf", 15: "open_redirect"
                    }
                    attack_probabilities = {
                        class_names.get(k, f"class_{k}"): v
                        for k, v in probs_dict.items()
                    }
                else:
                    # Fallback: use predicted class as rough confidence
                    probability = 0.9 if is_malicious else 0.1
                    attack_probabilities = {}

            # Standard format: single output array
            elif isinstance(outputs[0], np.ndarray):
                output = outputs[0]
                if output.ndim == 2 and output.shape[1] > 1:
                    # Multi-class probability output
                    probability = float(output[0][1])
                elif output.ndim == 2:
                    # Single probability output
                    probability = float(output[0][0])
                elif output.ndim == 1:
                    # Flat array
                    probability = float(output[0])
                else:
                    # Scalar
                    probability = float(output)
                is_malicious = probability > 0.5
                attack_probabilities = {}
            else:
                # Fallback
                probability = 0.5
                is_malicious = False
                attack_probabilities = {}

            return ModelPrediction(
                is_malicious=is_malicious,
                confidence=probability,
                category="ML_DETECTION",
                features_used=len(features),
                attack_probabilities=attack_probabilities
            )
        except Exception as e:
            logger.error(f"ONNX prediction error: {e}")
            return self._predict_threshold(features)
    
    def _predict_numpy(self, features: np.ndarray) -> ModelPrediction:
        """Numpy model prediction (simple linear model)"""
        try:
            weights = self.model["weights"]
            bias = self.model["bias"]
            threshold = self.model["threshold"]
            
            # Simple linear prediction
            score = float(np.dot(features, weights) + bias)
            probability = 1 / (1 + np.exp(-score))  # Sigmoid
            
            return ModelPrediction(
                is_malicious=probability > threshold,
                confidence=probability,
                category="ML_DETECTION",
                features_used=len(features)
            )
        except Exception as e:
            logger.error(f"Numpy prediction error: {e}")
            return self._predict_threshold(features)
    
    def _feat(self, features: np.ndarray, signal: str) -> float:
        """Read one logical signal by name under the active feature contract."""
        i = self._idx.get(signal)
        if i is None or i >= len(features):
            return 0.0
        return float(features[i])

    def _predict_threshold(self, features: np.ndarray) -> ModelPrediction:
        """Threshold-based prediction (fallback)"""
        # Simple heuristic based on feature values, addressed by NAME so the
        # contract can change without silently scoring the wrong columns.
        score = 0.0

        if self._feat(features, "special_char_ratio") > self.thresholds.get("special_char_ratio", 0.3):
            score += 0.3

        if self._feat(features, "entropy") > self.thresholds.get("entropy", 4.5):
            score += 0.2

        if self._feat(features, "quote_count") > self.thresholds.get("quote_count", 5):
            score += 0.2

        if self._feat(features, "angle_bracket_count") > self.thresholds.get("angle_bracket_count", 3):
            score += 0.2

        if self._feat(features, "sql") > 0:
            score += 0.3

        if self._feat(features, "xss") > 0:
            score += 0.3

        if self._feat(features, "traversal") > 0:
            score += 0.3

        # Normalize to 0-1
        probability = min(1.0, score)
        
        return ModelPrediction(
            is_malicious=probability > 0.5,
            confidence=probability,
            category="THRESHOLD_DETECTION",
            features_used=len(features)
        )


# ============================================================================
# MODEL CONVERTER (ONE-TIME MIGRATION)
# ============================================================================

def convert_pickle_to_safe(pickle_path: str, output_dir: str, model_name: str = "classifier"):
    """
    ONE-TIME MIGRATION: Convert pickle model to safe format
    
    RUN THIS OFFLINE ON A TRUSTED MACHINE!
    DO NOT USE IN PRODUCTION!
    
    Usage:
        python -c "from ml.secure_inference import convert_pickle_to_safe; \\
                   convert_pickle_to_safe('./models/old.pkl', './models/', 'classifier')"
    """
    import warnings
    warnings.warn(
        "⚠️ SECURITY WARNING: Loading pickle file!\n"
        "Only run this on a trusted model from a trusted source!\n"
        "Run in an isolated environment (VM/container)!",
        UserWarning
    )
    
    confirm = input("Type 'I UNDERSTAND THE RISKS' to continue: ")
    if confirm != "I UNDERSTAND THE RISKS":
        print("Aborted.")
        return
    
    print(f"[!] Loading pickle file: {pickle_path}")
    with open(pickle_path, 'rb') as f:
        # Use RestrictedUnpickler for safety
        model = RestrictedUnpickler(f).load()
    
    output_path = Path(output_dir)
    model_type = type(model).__name__
    
    print(f"[+] Model type: {model_type}")
    
    # Extract parameters based on model type
    if hasattr(model, 'feature_importances_'):
        # Tree-based model (RandomForest, GradientBoosting)
        params = {
            "feature_importances": model.feature_importances_,
        }
        meta = {
            "model_type": model_type,
            "n_features": model.n_features_in_ if hasattr(model, 'n_features_in_') else 0,
            "n_classes": len(model.classes_) if hasattr(model, 'classes_') else 2,
            "classes": model.classes_.tolist() if hasattr(model, 'classes_') else [0, 1],
        }
        
    elif hasattr(model, 'coef_'):
        # Linear model (LogisticRegression, SVM)
        params = {
            "weights": model.coef_.flatten(),
            "bias": model.intercept_.flatten() if hasattr(model, 'intercept_') else np.array([0]),
        }
        meta = {
            "model_type": model_type,
            "n_features": len(model.coef_.flatten()),
            "threshold": 0.5,
        }
        
    else:
        print(f"[-] Don't know how to extract parameters from {model_type}")
        print("[-] Consider exporting to ONNX format instead")
        return
    
    # Save parameters
    np.savez(output_path / f"{model_name}_params.npz", **params)
    print(f"[+] Saved parameters: {output_path / f'{model_name}_params.npz'}")
    
    # Save metadata
    with open(output_path / f"{model_name}_meta.json", 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"[+] Saved metadata: {output_path / f'{model_name}_meta.json'}")
    
    # Sign the model
    model_format = SecureModelFormat(output_dir)
    model_format.sign_model(model_name)
    print(f"[+] Signed model: {model_name}")
    
    print("\n[+] Migration complete!")
    print("[!] DELETE THE ORIGINAL PICKLE FILE!")
    print("[!] Test the new model before deploying!")


def export_to_onnx(sklearn_model, output_path: str, n_features: int):
    """
    Export sklearn model to ONNX format
    
    Requires: skl2onnx
    """
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
        
        initial_type = [('float_input', FloatTensorType([None, n_features]))]
        onnx_model = convert_sklearn(sklearn_model, initial_types=initial_type)
        
        with open(output_path, 'wb') as f:
            f.write(onnx_model.SerializeToString())
        
        print(f"[+] Exported to ONNX: {output_path}")
        
    except ImportError:
        print("[-] skl2onnx not installed. Run: pip install skl2onnx")


# Global instance
secure_ml_predictor = SecureMLPredictor()
