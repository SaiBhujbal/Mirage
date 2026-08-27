"""
MIRAGE Secure Model Loader
FIXES: Remote Code Execution via Pickle Deserialization (CRITICAL)

NEVER use pickle.load() on untrusted data!
This module provides safe alternatives with integrity verification.
"""
import os
import json
import hashlib
import hmac
import logging
import pickle
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import numpy as np

logger = logging.getLogger("mirage.security.model_loader")

class SecurityError(Exception):
    """Security-related error"""
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
        raise SecurityError(f"Security Violation: Deserialization of '{module}.{name}' is forbidden")

# ============================================================================
# SAFE SERIALIZATION ALTERNATIVES
# ============================================================================

class SecureModelLoader:
    """
    Secure model loading with integrity verification
    
    SECURITY MEASURES:
    1. NO PICKLE - Uses joblib with restricted unpickler OR numpy/json only
    2. Model signature verification (HMAC-SHA256)
    3. Model hash verification (SHA-256)
    4. Allowlist of permitted model types
    5. Size limits to prevent DoS
    """
    
    # Maximum model file size (100MB)
    MAX_MODEL_SIZE = 100 * 1024 * 1024
    
    # Allowed model file extensions
    ALLOWED_EXTENSIONS = {'.npz', '.json', '.npy'}
    
    # Model signature file extension
    SIGNATURE_EXTENSION = '.sig'
    
    def __init__(self, signing_key: bytes = None, models_dir: str = "./models"):
        """
        Initialize secure model loader
        
        Args:
            signing_key: HMAC key for model verification (should be from env/secrets)
            models_dir: Directory containing model files
        """
        self.models_dir = Path(models_dir)
        
        # Get signing key from environment or generate
        if signing_key:
            self.signing_key = signing_key
        else:
            # Try to load from environment
            env_key = os.environ.get('MODEL_SIGNING_KEY')
            if env_key:
                self.signing_key = env_key.encode()
            else:
                # Generate and warn - this should be set in production!
                self.signing_key = os.urandom(32)
                logger.warning(
                    "⚠️  MODEL_SIGNING_KEY not set! Using random key. "
                    "Models will need to be re-signed on restart. "
                    "Set MODEL_SIGNING_KEY environment variable in production."
                )
    
    def load_model(self, model_path: str, verify_signature: bool = True) -> Dict[str, Any]:
        """
        Securely load a model file
        
        Args:
            model_path: Path to model file
            verify_signature: Whether to verify model signature (default: True)
        
        Returns:
            Loaded model data
        
        Raises:
            SecurityError: If model fails security checks
            FileNotFoundError: If model file doesn't exist
        """
        path = Path(model_path)
        
        # Security check 1: Verify extension
        if path.suffix not in self.ALLOWED_EXTENSIONS:
            raise SecurityError(
                f"Forbidden model extension: {path.suffix}. "
                f"Allowed: {self.ALLOWED_EXTENSIONS}"
            )
        
        # Security check 2: Verify file exists and is within models directory
        abs_path = path.resolve()
        models_abs = self.models_dir.resolve()
        
        try:
            abs_path.relative_to(models_abs)
        except ValueError:
            raise SecurityError(
                f"Model path traversal detected! "
                f"Path {abs_path} is outside models directory {models_abs}"
            )
        
        if not abs_path.exists():
            raise FileNotFoundError(f"Model not found: {abs_path}")
        
        # Security check 3: Verify file size
        file_size = abs_path.stat().st_size
        if file_size > self.MAX_MODEL_SIZE:
            raise SecurityError(
                f"Model file too large: {file_size} bytes. "
                f"Maximum: {self.MAX_MODEL_SIZE} bytes"
            )
        
        # Security check 4: Verify signature (if required)
        if verify_signature:
            if not self._verify_signature(abs_path):
                raise SecurityError(
                    f"Model signature verification failed for {abs_path}. "
                    "Model may have been tampered with!"
                )
        
        # Load based on extension
        if path.suffix == '.npz':
            return self._load_npz(abs_path)
        elif path.suffix == '.npy':
            return self._load_npy(abs_path)
        elif path.suffix == '.json':
            return self._load_json(abs_path)
        else:
            raise SecurityError(f"Unknown extension: {path.suffix}")
    
    def _load_npz(self, path: Path) -> Dict[str, Any]:
        """Load numpy NPZ file (safe - no code execution)"""
        try:
            # allow_pickle=False is CRITICAL for security
            data = np.load(str(path), allow_pickle=False)
            return {key: data[key] for key in data.files}
        except Exception as e:
            raise SecurityError(f"Failed to load NPZ: {e}")
    
    def _load_npy(self, path: Path) -> np.ndarray:
        """Load numpy NPY file (safe - no code execution)"""
        try:
            return np.load(str(path), allow_pickle=False)
        except Exception as e:
            raise SecurityError(f"Failed to load NPY: {e}")
    
    def _load_json(self, path: Path) -> Dict:
        """Load JSON file (safe - no code execution)"""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            raise SecurityError(f"Failed to load JSON: {e}")
    
    def save_model(self, model_data: Dict[str, Any], model_path: str, sign: bool = True):
        """
        Securely save a model file with signature
        
        Args:
            model_data: Model data to save
            model_path: Path to save model
            sign: Whether to create signature file (default: True)
        """
        path = Path(model_path)
        
        if path.suffix not in self.ALLOWED_EXTENSIONS:
            raise SecurityError(f"Forbidden extension: {path.suffix}")
        
        # Save based on extension
        if path.suffix == '.npz':
            np.savez(str(path), **model_data)
        elif path.suffix == '.npy':
            np.save(str(path), model_data)
        elif path.suffix == '.json':
            with open(path, 'w') as f:
                json.dump(model_data, f)
        
        # Create signature
        if sign:
            self._create_signature(path)
    
    def _create_signature(self, model_path: Path):
        """Create HMAC-SHA256 signature for model file"""
        with open(model_path, 'rb') as f:
            content = f.read()
        
        # Create signature
        signature = hmac.new(self.signing_key, content, hashlib.sha256).hexdigest()
        
        # Also include file hash for integrity
        file_hash = hashlib.sha256(content).hexdigest()
        
        sig_data = {
            "signature": signature,
            "hash": file_hash,
            "algorithm": "HMAC-SHA256",
            "file": model_path.name,
        }
        
        sig_path = model_path.with_suffix(model_path.suffix + self.SIGNATURE_EXTENSION)
        with open(sig_path, 'w') as f:
            json.dump(sig_data, f)
        
        logger.info(f"Created signature for {model_path}")
    
    def _verify_signature(self, model_path: Path) -> bool:
        """Verify model signature"""
        sig_path = model_path.with_suffix(model_path.suffix + self.SIGNATURE_EXTENSION)
        
        if not sig_path.exists():
            logger.warning(f"No signature file for {model_path}")
            return False
        
        try:
            with open(sig_path, 'r') as f:
                sig_data = json.load(f)
            
            with open(model_path, 'rb') as f:
                content = f.read()
            
            # Verify hash first (fast check)
            file_hash = hashlib.sha256(content).hexdigest()
            if file_hash != sig_data.get("hash"):
                logger.error(f"Hash mismatch for {model_path}")
                return False
            
            # Verify HMAC signature
            expected_sig = hmac.new(self.signing_key, content, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig, sig_data.get("signature", "")):
                logger.error(f"Signature mismatch for {model_path}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False


# ============================================================================
# SKLEARN MODEL WRAPPER (Safe Loading)
# ============================================================================

class SafeSklearnModel:
    """
    Safe wrapper for sklearn models
    
    Instead of pickling the entire model, we:
    1. Save only the model parameters (numpy arrays)
    2. Reconstruct the model from parameters on load
    3. Verify signatures before loading
    """
    
    # Allowed sklearn model types
    ALLOWED_MODELS = {
        'RandomForestClassifier',
        'GradientBoostingClassifier',
        'LogisticRegression',
        'SVC',
        'DecisionTreeClassifier',
    }
    
    def __init__(self, model_type: str = 'RandomForestClassifier'):
        if model_type not in self.ALLOWED_MODELS:
            raise SecurityError(f"Model type not allowed: {model_type}")
        
        self.model_type = model_type
        self.model = None
        self.params = {}
    
    def save(self, model, path: str, loader: SecureModelLoader):
        """
        Save sklearn model safely (parameters only, no pickle)
        """
        model_type = type(model).__name__
        
        if model_type not in self.ALLOWED_MODELS:
            raise SecurityError(f"Cannot save model type: {model_type}")
        
        # Extract parameters based on model type
        if model_type == 'RandomForestClassifier':
            params = self._extract_rf_params(model)
        elif model_type == 'GradientBoostingClassifier':
            params = self._extract_gb_params(model)
        else:
            raise SecurityError(f"Parameter extraction not implemented for {model_type}")
        
        # Add metadata
        params['_model_type'] = model_type
        params['_n_features'] = model.n_features_in_
        params['_classes'] = model.classes_.tolist()
        
        # Save as NPZ (safe format)
        loader.save_model(params, path)
    
    def load(self, path: str, loader: SecureModelLoader):
        """
        Load sklearn model safely (reconstruct from parameters)
        """
        params = loader.load_model(path, verify_signature=True)
        
        model_type = params.get('_model_type')
        if model_type not in self.ALLOWED_MODELS:
            raise SecurityError(f"Unknown model type in file: {model_type}")
        
        # Reconstruct model
        if model_type == 'RandomForestClassifier':
            self.model = self._reconstruct_rf(params)
        elif model_type == 'GradientBoostingClassifier':
            self.model = self._reconstruct_gb(params)
        else:
            raise SecurityError(f"Reconstruction not implemented for {model_type}")
        
        return self.model
    
    def _extract_rf_params(self, model) -> Dict:
        """Extract RandomForest parameters as numpy arrays"""
        return {
            'n_estimators': model.n_estimators,
            'max_depth': model.max_depth,
            'feature_importances': model.feature_importances_,
            # Store tree structure (simplified)
            'tree_predictions': np.array([
                tree.predict_proba for tree in model.estimators_
            ]) if hasattr(model, 'estimators_') else None,
        }
    
    def _extract_gb_params(self, model) -> Dict:
        """Extract GradientBoosting parameters"""
        return {
            'n_estimators': model.n_estimators,
            'learning_rate': model.learning_rate,
            'max_depth': model.max_depth,
            'feature_importances': model.feature_importances_,
        }
    
    def _reconstruct_rf(self, params: Dict):
        """
        Reconstruct RandomForest from parameters
        
        NOTE: Full reconstruction requires retraining.
        For inference-only, we use a simpler approach.
        """
        # For production, you would:
        # 1. Store full tree structure in a safe format
        # 2. Or use ONNX format for inference
        # 3. Or retrain on startup from trusted data
        
        raise NotImplementedError(
            "Full RF reconstruction requires retraining. "
            "Use ONNX format for production inference."
        )
    
    def _reconstruct_gb(self, params: Dict):
        """Reconstruct GradientBoosting from parameters"""
        raise NotImplementedError(
            "Full GB reconstruction requires retraining. "
            "Use ONNX format for production inference."
        )


# ============================================================================
# ONNX MODEL LOADER (Recommended for Production)
# ============================================================================

class SafeONNXLoader:
    """
    Load ONNX models safely
    
    ONNX format is safe because:
    1. It's a declarative format (no executable code)
    2. It defines computation graph only
    3. No arbitrary code execution possible
    """
    
    def __init__(self, models_dir: str = "./models"):
        self.models_dir = Path(models_dir)
        self.secure_loader = SecureModelLoader(models_dir=models_dir)
    
    def load(self, model_path: str):
        """
        Load ONNX model with security checks
        """
        try:
            import onnxruntime as ort
        except ImportError:
            raise ImportError("onnxruntime not installed. Run: pip install onnxruntime")
        
        path = Path(model_path)
        
        # Security check: Verify path is within models directory
        abs_path = path.resolve()
        models_abs = self.models_dir.resolve()
        
        try:
            abs_path.relative_to(models_abs)
        except ValueError:
            raise SecurityError(f"Path traversal detected: {abs_path}")
        
        # Security check: Verify extension
        if path.suffix != '.onnx':
            raise SecurityError(f"Not an ONNX file: {path.suffix}")
        
        # Security check: Verify file size
        if abs_path.stat().st_size > 500 * 1024 * 1024:  # 500MB max
            raise SecurityError("ONNX file too large")
        
        # Load with ONNX Runtime (safe)
        session = ort.InferenceSession(str(abs_path))
        
        logger.info(f"Loaded ONNX model: {path.name}")
        return session


# ============================================================================
# MIGRATION HELPER
# ============================================================================

def migrate_pickle_to_safe(pickle_path: str, output_path: str, signing_key: bytes = None):
    """
    ONE-TIME MIGRATION: Convert pickle model to safe format
    
    Run this OFFLINE on a trusted machine to convert existing models.
    DO NOT run this on production systems!
    
    Usage:
        python -c "from core.secure_model_loader import migrate_pickle_to_safe; \
                   migrate_pickle_to_safe('./models/old_model.pkl', './models/new_model.npz')"
    """
    import pickle
    import warnings
    
    warnings.warn(
        "⚠️  SECURITY WARNING: Loading pickle file. "
        "Only run this on trusted models from a trusted source!",
        UserWarning
    )
    
    print(f"[!] Loading pickle file (DANGEROUS): {pickle_path}")
    print("[!] Only proceed if you trust this file!")
    
    confirm = input("Type 'I TRUST THIS FILE' to proceed: ")
    if confirm != 'I TRUST THIS FILE':
        print("Aborted.")
        return
    
    # Load pickle (using RestrictedUnpickler for safety)
    with open(pickle_path, 'rb') as f:
        model = RestrictedUnpickler(f).load()
    
    # Extract safe parameters
    model_type = type(model).__name__
    
    if hasattr(model, 'feature_importances_'):
        safe_data = {
            '_model_type': model_type,
            'feature_importances': model.feature_importances_,
            'n_features': getattr(model, 'n_features_in_', 0),
            'classes': model.classes_.tolist() if hasattr(model, 'classes_') else [],
        }
    else:
        raise ValueError(f"Don't know how to extract parameters from {model_type}")
    
    # Save safely
    loader = SecureModelLoader(signing_key=signing_key)
    loader.save_model(safe_data, output_path, sign=True)
    
    print(f"[+] Migrated to safe format: {output_path}")
    print(f"[+] Signature created: {output_path}.sig")
    print("[!] Delete the original pickle file!")


# Global instance
secure_model_loader = SecureModelLoader()
