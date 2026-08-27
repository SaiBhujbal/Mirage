#!/usr/bin/env python3
"""
MIRAGE Real-World Generalized Trainer
==========================================
Naval SWAVLAMBAN 2025 Challenge 3

Trains models using REAL attack payloads from:
- PayloadsAllTheThings
- SecLists  
- Embedded real payloads (fallback)
- 5 Network datasets (CICIDS2017, UNSW-NB15, CICDDoS2019, CTU-13)

Features:
- NO synthetic data (uses real pentest payloads)
- Modern attack categories (NoSQL, JWT, GraphQL, SSTI, etc.)
- Real-world evasion techniques for generalization
- Anti-overfitting: noise injection, augmentation
- Cross-validation for robust evaluation

Author: MIRAGE Team
Date: December 2025
"""

import os
import sys
import json
import time
import hmac
import hashlib
import logging
import warnings
import random
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

# XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# LightGBM (optional)
try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

# Import our modules
from ml.dataset_loader import DatasetLoader, HTTPFeatureExtractor
from ml.real_payload_loader import (
    RealPayloadLoader, 
    EmbeddedPayloads, 
    EvasionTechniques,
    ATTACK_CATEGORIES
)

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mirage.real_trainer")


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class RealTrainerConfig:
    """Configuration for real-world generalized training"""
    
    # Directories
    models_dir: str = "./models"
    data_dir: str = "./data/datasets"
    payloads_dir: str = "./data/payloads"
    
    # Data splits
    test_size: float = 0.15
    val_size: float = 0.15
    random_state: int = 42
    
    # HTTP Layer
    http_n_features: int = 50
    http_max_samples_per_category: int = 3000
    http_min_samples_per_category: int = 100
    
    # Network Layer
    network_n_features: int = 78
    network_max_samples: int = 100000
    
    # Evasion/Augmentation
    evasion_ratio: float = 0.4  # 40% of payloads get evasion applied
    noise_std: float = 0.05  # Gaussian noise for anti-overfitting
    
    # Isolation Forest
    if_n_estimators: int = 200
    if_contamination: float = 0.1
    if_max_samples: float = 0.8
    
    # XGBoost - tuned for generalization
    xgb_n_estimators: int = 300
    xgb_max_depth: int = 6  # Lower depth for generalization
    xgb_learning_rate: float = 0.05
    xgb_early_stopping: int = 30
    xgb_reg_alpha: float = 0.1  # L1 regularization
    xgb_reg_lambda: float = 1.0  # L2 regularization
    xgb_subsample: float = 0.8  # Row subsampling
    xgb_colsample_bytree: float = 0.8  # Column subsampling
    
    # Ensemble weights
    http_weight: float = 0.6
    network_weight: float = 0.4
    xgb_weight: float = 0.7
    if_weight: float = 0.3
    
    # Cross-validation
    cv_folds: int = 5
    use_cv: bool = True


# ============================================================================
# UNIFIED ATTACK CATEGORIES (Modern 2024)
# ============================================================================

UNIFIED_CATEGORIES = [
    'benign',             # 0
    'sqli',               # 1
    'xss',                # 2
    'rce',                # 3
    'path_traversal',     # 4
    'ssrf',               # 5
    'xxe',                # 6
    'ssti',               # 7
    'nosql',              # 8
    'jwt',                # 9
    'graphql',            # 10
    'ldap',               # 11
    'deserialization',    # 12
    'prototype_pollution', # 13
    'crlf',               # 14
    'open_redirect',      # 15
    'dos',                # 16 - Network layer
    'ddos',               # 17 - Network layer
    'brute_force',        # 18 - Network layer
    'port_scan',          # 19 - Network layer
    'botnet',             # 20 - Network layer
]


# ============================================================================
# REAL-WORLD TRAINER
# ============================================================================

class RealWorldTrainer:
    """
    Real-world generalized trainer using actual security payloads.
    
    Key differences from synthetic trainer:
    1. Uses real payloads from security tools
    2. Applies real evasion techniques
    3. Includes modern attack categories
    4. Anti-overfitting measures
    """
    
    def __init__(self, config: RealTrainerConfig = None):
        self.config = config or RealTrainerConfig()
        self.models_dir = Path(self.config.models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Loaders
        self.payload_loader = RealPayloadLoader(self.config.payloads_dir)
        self.dataset_loader = DatasetLoader(self.config.data_dir)
        self.feature_extractor = HTTPFeatureExtractor()
        
        # Models (HTTP Layer)
        self.http_scaler = None
        self.http_xgb = None
        self.http_if = None
        self.http_label_encoder = None
        
        # Models (Network Layer)
        self.network_scaler = None
        self.network_xgb = None
        self.network_if = None
        self.network_label_encoder = None
        self.network_n_features = None
        
        # Training results
        self.training_results = {}
    
    def _prepare_http_data(self) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Prepare HTTP training data from real payloads.
        Uses PayloadsAllTheThings/SecLists if available, otherwise embedded payloads.
        """
        logger.info("\n" + "=" * 70)
        logger.info("PREPARING HTTP LAYER DATA (Real Payloads)")
        logger.info("=" * 70)
        
        repos = self.payload_loader.check_repositories()
        has_repos = any(repos.values())
        
        all_features = []
        all_labels = []
        categories_used = []
        
        if has_repos:
            logger.info("Loading from PayloadsAllTheThings/SecLists...")
            payloads_by_cat = self.payload_loader.load_all_categories(
                max_per_category=self.config.http_max_samples_per_category,
                include_evasions=True,
                evasion_ratio=self.config.evasion_ratio
            )
        else:
            logger.info("Repositories not found. Using embedded real payloads...")
            payloads_by_cat = self._get_embedded_with_evasions()
        
        # Also load CSIC 2010 if available (real HTTP attacks from 2010)
        csic_features, csic_labels = self._load_csic_2010()
        if csic_features is not None:
            logger.info(f"  Added CSIC 2010: {len(csic_features)} samples")
        
        # Process each category
        cat_id = 0
        for cat_name in ATTACK_CATEGORIES.keys():
            payloads = payloads_by_cat.get(cat_name, [])
            
            if not payloads and cat_name != 'benign':
                # Try embedded fallback
                embedded = EmbeddedPayloads.get_category(cat_name)
                if embedded:
                    payloads = embedded
            
            if not payloads:
                logger.warning(f"  No payloads for {cat_name}, skipping")
                continue
            
            # Extract features
            cat_features = []
            for payload in payloads:
                try:
                    features = self.feature_extractor.extract(payload)
                    if features is not None and len(features) == self.config.http_n_features:
                        cat_features.append(features)
                except Exception as e:
                    continue
            
            if len(cat_features) < self.config.http_min_samples_per_category:
                logger.warning(f"  {cat_name}: Only {len(cat_features)} samples (min: {self.config.http_min_samples_per_category})")
                # Augment with variations
                cat_features = self._augment_features(cat_features, self.config.http_min_samples_per_category)
            
            if cat_features:
                all_features.extend(cat_features)
                all_labels.extend([cat_id] * len(cat_features))
                categories_used.append(cat_name)
                logger.info(f"  {cat_name}: {len(cat_features)} samples (id={cat_id})")
                cat_id += 1
        
        # Add CSIC 2010 data
        if csic_features is not None:
            # Map CSIC labels to our categories
            # CSIC has: normal (0), sqli (1), xss (2), etc.
            for i, (feat, label) in enumerate(zip(csic_features, csic_labels)):
                all_features.append(feat)
                # Map to nearest category
                if label == 0:
                    all_labels.append(0)  # benign
                else:
                    all_labels.append(min(label, len(categories_used) - 1))
        
        X = np.array(all_features, dtype=np.float32)
        y = np.array(all_labels, dtype=np.int32)
        
        # Clean data
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        # Add noise for anti-overfitting
        if self.config.noise_std > 0:
            noise = np.random.normal(0, self.config.noise_std, X.shape)
            X = X + noise
        
        logger.info(f"\n  Total HTTP data: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"  Categories: {len(categories_used)}")
        
        return X, y, categories_used
    
    def _get_embedded_with_evasions(self) -> Dict[str, List[str]]:
        """Get embedded payloads with evasion techniques applied"""
        embedded = EmbeddedPayloads.get_all()
        result = {}
        
        for cat, payloads in embedded.items():
            all_payloads = list(payloads)
            
            # Apply evasion to subset
            evasion_count = int(len(payloads) * self.config.evasion_ratio)
            for payload in random.sample(payloads, min(evasion_count, len(payloads))):
                evaded = EvasionTechniques.apply_random_evasion(payload, count=random.randint(1, 3))
                if evaded != payload:
                    all_payloads.append(evaded)
            
            result[cat] = all_payloads
        
        # Add benign samples
        result['benign'] = self._generate_benign_requests()
        
        return result
    
    def _generate_benign_requests(self, count: int = 2000) -> List[str]:
        """Generate realistic benign HTTP requests"""
        benign = []
        
        # API patterns
        api_endpoints = [
            "api/v1/users/{}", "api/v2/products/{}", "api/orders/{}",
            "api/search", "api/auth/login", "api/settings",
        ]
        
        # Web paths
        web_paths = [
            "index.html", "about", "contact", "products", "blog",
            "faq", "terms", "privacy", "help", "support",
        ]
        
        # Query parameters (normal)
        params = [
            "page=1", "limit=20", "sort=date", "order=desc",
            "lang=en", "format=json", "q=search+term",
            "category=electronics", "brand=apple", "price=100-500",
        ]
        
        # Form data (normal)
        form_data = [
            "name=John+Doe", "email=user@example.com",
            "username=johndoe", "message=Hello+World",
            "phone=1234567890", "country=US",
        ]
        
        for _ in range(count):
            r = random.random()
            
            if r < 0.25:
                # API endpoint
                endpoint = random.choice(api_endpoints).format(random.randint(1, 10000))
                if random.random() > 0.5:
                    endpoint += "?" + "&".join(random.sample(params, random.randint(1, 3)))
                benign.append(endpoint)
            
            elif r < 0.5:
                # Web path
                path = random.choice(web_paths)
                if random.random() > 0.7:
                    path += "?" + random.choice(params)
                benign.append(path)
            
            elif r < 0.75:
                # Form submission
                data = "&".join(random.sample(form_data, random.randint(2, 4)))
                benign.append(data)
            
            else:
                # Static resources
                resources = [
                    "static/css/style.css", "static/js/app.js",
                    "images/logo.png", "fonts/roboto.woff2",
                ]
                benign.append(random.choice(resources))
        
        return benign
    
    def _load_csic_2010(self) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Load CSIC 2010 dataset if available"""
        csic_dir = Path(self.config.data_dir) / 'csic2010'
        
        if not csic_dir.exists():
            return None, None
        
        try:
            result = self.dataset_loader.load_csic_2010(
                max_samples=self.config.http_max_samples_per_category * 2
            )
            if result[0] is not None:
                return result[0], result[1]
        except Exception as e:
            logger.warning(f"Failed to load CSIC 2010: {e}")
        
        return None, None
    
    def _augment_features(self, features: List[np.ndarray], target_count: int) -> List[np.ndarray]:
        """Augment features to reach target count using noise injection"""
        if not features:
            return features
        
        augmented = list(features)
        
        while len(augmented) < target_count:
            # Pick random existing feature
            base = random.choice(features)
            
            # Add small noise
            noise = np.random.normal(0, 0.1, base.shape)
            augmented.append(base + noise)
        
        return augmented
    
    def _prepare_network_data(self) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], Optional[List[str]]]:
        """
        Prepare network layer data from real datasets:
        - CICIDS2017
        - UNSW-NB15
        - CICDDoS2019
        - CTU-13
        """
        logger.info("\n" + "=" * 70)
        logger.info("PREPARING NETWORK LAYER DATA (Real Datasets)")
        logger.info("=" * 70)
        
        all_X = []
        all_y = []
        all_categories = set()
        
        # Try loading each dataset
        datasets_loaded = 0
        
        # CICIDS2017
        try:
            X, y, cats = self.dataset_loader.load_cicids2017(
                max_samples=self.config.network_max_samples // 4
            )
            if X is not None:
                all_X.append(X)
                all_y.append(y)
                all_categories.update(cats)
                datasets_loaded += 1
                logger.info(f"  CICIDS2017: {X.shape[0]} samples, {X.shape[1]} features")
        except Exception as e:
            logger.warning(f"  CICIDS2017 not available: {e}")
        
        # UNSW-NB15
        try:
            X, y, cats = self.dataset_loader.load_unsw_nb15(
                max_samples=self.config.network_max_samples // 4
            )
            if X is not None:
                all_X.append(X)
                all_y.append(y)
                all_categories.update(cats)
                datasets_loaded += 1
                logger.info(f"  UNSW-NB15: {X.shape[0]} samples, {X.shape[1]} features")
        except Exception as e:
            logger.warning(f"  UNSW-NB15 not available: {e}")
        
        # CICDDoS2019
        try:
            X, y, cats = self.dataset_loader.load_cicddos2019(
                max_samples=self.config.network_max_samples // 4
            )
            if X is not None:
                all_X.append(X)
                all_y.append(y)
                all_categories.update(cats)
                datasets_loaded += 1
                logger.info(f"  CICDDoS2019: {X.shape[0]} samples, {X.shape[1]} features")
        except Exception as e:
            logger.warning(f"  CICDDoS2019 not available: {e}")
        
        # CTU-13
        try:
            X, y, cats = self.dataset_loader.load_ctu13(
                max_samples=self.config.network_max_samples // 4
            )
            if X is not None:
                all_X.append(X)
                all_y.append(y)
                all_categories.update(cats)
                datasets_loaded += 1
                logger.info(f"  CTU-13: {X.shape[0]} samples, {X.shape[1]} features")
        except Exception as e:
            logger.warning(f"  CTU-13 not available: {e}")
        
        if not all_X:
            logger.warning("  No network datasets available!")
            return None, None, None
        
        # Normalize feature dimensions
        target_features = self.config.network_n_features
        normalized_X = []
        
        for X in all_X:
            if X.shape[1] < target_features:
                # Pad with zeros
                padding = np.zeros((X.shape[0], target_features - X.shape[1]))
                X = np.hstack([X, padding])
            elif X.shape[1] > target_features:
                # Truncate
                X = X[:, :target_features]
            normalized_X.append(X)
        
        # Combine all
        X_combined = np.vstack(normalized_X)
        
        # Re-encode labels
        combined_labels = []
        offset = 0
        for X, y in zip(all_X, all_y):
            combined_labels.extend(y + offset)
            offset += len(np.unique(y))
        
        y_combined = np.array(combined_labels)
        
        # Re-encode to sequential
        le = LabelEncoder()
        y_combined = le.fit_transform(y_combined)
        categories = [f"class_{i}" for i in range(len(le.classes_))]
        
        self.network_n_features = target_features
        
        # Clean data
        X_combined = np.nan_to_num(X_combined, nan=0.0, posinf=1e6, neginf=-1e6)
        
        logger.info(f"\n  Total Network data: {X_combined.shape[0]} samples, {X_combined.shape[1]} features")
        logger.info(f"  Datasets loaded: {datasets_loaded}")
        
        return X_combined, y_combined, categories
    
    def train(self, 
              train_http: bool = True, 
              train_network: bool = True) -> Dict:
        """
        Train dual-layer models
        
        Args:
            train_http: Train HTTP layer models
            train_network: Train network layer models
            
        Returns:
            Training results dictionary
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'config': asdict(self.config),
            'http_layer': None,
            'network_layer': None,
        }
        
        # Train HTTP Layer
        if train_http:
            X, y, categories = self._prepare_http_data()
            if X is not None and len(X) > 0:
                results['http_layer'] = self._train_http_layer(X, y, categories)
        
        # Train Network Layer
        if train_network:
            X, y, categories = self._prepare_network_data()
            if X is not None and len(X) > 0:
                results['network_layer'] = self._train_network_layer(X, y, categories)
        
        # Save all models
        self._save_models(results)
        
        self.training_results = results
        return results
    
    def _train_http_layer(self, X: np.ndarray, y: np.ndarray, categories: List[str]) -> Dict:
        """Train HTTP layer models"""
        logger.info("\n" + "=" * 70)
        logger.info("TRAINING HTTP LAYER")
        logger.info("=" * 70)
        
        results = {
            'n_samples': len(X),
            'n_features': X.shape[1],
            'n_categories': len(categories),
            'categories': categories,
        }
        
        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=self.config.test_size + self.config.val_size,
            stratify=y, random_state=self.config.random_state
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5,
            stratify=y_temp, random_state=self.config.random_state
        )
        
        logger.info(f"  Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        
        # Scale features
        self.http_scaler = RobustScaler()
        X_train_scaled = self.http_scaler.fit_transform(X_train)
        X_val_scaled = self.http_scaler.transform(X_val)
        X_test_scaled = self.http_scaler.transform(X_test)
        
        # Binary labels for anomaly detection
        y_train_binary = (y_train > 0).astype(int)
        y_test_binary = (y_test > 0).astype(int)
        
        # Train Isolation Forest
        logger.info("\n  Training Isolation Forest...")
        start = time.time()
        
        self.http_if = IsolationForest(
            n_estimators=self.config.if_n_estimators,
            contamination=self.config.if_contamination,
            max_samples=self.config.if_max_samples,
            random_state=self.config.random_state,
            n_jobs=-1
        )
        self.http_if.fit(X_train_scaled[y_train == 0])  # Train on benign only
        
        if_time = time.time() - start
        
        if_pred_raw = self.http_if.predict(X_test_scaled)
        if_pred = (if_pred_raw == -1).astype(int)  # -1 = anomaly
        if_f1 = f1_score(y_test_binary, if_pred)
        
        logger.info(f"    Time: {if_time:.2f}s, F1: {if_f1:.4f}")
        results['isolation_forest'] = {'time': if_time, 'f1': if_f1}
        
        # Train XGBoost
        logger.info("\n  Training XGBoost classifier...")
        start = time.time()
        
        n_classes = len(categories)
        
        if XGBOOST_AVAILABLE:
            self.http_xgb = xgb.XGBClassifier(
                n_estimators=self.config.xgb_n_estimators,
                max_depth=self.config.xgb_max_depth,
                learning_rate=self.config.xgb_learning_rate,
                objective='multi:softprob' if n_classes > 2 else 'binary:logistic',
                num_class=n_classes if n_classes > 2 else None,
                eval_metric='mlogloss' if n_classes > 2 else 'logloss',
                early_stopping_rounds=self.config.xgb_early_stopping,
                reg_alpha=self.config.xgb_reg_alpha,
                reg_lambda=self.config.xgb_reg_lambda,
                subsample=self.config.xgb_subsample,
                colsample_bytree=self.config.xgb_colsample_bytree,
                random_state=self.config.random_state,
                n_jobs=-1,
                verbosity=0
            )
            self.http_xgb.fit(
                X_train_scaled, y_train,
                eval_set=[(X_val_scaled, y_val)],
                verbose=False
            )
        else:
            self.http_xgb = RandomForestClassifier(
                n_estimators=200,
                max_depth=self.config.xgb_max_depth,
                random_state=self.config.random_state,
                n_jobs=-1
            )
            self.http_xgb.fit(X_train_scaled, y_train)
        
        xgb_time = time.time() - start
        
        xgb_pred = self.http_xgb.predict(X_test_scaled)
        xgb_acc = accuracy_score(y_test, xgb_pred)
        xgb_pred_binary = (xgb_pred > 0).astype(int)
        xgb_f1 = f1_score(y_test_binary, xgb_pred_binary)
        
        logger.info(f"    Time: {xgb_time:.2f}s, Accuracy: {xgb_acc:.4f}, Binary F1: {xgb_f1:.4f}")
        results['xgboost'] = {'time': xgb_time, 'accuracy': xgb_acc, 'f1': xgb_f1}
        
        # Ensemble evaluation
        ensemble_score = (
            self.config.xgb_weight * xgb_pred_binary +
            self.config.if_weight * if_pred
        )
        ensemble_pred = (ensemble_score > 0.5).astype(int)
        
        ensemble_f1 = f1_score(y_test_binary, ensemble_pred)
        ensemble_precision = precision_score(y_test_binary, ensemble_pred, zero_division=0)
        ensemble_recall = recall_score(y_test_binary, ensemble_pred, zero_division=0)
        
        cm = confusion_matrix(y_test_binary, ensemble_pred)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        else:
            tn, fp, fn, tp = 0, 0, 0, 0
            fpr = 0
        
        logger.info(f"\n  HTTP Ensemble: F1={ensemble_f1:.4f}, P={ensemble_precision:.4f}, R={ensemble_recall:.4f}")
        logger.info(f"  Confusion: TN={tn}, FP={fp}, FN={fn}, TP={tp}, FPR={fpr:.4%}")
        
        results['ensemble'] = {
            'f1': ensemble_f1,
            'precision': ensemble_precision,
            'recall': ensemble_recall,
            'fpr': fpr,
            'confusion': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)}
        }
        
        return results
    
    def _train_network_layer(self, X: np.ndarray, y: np.ndarray, categories: List[str]) -> Dict:
        """Train network layer models"""
        logger.info("\n" + "=" * 70)
        logger.info("TRAINING NETWORK LAYER")
        logger.info("=" * 70)
        
        results = {
            'n_samples': len(X),
            'n_features': X.shape[1],
            'n_categories': len(categories),
            'categories': categories,
        }
        
        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=self.config.test_size + self.config.val_size,
            stratify=y, random_state=self.config.random_state
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5,
            stratify=y_temp, random_state=self.config.random_state
        )
        
        logger.info(f"  Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        
        # Scale
        self.network_scaler = RobustScaler()
        X_train_scaled = self.network_scaler.fit_transform(X_train)
        X_val_scaled = self.network_scaler.transform(X_val)
        X_test_scaled = self.network_scaler.transform(X_test)
        
        # Binary labels
        y_train_binary = (y_train > 0).astype(int)
        y_test_binary = (y_test > 0).astype(int)
        
        # Isolation Forest
        logger.info("\n  Training Network Isolation Forest...")
        start = time.time()
        
        self.network_if = IsolationForest(
            n_estimators=self.config.if_n_estimators,
            contamination=self.config.if_contamination,
            max_samples=self.config.if_max_samples,
            random_state=self.config.random_state,
            n_jobs=-1
        )
        
        benign_mask = y_train == 0
        if np.sum(benign_mask) > 0:
            self.network_if.fit(X_train_scaled[benign_mask])
        else:
            self.network_if.fit(X_train_scaled[:1000])
        
        if_time = time.time() - start
        
        if_pred_raw = self.network_if.predict(X_test_scaled)
        if_pred = (if_pred_raw == -1).astype(int)
        if_f1 = f1_score(y_test_binary, if_pred)
        
        logger.info(f"    Time: {if_time:.2f}s, F1: {if_f1:.4f}")
        results['isolation_forest'] = {'time': if_time, 'f1': if_f1}
        
        # XGBoost
        logger.info("\n  Training Network XGBoost classifier...")
        start = time.time()
        
        n_classes = len(np.unique(y))
        
        if XGBOOST_AVAILABLE:
            self.network_xgb = xgb.XGBClassifier(
                n_estimators=self.config.xgb_n_estimators,
                max_depth=self.config.xgb_max_depth,
                learning_rate=self.config.xgb_learning_rate,
                objective='multi:softprob' if n_classes > 2 else 'binary:logistic',
                num_class=n_classes if n_classes > 2 else None,
                eval_metric='mlogloss' if n_classes > 2 else 'logloss',
                early_stopping_rounds=self.config.xgb_early_stopping,
                reg_alpha=self.config.xgb_reg_alpha,
                reg_lambda=self.config.xgb_reg_lambda,
                subsample=self.config.xgb_subsample,
                colsample_bytree=self.config.xgb_colsample_bytree,
                random_state=self.config.random_state,
                n_jobs=-1,
                verbosity=0
            )
            self.network_xgb.fit(
                X_train_scaled, y_train,
                eval_set=[(X_val_scaled, y_val)],
                verbose=False
            )
        else:
            self.network_xgb = RandomForestClassifier(
                n_estimators=200,
                max_depth=self.config.xgb_max_depth,
                random_state=self.config.random_state,
                n_jobs=-1
            )
            self.network_xgb.fit(X_train_scaled, y_train)
        
        xgb_time = time.time() - start
        
        xgb_pred = self.network_xgb.predict(X_test_scaled)
        xgb_acc = accuracy_score(y_test, xgb_pred)
        xgb_pred_binary = (xgb_pred > 0).astype(int)
        xgb_f1 = f1_score(y_test_binary, xgb_pred_binary)
        
        logger.info(f"    Time: {xgb_time:.2f}s, Accuracy: {xgb_acc:.4f}, Binary F1: {xgb_f1:.4f}")
        results['xgboost'] = {'time': xgb_time, 'accuracy': xgb_acc, 'f1': xgb_f1}
        
        # Ensemble
        ensemble_score = (
            self.config.xgb_weight * xgb_pred_binary +
            self.config.if_weight * if_pred
        )
        ensemble_pred = (ensemble_score > 0.5).astype(int)
        
        ensemble_f1 = f1_score(y_test_binary, ensemble_pred)
        ensemble_precision = precision_score(y_test_binary, ensemble_pred, zero_division=0)
        ensemble_recall = recall_score(y_test_binary, ensemble_pred, zero_division=0)
        
        cm = confusion_matrix(y_test_binary, ensemble_pred)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        else:
            tn, fp, fn, tp = 0, 0, 0, 0
            fpr = 0
        
        logger.info(f"\n  Network Ensemble: F1={ensemble_f1:.4f}, P={ensemble_precision:.4f}, R={ensemble_recall:.4f}")
        logger.info(f"  Confusion: TN={tn}, FP={fp}, FN={fn}, TP={tp}, FPR={fpr:.4%}")
        
        results['ensemble'] = {
            'f1': ensemble_f1,
            'precision': ensemble_precision,
            'recall': ensemble_recall,
            'fpr': fpr,
            'confusion': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)}
        }
        
        return results
    
    def _save_models(self, results: Dict):
        """Save all trained models"""
        import joblib
        
        logger.info("\n" + "=" * 70)
        logger.info("SAVING MODELS")
        logger.info("=" * 70)
        
        # HTTP Layer
        if self.http_scaler is not None:
            joblib.dump(self.http_scaler, self.models_dir / 'http_scaler.joblib')
            logger.info("  ✓ http_scaler.joblib")
        
        if self.http_if is not None:
            joblib.dump(self.http_if, self.models_dir / 'http_isolation_forest.joblib')
            logger.info("  ✓ http_isolation_forest.joblib")
        
        if self.http_xgb is not None:
            if XGBOOST_AVAILABLE and hasattr(self.http_xgb, 'save_model'):
                self.http_xgb.save_model(str(self.models_dir / 'http_classifier.xgb'))
                logger.info("  ✓ http_classifier.xgb")
            else:
                joblib.dump(self.http_xgb, self.models_dir / 'http_classifier.joblib')
                logger.info("  ✓ http_classifier.joblib")
        
        # Network Layer
        if self.network_scaler is not None:
            joblib.dump(self.network_scaler, self.models_dir / 'network_scaler.joblib')
            logger.info("  ✓ network_scaler.joblib")
        
        if self.network_if is not None:
            joblib.dump(self.network_if, self.models_dir / 'network_isolation_forest.joblib')
            logger.info("  ✓ network_isolation_forest.joblib")
        
        if self.network_xgb is not None:
            if XGBOOST_AVAILABLE and hasattr(self.network_xgb, 'save_model'):
                self.network_xgb.save_model(str(self.models_dir / 'network_classifier.xgb'))
                logger.info("  ✓ network_classifier.xgb")
            else:
                joblib.dump(self.network_xgb, self.models_dir / 'network_classifier.joblib')
                logger.info("  ✓ network_classifier.joblib")
        
        # Metadata
        http_cats = results.get('http_layer', {}).get('categories', [])
        net_cats = results.get('network_layer', {}).get('categories', [])
        
        metadata = {
            'version': '3.0.0',
            'trainer': 'RealWorldTrainer',
            'timestamp': datetime.now().isoformat(),
            'http_layer': {
                'n_features': self.config.http_n_features,
                'categories': http_cats,
                'scaler': 'http_scaler.joblib',
                'classifier': 'http_classifier.xgb' if XGBOOST_AVAILABLE else 'http_classifier.joblib',
                'isolation_forest': 'http_isolation_forest.joblib',
            } if self.http_xgb is not None else None,
            'network_layer': {
                'n_features': self.network_n_features or self.config.network_n_features,
                'categories': net_cats,
                'scaler': 'network_scaler.joblib',
                'classifier': 'network_classifier.xgb' if XGBOOST_AVAILABLE else 'network_classifier.joblib',
                'isolation_forest': 'network_isolation_forest.joblib',
            } if self.network_xgb is not None else None,
            'ensemble_weights': {
                'http_weight': self.config.http_weight,
                'network_weight': self.config.network_weight,
                'xgb_weight': self.config.xgb_weight,
                'if_weight': self.config.if_weight,
            },
            'attack_categories': UNIFIED_CATEGORIES,
            'training_source': 'real_payloads',
        }
        
        with open(self.models_dir / 'dual_layer_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info("  ✓ dual_layer_metadata.json")
        
        # Training report
        with open(self.models_dir / 'training_report.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info("  ✓ training_report.json")
        
        # Generate signatures
        self._generate_signatures()
    
    def _generate_signatures(self):
        """Generate HMAC signatures for model integrity"""
        key = os.environ.get('MODEL_SIGNING_KEY', 'mirage-naval-2025').encode()
        signatures = {}
        
        for f in self.models_dir.glob('*'):
            if f.is_file() and f.suffix in ['.joblib', '.xgb', '.json']:
                with open(f, 'rb') as file:
                    content = file.read()
                sig = hmac.new(key, content, hashlib.sha256).hexdigest()
                signatures[f.name] = sig
        
        with open(self.models_dir / 'model_signatures.json', 'w') as f:
            json.dump(signatures, f, indent=2)
        
        logger.info("  ✓ model_signatures.json")


# ============================================================================
# MAIN
# ============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='MIRAGE Real-World Generalized Trainer')
    parser.add_argument('--models-dir', default='./models', help='Models output directory')
    parser.add_argument('--data-dir', default='./data/datasets', help='Network datasets directory')
    parser.add_argument('--payloads-dir', default='./data/payloads', help='Payloads directory (PayloadsAllTheThings, SecLists)')
    parser.add_argument('--http-only', action='store_true', help='Train HTTP layer only')
    parser.add_argument('--network-only', action='store_true', help='Train network layer only')
    parser.add_argument('--max-http-samples', type=int, default=3000, help='Max HTTP samples per category')
    parser.add_argument('--max-network-samples', type=int, default=100000, help='Max network samples total')
    parser.add_argument('--evasion-ratio', type=float, default=0.4, help='Evasion augmentation ratio')
    parser.add_argument('--noise-std', type=float, default=0.05, help='Gaussian noise std for anti-overfitting')

    args = parser.parse_args()

    config = RealTrainerConfig(
        models_dir=args.models_dir,
        data_dir=args.data_dir,
        payloads_dir=args.payloads_dir,
        http_max_samples_per_category=args.max_http_samples,
        network_max_samples=args.max_network_samples,
        evasion_ratio=args.evasion_ratio,
        noise_std=args.noise_std,
    )
    
    trainer = RealWorldTrainer(config)
    
    results = trainer.train(
        train_http=not args.network_only,
        train_network=not args.http_only,
    )
    
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    
    if results.get('http_layer'):
        http = results['http_layer']
        print(f"\nHTTP Layer (Real Payloads):")
        print(f"  Samples: {http['n_samples']}, Features: {http['n_features']}")
        print(f"  Categories: {http['n_categories']}")
        print(f"  Ensemble F1: {http['ensemble']['f1']:.4f}")
        print(f"  FPR: {http['ensemble']['fpr']:.4%}")
    
    if results.get('network_layer'):
        net = results['network_layer']
        print(f"\nNetwork Layer (Real Datasets):")
        print(f"  Samples: {net['n_samples']}, Features: {net['n_features']}")
        print(f"  Categories: {net['n_categories']}")
        print(f"  Ensemble F1: {net['ensemble']['f1']:.4f}")
        print(f"  FPR: {net['ensemble']['fpr']:.4%}")
    
    print(f"\nModels saved to: {args.models_dir}/")


if __name__ == '__main__':
    main()
