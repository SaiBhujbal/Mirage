#!/usr/bin/env python3
"""
MIRAGE Dual-Layer ML Trainer
================================
Naval SWAVLAMBAN 2025 Challenge 3

Comprehensive training system supporting:
- HTTP Layer: CSIC 2010 + Synthetic payloads (50 features)
- Network Layer: CICIDS2017, UNSW-NB15, CICDDoS2019, CTU-13 (78 features)
- Meta-Ensemble: Combines both layers for final decision

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
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)

# XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    
# LightGBM (optional, faster for large datasets)
try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

# Import our dataset loader
from ml.dataset_loader import DatasetLoader, HTTPFeatureExtractor, SyntheticDataGenerator

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mirage.dual_trainer")


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class DualLayerConfig:
    """Configuration for dual-layer training"""
    
    # Directories
    models_dir: str = "./models"
    data_dir: str = "./data/datasets"
    
    # Data splits
    test_size: float = 0.15
    val_size: float = 0.15
    random_state: int = 42
    
    # HTTP Layer (CSIC 2010 + Synthetic)
    http_n_features: int = 50
    http_max_samples: int = 50000
    http_synthetic_samples: int = 1000  # Per category
    
    # Network Layer (CICIDS, UNSW, DDoS)
    network_n_features: int = 78  # Will be adjusted based on dataset
    network_max_samples: int = 100000
    
    # Isolation Forest
    if_n_estimators: int = 200
    if_contamination: float = 0.1
    if_max_samples: float = 0.8
    
    # XGBoost
    xgb_n_estimators: int = 500
    xgb_max_depth: int = 8
    xgb_learning_rate: float = 0.05
    xgb_early_stopping: int = 50
    
    # Ensemble weights
    http_weight: float = 0.6  # HTTP layer weight
    network_weight: float = 0.4  # Network layer weight
    xgb_weight: float = 0.7  # XGBoost within layer
    if_weight: float = 0.3  # IF within layer


# ============================================================================
# ATTACK CATEGORY MAPPINGS
# ============================================================================

# Unified attack categories across all datasets
UNIFIED_CATEGORIES = [
    'benign',           # 0 - Normal traffic
    'sqli',             # 1 - SQL Injection
    'xss',              # 2 - Cross-Site Scripting
    'rce',              # 3 - Remote Code Execution
    'path_traversal',   # 4 - Path/Directory Traversal
    'ssrf',             # 5 - Server-Side Request Forgery
    'dos',              # 6 - Denial of Service
    'ddos',             # 7 - Distributed DoS
    'brute_force',      # 8 - Brute Force Attack
    'port_scan',        # 9 - Port Scanning
    'botnet',           # 10 - Botnet Traffic
    'infiltration',     # 11 - Infiltration Attack
    'backdoor',         # 12 - Backdoor
    'exploit',          # 13 - Exploits
    'reconnaissance',   # 14 - Reconnaissance
    'other_attack',     # 15 - Other attacks
]

# Mapping from dataset-specific labels to unified categories
CICIDS2017_MAPPING = {
    'BENIGN': 0, 'benign': 0,
    'FTP-Patator': 8, 'SSH-Patator': 8,
    'DoS slowloris': 6, 'DoS Slowhttptest': 6, 'DoS Hulk': 6, 'DoS GoldenEye': 6,
    'Heartbleed': 13,
    'Web Attack Brute Force': 8, 'Web Attack – Brute Force': 8,
    'Web Attack XSS': 2, 'Web Attack – XSS': 2,
    'Web Attack Sql Injection': 1, 'Web Attack – Sql Injection': 1,
    'Infiltration': 11,
    'Bot': 10,
    'PortScan': 9,
    'DDoS': 7,
}

UNSW_NB15_MAPPING = {
    'Normal': 0, 'normal': 0,
    'Fuzzers': 15,
    'Analysis': 14,
    'Backdoor': 12, 'Backdoors': 12,
    'DoS': 6,
    'Exploits': 13,
    'Generic': 15,
    'Reconnaissance': 14,
    'Shellcode': 3,
    'Worms': 15,
}

CTU13_MAPPING = {
    'Normal': 0, 'LEGITIMATE': 0, 'Benign': 0,
    'Botnet': 10, 'botnet': 10,
    'Background': 0,
}


# ============================================================================
# DUAL-LAYER TRAINER
# ============================================================================

class DualLayerTrainer:
    """
    Dual-layer ML trainer for comprehensive attack detection
    
    Layer 1: HTTP Payload Analysis (CSIC 2010 + Synthetic)
    Layer 2: Network Flow Analysis (CICIDS2017, UNSW-NB15, CICDDoS2019)
    Meta-Ensemble: Combines both layers
    """
    
    def __init__(self, config: DualLayerConfig = None):
        self.config = config or DualLayerConfig()
        self.models_dir = Path(self.config.models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Dataset loader
        self.loader = DatasetLoader(self.config.data_dir)
        self.http_extractor = HTTPFeatureExtractor()
        self.synthetic_gen = SyntheticDataGenerator()
        
        # HTTP Layer Models
        self.http_scaler = None
        self.http_xgb = None
        self.http_if = None
        self.http_categories = None
        
        # Network Layer Models
        self.network_scaler = None
        self.network_xgb = None
        self.network_if = None
        self.network_categories = None
        self.network_n_features = None
        
        # Training results
        self.training_results = {}
    
    def train(self, 
              use_http: bool = True,
              use_network: bool = True,
              http_datasets: List[str] = None,
              network_datasets: List[str] = None) -> Dict:
        """
        Train dual-layer ensemble
        
        Args:
            use_http: Train HTTP layer
            use_network: Train Network layer
            http_datasets: List of HTTP dataset paths
            network_datasets: List of network dataset paths
            
        Returns:
            Training results dictionary
        """
        results = {
            'http_layer': None,
            'network_layer': None,
            'meta_ensemble': None,
            'timestamp': datetime.now().isoformat(),
            'config': asdict(self.config),
        }
        
        # ========================
        # LAYER 1: HTTP TRAINING
        # ========================
        if use_http:
            logger.info("\n" + "=" * 70)
            logger.info("LAYER 1: HTTP PAYLOAD ANALYSIS")
            logger.info("=" * 70)
            
            X_http, y_http, http_cats = self._prepare_http_data(http_datasets)
            
            if X_http is not None and len(X_http) > 0:
                results['http_layer'] = self._train_http_layer(X_http, y_http, http_cats)
            else:
                logger.warning("No HTTP data available - using synthetic only")
                X_syn, y_syn, syn_cats = self.synthetic_gen.generate(
                    samples_per_category=self.config.http_synthetic_samples
                )
                results['http_layer'] = self._train_http_layer(X_syn, y_syn, syn_cats)
        
        # ========================
        # LAYER 2: NETWORK TRAINING
        # ========================
        if use_network:
            logger.info("\n" + "=" * 70)
            logger.info("LAYER 2: NETWORK FLOW ANALYSIS")
            logger.info("=" * 70)
            
            X_net, y_net, net_cats = self._prepare_network_data(network_datasets)
            
            if X_net is not None and len(X_net) > 0:
                results['network_layer'] = self._train_network_layer(X_net, y_net, net_cats)
            else:
                logger.warning("No network data available - skipping network layer")
        
        # ========================
        # SAVE MODELS
        # ========================
        self._save_all_models(results)
        
        self.training_results = results
        return results
    
    def _prepare_http_data(self, 
                           dataset_paths: List[str] = None) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Prepare HTTP layer training data"""
        X_all = []
        y_all = []
        
        # Load CSIC 2010 if available
        csic_normal = Path(self.config.data_dir) / 'csic2010' / 'normalTrafficTraining.txt'
        csic_anomalous = Path(self.config.data_dir) / 'csic2010' / 'anomalousTrafficTest.txt'
        
        if csic_normal.exists() or csic_anomalous.exists():
            logger.info("Loading CSIC 2010 dataset...")
            X_csic, y_csic, _ = self.loader.load_csic_2010(
                str(csic_normal) if csic_normal.exists() else None,
                str(csic_anomalous) if csic_anomalous.exists() else None,
                max_samples=self.config.http_max_samples // 2
            )
            if X_csic is not None:
                X_all.append(X_csic)
                y_all.append(y_csic)
                logger.info(f"  CSIC 2010: {len(X_csic)} samples")
        
        # Load any custom HTTP datasets
        if dataset_paths:
            for path in dataset_paths:
                if Path(path).exists():
                    try:
                        # Assume CSV with 'payload' and 'label' columns
                        df = pd.read_csv(path)
                        for _, row in df.iterrows():
                            features = self.http_extractor.extract(str(row.get('payload', '')))
                            X_all.append(features.reshape(1, -1))
                            y_all.append(np.array([row.get('label', 0)]))
                    except Exception as e:
                        logger.warning(f"Failed to load {path}: {e}")
        
        # Add synthetic data
        logger.info("Generating synthetic HTTP payloads...")
        X_syn, y_syn, syn_cats = self.synthetic_gen.generate(
            samples_per_category=self.config.http_synthetic_samples
        )
        X_all.append(X_syn)
        y_all.append(y_syn)
        logger.info(f"  Synthetic: {len(X_syn)} samples")
        
        if not X_all:
            return None, None, None
        
        # Combine all data
        X = np.vstack(X_all)
        y = np.concatenate(y_all)
        
        # Map to binary for ensemble (benign=0, attack=1)
        # Keep original categories for multi-class
        y_binary = (y > 0).astype(int)
        
        # Use synthetic categories (which are more granular)
        categories = syn_cats
        
        logger.info(f"  Total HTTP data: {X.shape[0]} samples, {X.shape[1]} features")
        
        return X, y, categories
    
    def _prepare_network_data(self,
                              dataset_paths: List[str] = None) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Prepare network layer training data"""
        X_all = []
        y_all = []
        categories_all = []
        n_features = None
        
        # Try to load each network dataset
        datasets_to_try = [
            ('cicids2017', self.loader.load_cicids2017, CICIDS2017_MAPPING),
            ('unsw_nb15', self.loader.load_unsw_nb15, UNSW_NB15_MAPPING),
            ('cicddos2019', self.loader.load_cicddos2019, CICIDS2017_MAPPING),
            ('ctu13', self.loader.load_ctu13, CTU13_MAPPING),
        ]
        
        for name, loader_func, mapping in datasets_to_try:
            try:
                X, y, cats = loader_func(max_samples=self.config.network_max_samples // 4)
                
                if X is not None and len(X) > 0:
                    # Map to unified categories
                    y_mapped = np.zeros_like(y)
                    for orig_cat, unified_idx in mapping.items():
                        mask = np.isin(y, [i for i, c in enumerate(cats) if orig_cat.lower() in c.lower()])
                        y_mapped[mask] = unified_idx
                    
                    # Pad/truncate features to common size
                    if n_features is None:
                        n_features = X.shape[1]
                    elif X.shape[1] != n_features:
                        # Pad or truncate
                        if X.shape[1] < n_features:
                            padding = np.zeros((X.shape[0], n_features - X.shape[1]))
                            X = np.hstack([X, padding])
                        else:
                            X = X[:, :n_features]
                    
                    X_all.append(X)
                    y_all.append(y_mapped)
                    logger.info(f"  {name}: {len(X)} samples, {X.shape[1]} features")
                    
            except Exception as e:
                logger.warning(f"  {name}: Failed to load - {e}")
        
        if not X_all:
            return None, None, None
        
        # Combine all data
        X = np.vstack(X_all)
        y = np.concatenate(y_all)
        
        # Use unified categories
        categories = UNIFIED_CATEGORIES
        
        self.network_n_features = X.shape[1]
        logger.info(f"  Total Network data: {X.shape[0]} samples, {X.shape[1]} features")
        
        return X, y, categories
    
    def _train_http_layer(self, 
                          X: np.ndarray, 
                          y: np.ndarray,
                          categories: List[str]) -> Dict:
        """Train HTTP layer models"""
        results = {}
        
        # Binary labels for IF
        y_binary = (y > 0).astype(int)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.config.test_size, 
            stratify=y, random_state=self.config.random_state
        )
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train, test_size=self.config.val_size,
            stratify=y_train, random_state=self.config.random_state
        )
        
        y_train_binary = (y_train > 0).astype(int)
        y_val_binary = (y_val > 0).astype(int)
        y_test_binary = (y_test > 0).astype(int)
        
        # Scale features
        self.http_scaler = RobustScaler()
        X_train_scaled = self.http_scaler.fit_transform(X_train)
        X_val_scaled = self.http_scaler.transform(X_val)
        X_test_scaled = self.http_scaler.transform(X_test)
        
        # Store categories
        self.http_categories = categories
        
        # Train Isolation Forest
        logger.info("\n  Training HTTP Isolation Forest...")
        start = time.time()
        self.http_if = IsolationForest(
            n_estimators=self.config.if_n_estimators,
            contamination=self.config.if_contamination,
            max_samples=self.config.if_max_samples,
            random_state=self.config.random_state,
            n_jobs=-1
        )
        self.http_if.fit(X_train_scaled)
        if_time = time.time() - start
        
        # IF predictions
        if_pred = (self.http_if.predict(X_test_scaled) == -1).astype(int)
        if_f1 = f1_score(y_test_binary, if_pred)
        logger.info(f"    Time: {if_time:.2f}s, F1: {if_f1:.4f}")
        
        results['isolation_forest'] = {
            'training_time': if_time,
            'f1': if_f1,
        }
        
        # Train XGBoost
        logger.info("\n  Training HTTP XGBoost...")
        start = time.time()
        
        if XGBOOST_AVAILABLE:
            n_classes = len(np.unique(y_train))
            self.http_xgb = xgb.XGBClassifier(
                n_estimators=self.config.xgb_n_estimators,
                max_depth=self.config.xgb_max_depth,
                learning_rate=self.config.xgb_learning_rate,
                objective='multi:softprob' if n_classes > 2 else 'binary:logistic',
                num_class=n_classes if n_classes > 2 else None,
                eval_metric='mlogloss' if n_classes > 2 else 'logloss',
                early_stopping_rounds=self.config.xgb_early_stopping,
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
        
        # XGBoost predictions
        xgb_pred = self.http_xgb.predict(X_test_scaled)
        xgb_pred_binary = (xgb_pred > 0).astype(int)
        xgb_acc = accuracy_score(y_test, xgb_pred)
        xgb_f1 = f1_score(y_test_binary, xgb_pred_binary)
        
        logger.info(f"    Time: {xgb_time:.2f}s, Accuracy: {xgb_acc:.4f}, Binary F1: {xgb_f1:.4f}")
        
        results['xgboost'] = {
            'training_time': xgb_time,
            'accuracy': xgb_acc,
            'f1': xgb_f1,
        }
        
        # Ensemble evaluation
        ensemble_score = (
            self.config.xgb_weight * xgb_pred_binary +
            self.config.if_weight * if_pred
        )
        ensemble_pred = (ensemble_score > 0.5).astype(int)
        
        ensemble_f1 = f1_score(y_test_binary, ensemble_pred)
        ensemble_precision = precision_score(y_test_binary, ensemble_pred)
        ensemble_recall = recall_score(y_test_binary, ensemble_pred)
        
        logger.info(f"\n  HTTP Ensemble: F1={ensemble_f1:.4f}, P={ensemble_precision:.4f}, R={ensemble_recall:.4f}")
        
        # Confusion matrix
        cm = confusion_matrix(y_test_binary, ensemble_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        logger.info(f"  Confusion: TN={tn}, FP={fp}, FN={fn}, TP={tp}, FPR={fpr:.4%}")
        
        results['ensemble'] = {
            'f1': ensemble_f1,
            'precision': ensemble_precision,
            'recall': ensemble_recall,
            'fpr': fpr,
            'confusion_matrix': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        }
        
        results['n_samples'] = len(X)
        results['n_features'] = X.shape[1]
        results['categories'] = categories
        
        return results
    
    def _train_network_layer(self,
                             X: np.ndarray,
                             y: np.ndarray,
                             categories: List[str]) -> Dict:
        """Train network layer models"""
        results = {}
        
        # Binary labels
        y_binary = (y > 0).astype(int)
        
        # Handle class imbalance - some classes may have very few samples
        unique, counts = np.unique(y, return_counts=True)
        min_class_size = min(counts)
        
        # Need at least 2 samples per class for stratified split
        if min_class_size < 2:
            # Remove rare classes
            valid_mask = np.isin(y, unique[counts >= 2])
            X = X[valid_mask]
            y = y[valid_mask]
            y_binary = y_binary[valid_mask]
            logger.info(f"  Removed rare classes. Remaining: {len(X)} samples")
        
        # Split data
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.config.test_size,
                stratify=y, random_state=self.config.random_state
            )
        except ValueError:
            # Fallback to non-stratified split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.config.test_size,
                random_state=self.config.random_state
            )
        
        try:
            X_train, X_val, y_train, y_val = train_test_split(
                X_train, y_train, test_size=self.config.val_size,
                stratify=y_train, random_state=self.config.random_state
            )
        except ValueError:
            X_train, X_val, y_train, y_val = train_test_split(
                X_train, y_train, test_size=self.config.val_size,
                random_state=self.config.random_state
            )
        
        y_train_binary = (y_train > 0).astype(int)
        y_val_binary = (y_val > 0).astype(int)
        y_test_binary = (y_test > 0).astype(int)
        
        # Scale features
        self.network_scaler = RobustScaler()
        X_train_scaled = self.network_scaler.fit_transform(X_train)
        X_val_scaled = self.network_scaler.transform(X_val)
        X_test_scaled = self.network_scaler.transform(X_test)
        
        # Store categories
        self.network_categories = categories
        
        # Train Isolation Forest
        logger.info("\n  Training Network Isolation Forest...")
        start = time.time()
        self.network_if = IsolationForest(
            n_estimators=self.config.if_n_estimators,
            contamination=self.config.if_contamination,
            max_samples=min(self.config.if_max_samples, 1.0),
            random_state=self.config.random_state,
            n_jobs=-1
        )
        self.network_if.fit(X_train_scaled)
        if_time = time.time() - start
        
        if_pred = (self.network_if.predict(X_test_scaled) == -1).astype(int)
        if_f1 = f1_score(y_test_binary, if_pred)
        logger.info(f"    Time: {if_time:.2f}s, F1: {if_f1:.4f}")
        
        results['isolation_forest'] = {
            'training_time': if_time,
            'f1': if_f1,
        }
        
        # Train XGBoost
        logger.info("\n  Training Network XGBoost...")
        start = time.time()
        
        n_classes = len(np.unique(y_train))
        
        if XGBOOST_AVAILABLE:
            self.network_xgb = xgb.XGBClassifier(
                n_estimators=self.config.xgb_n_estimators,
                max_depth=self.config.xgb_max_depth,
                learning_rate=self.config.xgb_learning_rate,
                objective='multi:softprob' if n_classes > 2 else 'binary:logistic',
                num_class=n_classes if n_classes > 2 else None,
                eval_metric='mlogloss' if n_classes > 2 else 'logloss',
                early_stopping_rounds=self.config.xgb_early_stopping,
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
        xgb_pred_binary = (xgb_pred > 0).astype(int)
        xgb_acc = accuracy_score(y_test, xgb_pred)
        xgb_f1 = f1_score(y_test_binary, xgb_pred_binary)
        
        logger.info(f"    Time: {xgb_time:.2f}s, Accuracy: {xgb_acc:.4f}, Binary F1: {xgb_f1:.4f}")
        
        results['xgboost'] = {
            'training_time': xgb_time,
            'accuracy': xgb_acc,
            'f1': xgb_f1,
        }
        
        # Ensemble
        ensemble_score = (
            self.config.xgb_weight * xgb_pred_binary +
            self.config.if_weight * if_pred
        )
        ensemble_pred = (ensemble_score > 0.5).astype(int)
        
        ensemble_f1 = f1_score(y_test_binary, ensemble_pred)
        ensemble_precision = precision_score(y_test_binary, ensemble_pred)
        ensemble_recall = recall_score(y_test_binary, ensemble_pred)
        
        logger.info(f"\n  Network Ensemble: F1={ensemble_f1:.4f}, P={ensemble_precision:.4f}, R={ensemble_recall:.4f}")
        
        cm = confusion_matrix(y_test_binary, ensemble_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        logger.info(f"  Confusion: TN={tn}, FP={fp}, FN={fn}, TP={tp}, FPR={fpr:.4%}")
        
        results['ensemble'] = {
            'f1': ensemble_f1,
            'precision': ensemble_precision,
            'recall': ensemble_recall,
            'fpr': fpr,
            'confusion_matrix': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        }
        
        results['n_samples'] = len(X)
        results['n_features'] = X.shape[1]
        results['categories'] = categories[:len(np.unique(y))]
        
        return results
    
    def _save_all_models(self, results: Dict):
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
        metadata = {
            'http_layer': {
                'n_features': self.config.http_n_features,
                'categories': self.http_categories,
                'scaler': 'http_scaler.joblib',
                'classifier': 'http_classifier.xgb' if XGBOOST_AVAILABLE else 'http_classifier.joblib',
                'isolation_forest': 'http_isolation_forest.joblib',
            },
            'network_layer': {
                'n_features': self.network_n_features,
                'categories': self.network_categories,
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
            'unified_categories': UNIFIED_CATEGORIES,
            'version': '2.0.0',
            'timestamp': datetime.now().isoformat(),
        }
        
        with open(self.models_dir / 'dual_layer_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info("  ✓ dual_layer_metadata.json")
        
        # Training report
        with open(self.models_dir / 'dual_layer_training_report.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info("  ✓ dual_layer_training_report.json")
        
        # Generate signatures
        self._generate_signatures()
    
    def _generate_signatures(self):
        """Generate HMAC signatures for model files"""
        key = os.environ.get('MODEL_SIGNING_KEY', 'mirage-naval-2025').encode()
        signatures = {}
        
        for f in self.models_dir.glob('*'):
            if f.is_file() and f.suffix in ['.joblib', '.xgb', '.json', '.npz']:
                with open(f, 'rb') as file:
                    content = file.read()
                sig = hmac.new(key, content, hashlib.sha256).hexdigest()
                signatures[f.name] = sig
        
        with open(self.models_dir / 'dual_layer_signatures.json', 'w') as f:
            json.dump(signatures, f, indent=2)
        
        logger.info("  ✓ dual_layer_signatures.json")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='MIRAGE Dual-Layer ML Trainer')
    parser.add_argument('--models-dir', default='./models', help='Models output directory')
    parser.add_argument('--data-dir', default='./data/datasets', help='Datasets directory')
    parser.add_argument('--http-only', action='store_true', help='Train HTTP layer only')
    parser.add_argument('--network-only', action='store_true', help='Train network layer only')
    parser.add_argument('--http-samples', type=int, default=1000, help='Synthetic samples per HTTP category')
    parser.add_argument('--network-samples', type=int, default=100000, help='Max network samples')
    
    args = parser.parse_args()
    
    config = DualLayerConfig(
        models_dir=args.models_dir,
        data_dir=args.data_dir,
        http_synthetic_samples=args.http_samples,
        network_max_samples=args.network_samples,
    )
    
    trainer = DualLayerTrainer(config)
    
    results = trainer.train(
        use_http=not args.network_only,
        use_network=not args.http_only,
    )
    
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    
    if results.get('http_layer'):
        http = results['http_layer']
        print(f"\nHTTP Layer:")
        print(f"  Samples: {http['n_samples']}, Features: {http['n_features']}")
        print(f"  Ensemble F1: {http['ensemble']['f1']:.4f}")
        print(f"  FPR: {http['ensemble']['fpr']:.4%}")
    
    if results.get('network_layer'):
        net = results['network_layer']
        print(f"\nNetwork Layer:")
        print(f"  Samples: {net['n_samples']}, Features: {net['n_features']}")
        print(f"  Ensemble F1: {net['ensemble']['f1']:.4f}")
        print(f"  FPR: {net['ensemble']['fpr']:.4%}")
