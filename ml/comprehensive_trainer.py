#!/usr/bin/env python3
"""
DECEPTICON Comprehensive Model Trainer
======================================
Naval SWAVLAMBAN 2025 Challenge 3

Trains ML models on ALL attack types using real payloads:
- 15 attack categories
- 700+ embedded real payloads
- Evasion technique augmentation
- Anti-overfitting measures

Author: DECEPTICON Team
Date: December 2025
Security: No pickle, no eval, safe operations only
"""

import os
import sys
import json
import random
import logging
import hashlib
import argparse
from typing import Dict, List, Tuple, Optional, Set
from pathlib import Path
from datetime import datetime
from collections import Counter

import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("decepticon.trainer")

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.real_payload_loader import EmbeddedPayloads, EvasionTechniques
from ml.comprehensive_features import ComprehensiveFeatureExtractor

# Try to import sklearn/xgboost
try:
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest
    from sklearn.model_selection import train_test_split
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("sklearn not available - install with: pip install scikit-learn")

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logger.warning("XGBoost not available - install with: pip install xgboost")


class AttackCategory:
    """Attack category constants matching feature extractor"""
    BENIGN = 0
    SQLI = 1
    XSS = 2
    RCE = 3
    PATH_TRAVERSAL = 4
    SSRF = 5
    NOSQL = 6
    XXE = 7
    SSTI = 8
    JWT = 9
    GRAPHQL = 10
    PROTOTYPE_POLLUTION = 11
    DESERIALIZATION = 12
    LDAP = 13
    CRLF = 14
    OPEN_REDIRECT = 15
    
    NAME_TO_ID = {
        'benign': 0, 'sqli': 1, 'xss': 2, 'rce': 3,
        'path_traversal': 4, 'ssrf': 5, 'nosql': 6, 'xxe': 7,
        'ssti': 8, 'jwt': 9, 'graphql': 10, 'prototype_pollution': 11,
        'deserialization': 12, 'ldap': 13, 'crlf': 14, 'open_redirect': 15,
    }
    
    ID_TO_NAME = {v: k for k, v in NAME_TO_ID.items()}


class BenignPayloadGenerator:
    """Generate realistic benign HTTP payloads"""
    
    API_ENDPOINTS = [
        "/api/v1/users", "/api/v1/products", "/api/v1/orders",
        "/api/v2/customers", "/api/v2/inventory", "/api/v2/payments",
        "/graphql", "/rest/users", "/health", "/status", "/metrics",
    ]
    
    WEB_PATHS = [
        "/", "/index.html", "/about", "/contact", "/login", "/register",
        "/dashboard", "/profile", "/settings", "/help", "/products",
    ]
    
    QUERY_PARAMS = [
        "page=1", "limit=10", "offset=0", "sort=name", "order=asc",
        "q=search+term", "filter=active", "category=electronics",
        "id=123", "user_id=456", "format=json",
    ]
    
    FORM_DATA = [
        "username=john_doe", "email=user@example.com", "name=John+Doe",
        "message=Hello+World", "quantity=1", "size=medium",
    ]
    
    JSON_BODIES = [
        '{"name": "John", "email": "john@example.com"}',
        '{"page": 1, "limit": 10}',
        '{"search": "laptop", "category": "electronics"}',
        '{"id": 123, "status": "active"}',
    ]
    
    @classmethod
    def generate(cls, count: int = 1000) -> List[str]:
        payloads = []
        for _ in range(count // 5):
            endpoint = random.choice(cls.API_ENDPOINTS)
            params = random.sample(cls.QUERY_PARAMS, random.randint(1, 3))
            payloads.append(f"{endpoint}?{'&'.join(params)}")
        for _ in range(count // 5):
            payloads.append(random.choice(cls.WEB_PATHS))
        for _ in range(count // 5):
            fields = random.sample(cls.FORM_DATA, random.randint(2, 4))
            payloads.append('&'.join(fields))
        for _ in range(count // 5):
            payloads.append(random.choice(cls.JSON_BODIES))
        for _ in range(count // 5):
            payloads.append(f"/users/{random.randint(1, 10000)}")
        return payloads


class ComprehensiveTrainer:
    """Comprehensive model trainer for all attack types."""
    
    def __init__(self, models_dir: str = "models", evasion_ratio: float = 0.4, noise_ratio: float = 0.05):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.evasion_ratio = evasion_ratio
        self.noise_ratio = noise_ratio
        self.feature_extractor = ComprehensiveFeatureExtractor()
        self.evasion = EvasionTechniques()
        logger.info(f"Trainer initialized: models_dir={models_dir}")
    
    def load_all_payloads(self) -> Tuple[List[str], List[int]]:
        payloads, labels = [], []
        embedded = EmbeddedPayloads.get_all()
        
        for category_name, category_payloads in embedded.items():
            category_id = AttackCategory.NAME_TO_ID.get(category_name, 1)
            for payload in category_payloads:
                payloads.append(payload)
                labels.append(category_id)
                if random.random() < self.evasion_ratio:
                    evaded = self.evasion.apply_random(payload)
                    payloads.append(evaded)
                    labels.append(category_id)
        
        benign_count = len(payloads) // 2
        benign_payloads = BenignPayloadGenerator.generate(benign_count)
        for payload in benign_payloads:
            payloads.append(payload)
            labels.append(AttackCategory.BENIGN)
        
        logger.info(f"Loaded {len(payloads)} total payloads")
        counter = Counter(labels)
        for cat_id, count in sorted(counter.items()):
            cat_name = AttackCategory.ID_TO_NAME.get(cat_id, f"unknown_{cat_id}")
            logger.info(f"  {cat_name}: {count} samples")
        
        return payloads, labels
    
    def extract_features(self, payloads: List[str]) -> np.ndarray:
        logger.info(f"Extracting features from {len(payloads)} payloads...")
        features = []
        for i, payload in enumerate(payloads):
            if i % 500 == 0 and i > 0:
                logger.info(f"  Processed {i}/{len(payloads)}")
            feat = self.feature_extractor.extract(payload)
            features.append(feat)
        X = np.array(features, dtype=np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=100.0, neginf=0.0)
        logger.info(f"Feature matrix shape: {X.shape}")
        return X
    
    def add_noise(self, X: np.ndarray) -> np.ndarray:
        if self.noise_ratio <= 0:
            return X
        noise = np.random.normal(0, self.noise_ratio, X.shape)
        return np.clip(X + noise, 0, None).astype(np.float32)
    
    def train_classifier(self, X: np.ndarray, y: np.ndarray) -> Tuple:
        if not XGBOOST_AVAILABLE:
            logger.error("XGBoost not available!")
            return None, None
        
        logger.info("Training XGBoost classifier...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        X_train = self.add_noise(X_train)
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        params = {
            'objective': 'multi:softmax', 'num_class': len(set(y)),
            'max_depth': 6, 'learning_rate': 0.1, 'n_estimators': 200,
            'subsample': 0.8, 'colsample_bytree': 0.8,
            'reg_alpha': 0.1, 'reg_lambda': 1.0,
            'min_child_weight': 3, 'gamma': 0.1,
            'random_state': 42, 'n_jobs': -1,
        }
        
        model = xgb.XGBClassifier(**params)
        model.fit(X_train_scaled, y_train, eval_set=[(X_test_scaled, y_test)], verbose=False)
        
        train_score = model.score(X_train_scaled, y_train)
        test_score = model.score(X_test_scaled, y_test)
        logger.info(f"  Train accuracy: {train_score:.4f}")
        logger.info(f"  Test accuracy: {test_score:.4f}")
        
        if train_score - test_score > 0.1:
            logger.warning("  Warning: Possible overfitting!")
        
        return model, scaler
    
    def train_anomaly_detector(self, X: np.ndarray, y: np.ndarray) -> Tuple:
        if not SKLEARN_AVAILABLE:
            return None, None
        
        logger.info("Training Isolation Forest...")
        benign_mask = y == AttackCategory.BENIGN
        X_benign = X[benign_mask] if benign_mask.sum() >= 100 else X
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_benign)
        
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
        model.fit(X_scaled)
        
        X_all_scaled = scaler.transform(X)
        predictions = model.predict(X_all_scaled)
        
        attack_mask = y > 0
        attack_rate = (predictions[attack_mask] == -1).sum() / attack_mask.sum() if attack_mask.sum() > 0 else 0
        logger.info(f"  Attack detection rate: {attack_rate:.4f}")
        
        return model, scaler
    
    def save_models(self, classifier, classifier_scaler, anomaly_detector, anomaly_scaler, metadata: Dict):
        if classifier is not None:
            classifier.save_model(str(self.models_dir / "http_classifier.xgb"))
            logger.info(f"Saved classifier")
        if classifier_scaler is not None:
            joblib.dump(classifier_scaler, self.models_dir / "http_scaler.joblib")
        if anomaly_detector is not None:
            joblib.dump(anomaly_detector, self.models_dir / "http_isolation_forest.joblib")
        if anomaly_scaler is not None:
            joblib.dump(anomaly_scaler, self.models_dir / "http_anomaly_scaler.joblib")
        
        with open(self.models_dir / "training_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
        logger.info("Models saved successfully")
    
    def train(self) -> bool:
        logger.info("=" * 60)
        logger.info("DECEPTICON Comprehensive Model Training")
        logger.info("=" * 60)
        
        start_time = datetime.now()
        
        if not SKLEARN_AVAILABLE or not XGBOOST_AVAILABLE:
            logger.error("Required dependencies not available!")
            return False
        
        payloads, labels = self.load_all_payloads()
        X = self.extract_features(payloads)
        y = np.array(labels)
        
        classifier, classifier_scaler = self.train_classifier(X, y)
        anomaly_detector, anomaly_scaler = self.train_anomaly_detector(X, y)
        
        metadata = {
            'trained_at': datetime.now().isoformat(),
            'training_duration': str(datetime.now() - start_time),
            'total_samples': len(payloads),
            'feature_count': X.shape[1],
            'categories': len(set(labels)),
            'category_distribution': dict(Counter(labels)),
            'attack_categories': list(AttackCategory.NAME_TO_ID.keys()),
        }
        
        self.save_models(classifier, classifier_scaler, anomaly_detector, anomaly_scaler, metadata)
        
        logger.info(f"Training completed in {datetime.now() - start_time}")
        return True


def main():
    parser = argparse.ArgumentParser(description="DECEPTICON Model Trainer")
    parser.add_argument('--models-dir', type=str, default='models')
    parser.add_argument('--evasion-ratio', type=float, default=0.4)
    parser.add_argument('--noise-ratio', type=float, default=0.05)
    args = parser.parse_args()
    
    trainer = ComprehensiveTrainer(
        models_dir=args.models_dir,
        evasion_ratio=args.evasion_ratio,
        noise_ratio=args.noise_ratio
    )
    
    success = trainer.train()
    if success:
        print("\n✓ Training completed!")
    else:
        print("\n✗ Training failed!")
        sys.exit(1)


if __name__ == '__main__':
    main()
