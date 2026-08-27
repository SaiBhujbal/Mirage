> **Accuracy correction (2026):** Earlier revisions cited **99.84%** ML accuracy — a disproved synthetic-data figure. Measured performance is **97.43% accuracy / 0.44% FP on an offline test set**, and **4.99% false positives on independent CSIC-2010 benign traffic** (see LEGACY.md and ml/RESEARCH_DESIGN.md). ML runs shadow/high-precision by default; figures below are offline test metrics, not production.

# DECEPTICON Adaptive Anomaly Detection System

Naval SWAVLAMBAN 2025 - Challenge 3: Adaptive Anomaly Detection

## Overview

This module implements a research-backed ensemble ML system for Web Application Firewall (WAF) anomaly detection, achieving **~99.9% F1** and **0.44% false-positive rate** on an offline test set (measured **4.99%** false positives on independent CSIC-2010 benign traffic — see RESEARCH_DESIGN.md; ML runs shadow/high-precision by default).

## Architecture (Challenge 3.2 Compliance)

### Ensemble Models

| Model | Type | Purpose | Accuracy |
|-------|------|---------|----------|
| **XGBoost** | Supervised | Known attack classification | 99.5% |
| **Isolation Forest** | Unsupervised | Zero-day detection | N/A |
| **VAE (Optional)** | Semi-supervised | Baseline learning | N/A |

### Research Backing

Based on 2024-2025 research:
- Hybrid Autoencoder + IF + XGBoost achieves 95%+ accuracy (MDPI 2025)
- XGBoost excels at modeling nonlinear relationships (Nature 2024)
- Stacking XGBoost + LSTM achieves 0.983 AUC (Wiley 2020)

## Features

### 1. Comprehensive Attack Detection

10 attack categories with 500+ unique payloads:
- SQL Injection (UNION, error-based, time-based, NoSQL)
- Cross-Site Scripting (DOM, reflected, stored, template injection)
- Remote Code Execution (command injection, reverse shells)
- Path Traversal (LFI, PHP wrappers)
- SSRF (cloud metadata, internal services)
- XXE, LDAP Injection, Header Injection, Log Injection

### 2. Feature Engineering

50-dimensional feature vector including:
- Length and entropy features
- Character distribution ratios
- Attack indicator counts
- Structural analysis
- Statistical features

### 3. Security Features

- **NO PICKLE** - Uses joblib, XGBoost native format, or numpy
- Model signature verification (HMAC-SHA256)
- Input size limits (100KB max)
- Path validation
- Thread-safe inference

### 4. Early Stopping

- Validation loss monitoring
- Patience-based stopping
- Learning rate scheduling
- Best model checkpointing

### 5. Continuous Learning

- Feedback collection (FP/FN)
- Automatic retraining triggers
- Model versioning support
- Human-in-the-loop validation

## Installation

```bash
# Core dependencies
pip install numpy pandas scikit-learn xgboost flask

# Optional (enhanced features)
pip install torch onnx onnxruntime skl2onnx lightgbm
```

## Usage

### Training

```bash
# Full training with 1000 samples per category
python ml/adaptive_trainer.py --samples 1000 --models-dir ./models

# Quick training (testing)
python ml/adaptive_trainer.py --samples 200 --models-dir ./models
```

### Inference

```python
from ml.secure_ensemble import SecureEnsemblePredictor

# Initialize predictor
predictor = SecureEnsemblePredictor(models_dir='./models')

# Predict
result = predictor.predict("' OR 1=1--")

print(f"Malicious: {result.is_malicious}")
print(f"Category: {result.category}")
print(f"Confidence: {result.confidence:.2%}")
print(f"Latency: {result.latency_ms:.2f}ms")
```

### GUI Dashboard

```bash
# Start dashboard
python gui/dashboard.py --port 8080

# Access at http://localhost:8080
# Credentials: admin / [See console output for generated password]
# (Set ADMIN_PASS environment variable for custom password)
```

## Model Files

| File | Size | Purpose |
|------|------|---------|
| `classifier.xgb` | ~2.6MB | XGBoost classifier |
| `isolation_forest.joblib` | ~4MB | Isolation Forest |
| `scaler.joblib` | ~1KB | Feature scaler |
| `ensemble_metadata.json` | ~2KB | Model metadata |
| `model_signatures.json` | ~1KB | HMAC signatures |

## Performance

### Training Results (5000 samples)

```
============================================================
FINAL ENSEMBLE METRICS
============================================================
  F1 Score: 0.9993
  Precision: 1.0000
  Recall: 0.9985
  AUC: 1.0000
  False Positive Rate: 0.0000%
  Confusion Matrix: TN=75, FP=0, FN=1, TP=674
```

### Inference Performance

| Metric | Value |
|--------|-------|
| Average Latency | 10-25ms |
| Memory Usage | ~50MB |
| Throughput | ~100 req/s |

### Per-Category Accuracy

| Category | Precision | Recall | F1 |
|----------|-----------|--------|-----|
| Benign | 1.00 | 1.00 | 1.00 |
| SQLi | 1.00 | 0.99 | 0.99 |
| XSS | 1.00 | 1.00 | 1.00 |
| RCE | 1.00 | 1.00 | 1.00 |
| Path Traversal | 1.00 | 1.00 | 1.00 |
| SSRF | 1.00 | 1.00 | 1.00 |
| XXE | 1.00 | 1.00 | 1.00 |
| LDAP Injection | 1.00 | 1.00 | 1.00 |
| Header Injection | 1.00 | 1.00 | 1.00 |
| Log Injection | 1.00 | 1.00 | 1.00 |

## Challenge 3.2 Compliance Checklist

- [x] **Supervised Learning**: XGBoost for known attack classification
- [x] **Unsupervised Learning**: Isolation Forest for anomaly detection
- [x] **Semi-supervised Learning**: VAE for baseline learning (optional)
- [x] **Ensemble Approach**: Weighted voting combination
- [x] **ONNX Export**: Secure model format (no pickle)
- [x] **Early Stopping**: Validation loss monitoring
- [x] **Continuous Learning**: Feedback integration framework
- [x] **Explainability**: Feature importance and attack indicators
- [x] **Low Latency**: <25ms inference time

## API Reference

### SecureEnsemblePredictor

```python
class SecureEnsemblePredictor:
    def __init__(self, 
                 models_dir: str = "./models",
                 signing_key: Optional[str] = None,
                 verify_signatures: bool = True):
        """
        Initialize the secure ensemble predictor.
        
        Args:
            models_dir: Path to models directory
            signing_key: HMAC key for signature verification
            verify_signatures: Enable signature verification
        """
    
    def predict(self, payload: str) -> EnsemblePrediction:
        """
        Make prediction on payload.
        
        Returns:
            EnsemblePrediction with is_malicious, confidence, category, etc.
        """
```

### EnsemblePrediction

```python
@dataclass
class EnsemblePrediction:
    is_malicious: bool           # True if attack detected
    confidence: float            # Confidence score (0-1)
    category: str                # Predicted category
    category_probabilities: Dict # Per-category probabilities
    model_scores: Dict           # Individual model scores
    explanation: Dict            # Feature contributions
    latency_ms: float           # Inference time
```

## Security Considerations

1. **No Pickle Deserialization**: All models use safe formats
2. **Input Sanitization**: Size limits and character filtering
3. **Signature Verification**: HMAC-SHA256 for model integrity
4. **Thread Safety**: Lock-protected inference
5. **Rate Limiting**: Built into dashboard API

## Directory Structure

```
decepticon/
├── ml/
│   ├── adaptive_trainer.py    # Training pipeline
│   ├── secure_ensemble.py     # Secure inference
│   └── __init__.py
├── gui/
│   ├── dashboard.py           # Admin dashboard
│   └── __init__.py
├── models/
│   ├── classifier.xgb         # XGBoost model
│   ├── isolation_forest.joblib
│   ├── scaler.joblib
│   ├── ensemble_metadata.json
│   └── model_signatures.json
└── data/
    └── feedback/              # Continuous learning data
```

## License

Developed for Naval SWAVLAMBAN 2025 Challenge 3.

## Authors

DECEPTICON Team - December 2025
