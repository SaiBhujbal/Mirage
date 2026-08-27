> **Accuracy correction (2026):** Earlier revisions cited **99.84%** ML accuracy — a disproved synthetic-data figure. Measured performance is **97.43% accuracy / 0.44% FP on an offline test set**, and **4.99% false positives on independent CSIC-2010 benign traffic** (see LEGACY.md and ml/RESEARCH_DESIGN.md). ML runs shadow/high-precision by default; figures below are offline test metrics, not production.

# DECEPTICON WAF
## ML-Powered Web Application Firewall with ONNX Acceleration

**Naval SWAVLAMBAN 2025 - Challenge 3: ML-Based Adaptive Cybersecurity System**

Advanced Web Application Firewall with Machine Learning-based attack detection, ONNX-accelerated inference (6x faster), and seamless integration with open-source WAFs like ModSecurity.

---

## Features

- **5-Layer Defense Architecture**: Pattern → ML → Behavioral → Anomaly → Zero-Day
- **ML-Based Detection**: XGBoost classifier with 97.43% accuracy
- **ONNX Acceleration**: 6x faster inference (0.5ms vs 3.2ms)
- **16 Attack Categories**: SQLi, XSS, RCE, SSRF, XXE, SSTI, and more
- **Zero-Day Detection**: Isolation Forest anomaly detection
- **Deception Technology**: Honeypots for attacker intelligence gathering
- **ModSecurity Integration**: Seamless integration via REST API
- **Docker Deployment**: Production-ready with Grafana monitoring
- **Ultra-Low Latency**: <5ms P95 latency, 200+ req/s

---

## Table of Contents

1. [Installation](#installation)
2. [ML Model Training](#ml-model-training)
3. [ONNX Conversion](#onnx-conversion)
4. [Running the WAF](#running-the-waf)
5. [Docker Deployment](#docker-deployment)
6. [ModSecurity Integration](#modsecurity-integration)
7. [API Usage](#api-usage)
8. [Testing](#testing)

---

## Installation

### Prerequisites

- Python 3.11+
- 8GB RAM (minimum)
- Docker (optional, for production deployment)

### Setup

```bash
# Clone repository
git clone <repository-url>
cd decepticon-waf

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
```

### Payload Datasets Installation

The WAF uses popular security payload datasets for training and testing. Install them in the `data/payloads/` directory:

```bash
# Navigate to payloads directory
cd data/payloads

# Clone SecLists - Collection of security testing lists
git clone https://github.com/danielmiessler/SecLists.git

# Clone PayloadsAllTheThings - Useful payloads for web attacks
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# Clone FuzzDB - Attack patterns and discovery primitives
git clone https://github.com/fuzzdb-project/fuzzdb.git

# Return to project root
cd ../..
```

### Dataset Overview

| Dataset | Description | Size |
|---------|-------------|------|
| **SecLists** | Comprehensive wordlists for fuzzing, passwords, usernames, discovery | ~1GB |
| **PayloadsAllTheThings** | Attack payloads for SQLi, XSS, XXE, SSTI, and 50+ categories | ~200MB |
| **FuzzDB** | Attack patterns, regex patterns, web backdoors, discovery primitives | ~100MB |

### Directory Structure After Installation

```
data/payloads/
├── SecLists/
│   ├── Discovery/
│   ├── Fuzzing/
│   ├── Passwords/
│   ├── Payloads/
│   └── ...
├── PayloadsAllTheThings/
│   ├── SQL Injection/
│   ├── XSS Injection/
│   ├── XXE Injection/
│   └── ...
└── fuzzdb/
    ├── attack/
    ├── discovery/
    ├── regex/
    └── ...
```

> **Note**: These datasets are used for ML model training and security testing. Total download size is approximately 1.3GB.

---

## ML Model Training

Train the machine learning models before first use:

```bash
# Navigate to ML directory
cd ml

# Train both XGBoost classifier and Isolation Forest
python real_world_trainer.py
```

### What Happens:
- Loads training data from `data/trained/`
- Trains XGBoost classifier (16 attack categories)
- Trains Isolation Forest (anomaly detection)
- Saves models to `models/`:
  - `http_classifier.xgb` - Attack classifier
  - `http_isolation_forest.joblib` - Anomaly detector
  - `http_scaler.joblib` - Feature scaler

---

## ONNX Conversion

Convert trained models to ONNX format for 6x performance improvement:

```bash
# From ML directory
python convert_to_onnx.py
```

### Output Files:
- `models/http_classifier.onnx` - XGBoost classifier (primary detection model)
- `models/http_isolation_forest.onnx` - Anomaly detection (zero-day detection)
- `models/http_scaler.onnx` - Feature scaler (preprocessing)

---

## Running the WAF

### Start Server

```bash
# Return to project root
cd ..

# Start WAF server
python main.py server
```

Server starts on **http://localhost:8080**

### Available Commands

```bash
python main.py server     # Start WAF API server
python main.py demo       # Interactive demo
python main.py benchmark  # Performance benchmark
python main.py test       # Run test suite
python main.py attack     # Attack detection test
```

### Verify Server

```bash
curl http://localhost:8080/api/waf/health
```

```

---

## Docker Deployment

### Development Mode

```bash
# Build and start
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f waf

# Stop
docker-compose down
```

WAF accessible at: **http://localhost:8080**

### Production Mode (with Monitoring)

```bash
# Start with Grafana + Prometheus
docker-compose -f docker-compose.production.yml up -d

# Access services
# WAF:        http://localhost:8080
# Grafana:    http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090
```

### Inside Docker Container

```bash
# Execute bash in container
docker-compose exec waf bash

# Run tests inside container
cd tests/security
python run_quick_tests.py
```

**Note**: Docker image includes `jq` and `bc` for bash test scripts.

---

## ModSecurity Integration

DECEPTICON WAF can be integrated with ModSecurity (or any open-source WAF) as an ML enhancement layer.

### Integration Architecture

```
┌─────────────────────────────────────────┐
│          ModSecurity WAF                │
│    (Apache/Nginx + Core Rule Set)       │
└─────────────────┬───────────────────────┘
                  │
                  │ HTTP POST (Lua Hook)
                  ▼
┌─────────────────────────────────────────┐
│       DECEPTICON ML API                 │
│        http://localhost:8080            │
│                                         │
│  POST /api/waf/analyze                  │
│    - ML-based attack detection          │
│    - 97.43% accuracy                    │
│    - Zero-day detection                 │
│    - <5ms latency                       │
└─────────────────┬───────────────────────┘
                  │
                  ▼
      ┌──────────────────────┐
      │  Response:            │
      │  {                    │
      │    "action": "BLOCK", │
      │    "risk": "CRITICAL",│
      │    "detections": [...] │
      │  }                    │
      └──────────────────────┘
```

### ModSecurity Lua Integration

**File**: `/etc/modsecurity/decepticon_ml.lua`

```lua
-- DECEPTICON ML Integration for ModSecurity
local http = require "resty.http"
local cjson = require "cjson"

function check_with_ml(txn)
    local httpc = http.new()
    httpc:set_timeout(100)  -- 100ms timeout

    -- Build request payload
    local payload = cjson.encode({
        method = txn:getvar("REQUEST_METHOD"),
        path = txn:getvar("REQUEST_URI"),
        query = txn:getvar("QUERY_STRING") or "",
        body = txn:getvar("REQUEST_BODY") or "",
        headers = {
            ["user-agent"] = txn:getvar("HTTP:User-Agent"),
            ["content-type"] = txn:getvar("HTTP:Content-Type")
        },
        client_ip = txn:getvar("REMOTE_ADDR"),
        client_port = tonumber(txn:getvar("REMOTE_PORT"))
    })

    -- Call DECEPTICON API
    local res, err = httpc:request_uri("http://localhost:8080/api/waf/analyze", {
        method = "POST",
        body = payload,
        headers = {
            ["Content-Type"] = "application/json"
        }
    })

    if not res then
        -- Fail-open on API error (don't block legitimate traffic)
        return nil
    end

    -- Parse response
    local result = cjson.decode(res.body)

    if result.action == "BLOCK" then
        return result.risk_level, result.detections
    end

    return nil
end
```

**ModSecurity Configuration**: `/etc/modsecurity/modsecurity.conf`

```apache
# Enable Lua hook for DECEPTICON ML
SecRuleEngine On
SecDefaultAction "phase:1,pass,log"

# Call ML API before ModSecurity rules
SecRule REQUEST_METHOD "@rx .*" \
    "id:9000,\
     phase:1,\
     pass,\
     exec:/etc/modsecurity/decepticon_ml.lua"

# Block if ML detects attack
SecRule TX:ML_DECISION "@streq BLOCK" \
    "id:9001,\
     phase:2,\
     deny,\
     status:403,\
     msg:'Attack detected by DECEPTICON ML: %{TX.ML_DETAILS}'"
```

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name example.com;

    # Enable ModSecurity
    modsecurity on;
    modsecurity_rules_file /etc/modsecurity/modsecurity.conf;

    location / {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Start Both Services

```bash
# Terminal 1: Start DECEPTICON ML API
python main.py server

# Terminal 2: Restart Nginx/Apache with ModSecurity
sudo systemctl restart nginx
# or
sudo systemctl restart apache2
```

### Test Integration

```bash
# Send malicious request through ModSecurity
curl http://localhost/users?id=1+OR+1=1--

# ModSecurity logs will show:
# [ModSecurity] Attack detected by DECEPTICON ML: SQL Injection (confidence: 0.9987)
```

---

## API Usage

### Analyze Request

```bash
curl -X POST http://localhost:8080/api/waf/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "/users",
    "query": "id=1 OR 1=1--"
  }'
```

### Response

```json
{
  "request_id": "1e04dd2b-10ea-4e00-b08d-4267a95d1830",
  "action": "BLOCK",
  "risk_level": "CRITICAL",
  "latency_ms": 0.46,
  "detections": [
    {
      "source": "rules",
      "category": "SQLI",
      "confidence": 0.95,
      "rule_id": "SQLI-001",
      "matched_pattern": "Boolean-based SQLi"
    }
  ]
}
```

### Available Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/waf/health` | GET | Detailed health status |
| `/api/waf/analyze` | POST | Analyze single request |
| `/api/waf/test` | POST | Test endpoint |
| `/metrics` | GET | Prometheus metrics |
| `/docs` | GET | OpenAPI documentation |

---

## Testing

### Python Tests (Recommended - Works on All Platforms)

```bash
# Start WAF server first
python main.py server

# In another terminal
python tests/security/run_quick_tests.py
```

### Bash Tests (Linux/Docker only - Requires jq & bc)

```bash
# Install dependencies
sudo apt-get install jq bc  # Ubuntu/Debian
brew install jq bc          # macOS

# Run tests
cd tests/security
chmod +x run_quick_tests.sh
./run_quick_tests.sh
```

### Docker Tests

```bash
# Tests run automatically in Docker (jq & bc pre-installed)
docker-compose exec waf python tests/security/run_quick_tests.py
```


---

## Architecture

### 5-Layer Defense Architecture (Standalone Mode)

```
┌──────────────────────────────────────────┐
│         Client Request                   │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│      DECEPTICON WAF (5-Layer Defense)    │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Layer 1: Pattern Matching (<1ms)  │ │
│  │  - 185+ regex rules, 16 categories │ │
│  │  - Bloom filter pre-screening      │ │
│  └───────────────┬────────────────────┘ │
│                  ▼                       │
│  ┌────────────────────────────────────┐ │
│  │  Layer 2: ML Classifier (ONNX)     │ │
│  │  - XGBoost with 97.43% accuracy    │ │
│  │  - 45 engineered features          │ │
│  └───────────────┬────────────────────┘ │
│                  ▼                       │
│  ┌────────────────────────────────────┐ │
│  │  Layer 3: Behavioral Analysis      │ │
│  │  - Session tracking & fingerprint  │ │
│  │  - Bot detection & rate limiting   │ │
│  └───────────────┬────────────────────┘ │
│                  ▼                       │
│  ┌────────────────────────────────────┐ │
│  │  Layer 4: Anomaly Detection        │ │
│  │  - Isolation Forest model          │ │
│  │  - Statistical deviation analysis  │ │
│  └───────────────┬────────────────────┘ │
│                  ▼                       │
│  ┌────────────────────────────────────┐ │
│  │  Layer 5: Zero-Day Detection       │ │
│  │  - Entropy analysis & heuristics   │ │
│  │  - Novel pattern identification    │ │
│  └───────────────┬────────────────────┘ │
│                  ▼                       │
│              ALLOW/BLOCK                 │
└──────────────────────────────────────────┘
```

### Integrated Mode (with ModSecurity)

```
┌──────────────────────────────────────────┐
│         Client Request                   │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│     ModSecurity WAF (Primary Layer)      │
│  - Core Rule Set (CRS)                   │
│  - Pattern matching                      │
│  - Request validation                    │
└───────────────┬──────────────────────────┘
                │
                │ Lua Hook (async)
                ▼
┌──────────────────────────────────────────┐
│    DECEPTICON ML API (Enhancement)       │
│  - ML-based detection                    │
│  - Zero-day detection                    │
│  - Advanced evasion detection            │
└───────────────┬──────────────────────────┘
                │
                ▼
        ┌──────────────┐
        │  Final       │
        │  Decision:   │
        │  ALLOW/BLOCK │
        └──────────────┘
```

---

## Environment Variables

Create `.env` file (use `.env.example` as template):

```bash
# Core Settings
ENV=production
HOST=0.0.0.0
PORT=8080
WORKERS=4

# Security
TLS_ENABLED=true
TLS_CERT_PATH=./certs/cert.pem
TLS_KEY_PATH=./certs/key.pem

# Redis (for production)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_secure_password_here

# Session Encryption
SESSION_ENCRYPTION_KEY=your_32_byte_base64_key_here

# Admin Authentication
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your_bcrypt_hash_here

# ML Models (Real-world trained models)
ML_MODEL_PATH=./models/http_classifier.onnx
ML_ANOMALY_MODEL_PATH=./models/http_isolation_forest.onnx
ML_SCALER_PATH=./models/http_scaler.onnx
USE_ONNX=true
```

Generate secure values:

```bash
# Redis password
openssl rand -base64 32

# Session encryption key
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"

# Admin password hash
python -c "import bcrypt; print(bcrypt.hashpw(b'your_password', bcrypt.gensalt()).decode())"
```

---

## Project Structure

```
decepticon-waf/
├── api/                    # API endpoints
│   ├── app.py             # Main FastAPI app
│   └── secure_api.py      # Security middleware
├── ml/                     # Machine learning
│   ├── real_world_trainer.py    # Train models
│   ├── convert_to_onnx.py       # ONNX conversion
│   └── secure_inference.py      # ONNX inference
├── core/                   # Core WAF logic
│   ├── waf_engine.py      # Main WAF engine
│   ├── pattern_engine.py  # Pattern matching
│   └── rate_limiter.py    # Rate limiting
├── models/                 # Trained models
│   ├── *.onnx             # ONNX models (production)
│   └── *.joblib           # Original models
├── data/                   # Training data
│   └── trained/           # Training datasets
├── tests/                  # Test suite
│   └── security/          # Security tests
├── docker-compose.yml      # Development deployment
├── docker-compose.production.yml  # Production with monitoring
├── Dockerfile             # Docker image
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

---

## Troubleshooting

### Issue: "No ML model found"

**Solution**: Convert models to ONNX first:
```bash
cd ml && python convert_to_onnx.py
```

### Issue: ModSecurity integration not working

**Solution**: Check Lua module is installed:
```bash
# Nginx
nginx -V 2>&1 | grep lua

# Apache
apachectl -M | grep lua
```

Install if missing:
```bash
sudo apt-get install libnginx-mod-http-lua  # Nginx
sudo apt-get install libapache2-mod-security2  # Apache
```

### Issue: High latency

**Solution**:
1. Ensure ONNX models are being used (check logs for "ONNX Runtime")
2. Increase workers: `WORKERS=8` in `.env`
3. Use production mode: `ENV=production`

### Issue: Tests fail on Windows

**Solution**: Use Python test runner instead of bash scripts:
```bash
python tests/security/run_quick_tests.py
```

---

## License

MIT License

---

## Support

For issues or questions:
- Check logs: `logs/waf.log`
- Review metrics: `http://localhost:8080/metrics`
- Test health: `curl http://localhost:8080/api/waf/health`
