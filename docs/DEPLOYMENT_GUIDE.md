# MIRAGE WAF - Production Deployment Guide

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Security Checklist](#security-checklist)
4. [Installation Steps](#installation-steps)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Monitoring & Dashboards](#monitoring--dashboards)
8. [Health Checks & Verification](#health-checks--verification)
9. [Performance Tuning](#performance-tuning)
10. [Troubleshooting](#troubleshooting)
11. [Maintenance & Updates](#maintenance--updates)
12. [Security Hardening](#security-hardening)

---

## Overview

This guide covers deploying MIRAGE ML-WAF in a production environment with:

- **Docker Compose orchestration** - Multi-container architecture
- **Prometheus metrics** - Real-time performance monitoring
- **Grafana dashboards** - Visual analytics and security insights
- **Redis session storage** - High-performance caching
- **Production-hardened security** - Enterprise-grade protection

**Architecture:**
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  Reverse    │────▶│  MIRAGE │
│  Requests   │     │   Proxy     │     │     WAF     │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌──────────────────────────┼──────────────┐
                    │                          │              │
             ┌──────▼──────┐          ┌────────▼─────┐  ┌────▼────┐
             │   Redis     │          │  Prometheus  │  │ Grafana │
             │   Cache     │          │   Metrics    │  │Dashboard│
             └─────────────┘          └──────────────┘  └─────────┘
```

---

## Prerequisites

### System Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 4GB
- Disk: 20GB SSD
- OS: Linux (Ubuntu 20.04+, CentOS 8+, Debian 11+)

**Recommended:**
- CPU: 4 cores
- RAM: 8GB
- Disk: 50GB SSD
- OS: Ubuntu 22.04 LTS

### Software Requirements

```bash
# Docker
docker --version  # >= 20.10.0
docker-compose --version  # >= 1.29.0

# Python (for setup scripts)
python3 --version  # >= 3.9

# OpenSSL (for secret generation)
openssl version  # >= 1.1.1
```

### Network Requirements

**Ports:**
- `8080` - WAF API (should be behind reverse proxy)
- `3000` - Grafana Dashboard (restrict to admin IPs)
- `9090` - Prometheus (internal only, commented out by default)

**Firewall Rules:**
```bash
# Allow WAF traffic (via reverse proxy only)
sudo ufw allow from 10.0.0.0/8 to any port 8080

# Allow Grafana (restrict to admin network)
sudo ufw allow from 192.168.1.0/24 to any port 3000

# Block direct Prometheus access
sudo ufw deny 9090
```

---

## Security Checklist

**Before deploying, ensure:**

- [ ] All secrets in `.env` are generated with strong random values
- [ ] `.env` file permissions are set to `600` (read/write owner only)
- [ ] `.env` is NOT committed to version control (check `.gitignore`)
- [ ] Grafana default password is changed
- [ ] Redis password is strong (32+ characters)
- [ ] TLS certificates are valid and up-to-date
- [ ] WAF is behind a reverse proxy (Nginx, Caddy, or Traefik)
- [ ] Admin API access is IP-restricted
- [ ] Docker daemon is secured (non-root user, socket permissions)
- [ ] Container images are from trusted sources
- [ ] System firewall (ufw/iptables) is enabled
- [ ] SSH key-based authentication is enforced
- [ ] Security updates are applied to host OS

---

## Installation Steps

### Step 1: Clone Repository

```bash
# Clone the repository
git clone https://github.com/your-org/mirage-waf.git
cd mirage-waf

# Verify integrity (optional but recommended)
git verify-commit HEAD
```

### Step 2: Generate Secrets

**Option A: Automated Script**

```bash
# Create secret generation script
cat > generate_secrets.sh << 'EOF'
#!/bin/bash
echo "# MIRAGE WAF Secrets - Generated $(date)"
echo "# SAVE THIS OUTPUT SECURELY!"
echo ""

# Admin key
ADMIN_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
ADMIN_KEY_HASH=$(echo -n "$ADMIN_KEY" | python3 -c "import hashlib, sys; print(hashlib.sha256(sys.stdin.read().encode()).hexdigest())")
echo "# Admin Key (SAVE THIS): $ADMIN_KEY"
echo "MIRAGE_ADMIN_KEY_HASH=$ADMIN_KEY_HASH"
echo ""

# Model signing key
echo "MODEL_SIGNING_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")"

# Session encryption key
echo "SESSION_ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")"

# Redis password
echo "REDIS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"

# Redis secret suffix
echo "REDIS_SECRET_SUFFIX=$(python3 -c "import secrets; print(secrets.token_hex(8))")"

# Grafana password
echo "GRAFANA_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")"
echo ""
echo "# IMPORTANT: Copy these values to .env file"
EOF

chmod +x generate_secrets.sh
./generate_secrets.sh > secrets.txt

# CRITICAL: Save secrets.txt to a secure location (password manager, vault)
# Then delete it from the server after copying to .env
```

**Option B: Manual Generation**

```bash
# Redis password
openssl rand -base64 32

# Admin key (remember the key, use the hash in .env)
python3 -c "import secrets; key = secrets.token_urlsafe(32); import hashlib; print(f'Key: {key}\nHash: {hashlib.sha256(key.encode()).hexdigest()}')"

# Model signing key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Session encryption key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Redis secret suffix
python3 -c "import secrets; print(secrets.token_hex(8))"

# Grafana password
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

### Step 3: Configure Environment

```bash
# Copy environment template
cp .env.production.example .env

# Edit with your secrets
nano .env  # or vim, emacs, etc.

# Secure permissions
chmod 600 .env

# Verify configuration
cat .env | grep -v "^#" | grep -v "^$"
```

### Step 4: Prepare ML Models

```bash
# Ensure trained models exist
ls -lh models/

# Required files:
# - http_classifier.xgb
# - dual_layer_signatures.json
# - dual_layer_metadata.json

# If models don't exist, train them:
python3 ml/train_dual_layer.py

# Verify model integrity
python3 -c "from ml.dual_layer_inference import DualLayerPredictor; p = DualLayerPredictor(); print('Models loaded successfully')"
```

---

## Configuration

### Docker Compose Configuration

The `docker-compose.production.yml` is pre-configured with secure defaults. Review and adjust if needed:

```yaml
# Key configuration sections:

# WAF Service
services:
  waf:
    ports:
      - "8080:8080"  # Change if using different port
    environment:
      - WORKERS=4    # Adjust based on CPU cores
    deploy:
      resources:
        limits:
          cpus: '2'     # Adjust based on available resources
          memory: 2G

# Prometheus
  prometheus:
    command:
      - '--storage.tsdb.retention.time=15d'  # Adjust retention

# Grafana
  grafana:
    ports:
      - "3000:3000"  # Change if port conflicts exist
```

### Reverse Proxy Configuration

**Nginx Example:**

```nginx
# /etc/nginx/sites-available/mirage-waf

upstream mirage_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name waf.yourdomain.com;

    # TLS Configuration
    ssl_certificate /etc/letsencrypt/live/waf.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/waf.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=waf_api:10m rate=10r/s;
    limit_req zone=waf_api burst=20 nodelay;

    # WAF API
    location /api/ {
        proxy_pass http://mirage_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }

    # Health check (no auth)
    location /api/waf/health {
        proxy_pass http://mirage_backend;
        access_log off;
    }

    # Metrics (restrict to monitoring IPs)
    location /metrics {
        allow 10.0.0.0/8;  # Internal network only
        deny all;
        proxy_pass http://mirage_backend;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name waf.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

**Enable Nginx configuration:**

```bash
sudo ln -s /etc/nginx/sites-available/mirage-waf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Deployment

### Production Deployment

```bash
# Pull latest images
docker-compose -f docker-compose.production.yml pull

# Build WAF image
docker-compose -f docker-compose.production.yml build

# Start services (detached mode)
docker-compose -f docker-compose.production.yml up -d

# Verify all services are running
docker-compose -f docker-compose.production.yml ps

# Expected output:
# NAME                      STATUS          PORTS
# mirage-waf            Up (healthy)    0.0.0.0:8080->8080/tcp
# mirage-redis          Up (healthy)
# mirage-prometheus     Up (healthy)
# mirage-grafana        Up (healthy)    0.0.0.0:3000->3000/tcp
```

### Verify Deployment

```bash
# Check WAF health
curl http://localhost:8080/api/waf/health

# Expected: {"status": "healthy", "timestamp": "..."}

# Check Prometheus
docker exec mirage-prometheus wget -qO- http://localhost:9090/-/healthy

# Expected: Prometheus is Healthy.

# Check Grafana
curl http://localhost:3000/api/health

# Expected: {"database": "ok", "version": "..."}

# Check Redis
docker exec mirage-redis redis-cli -a "$REDIS_PASSWORD" ping

# Expected: PONG
```

### View Logs

```bash
# All services
docker-compose -f docker-compose.production.yml logs -f

# Specific service
docker-compose -f docker-compose.production.yml logs -f waf

# With timestamps
docker-compose -f docker-compose.production.yml logs -f --timestamps waf

# Last 100 lines
docker-compose -f docker-compose.production.yml logs --tail=100 waf
```

---

## Monitoring & Dashboards

### Access Grafana

1. **Open Grafana:**
   ```
   http://your-server:3000
   ```

2. **Login:**
   - Username: `admin` (or value from `GRAFANA_USER`)
   - Password: (value from `GRAFANA_PASSWORD` in `.env`)

3. **Available Dashboards:**
   - **WAF Overview** - Real-time security metrics, blocked attacks, throughput
   - **ML Performance** - Model accuracy, latency, FP/FN tracking
   - **Security Metrics** - Threat intelligence, attack timeline, anomalies

### Prometheus Metrics

Access Prometheus UI (internal only):

```bash
# Port forward for local access
docker exec -it mirage-prometheus wget -qO- http://localhost:9090

# Or expose temporarily (NOT recommended for production)
# Uncomment ports in docker-compose.production.yml
```

**Key Metrics:**

```promql
# Request rate
rate(waf_requests_total[1m])

# Block rate
rate(waf_requests_blocked_total[1m])

# ML latency (P95)
histogram_quantile(0.95, rate(waf_ml_prediction_latency_seconds_bucket[1m]))

# False positive rate
waf_false_positive_rate

# Attack categories
waf_requests_blocked_total{attack_category="sqli"}
```

### Alerts

**Configured Alerts** (in `config/prometheus_rules/waf_alerts.yml`):

- High ML latency (>5ms P95)
- Critical ML latency (>10ms P95)
- Zero-day spike (>5 detections/5min)
- High false positive rate (>5%)
- Redis connection failures
- WAF service down

**Email Notifications** (optional):

Configure Alertmanager by uncommenting the alerting section in `deploy/prometheus.yml`.

---

## Health Checks & Verification

### Automated Health Checks

```bash
#!/bin/bash
# health_check.sh

# WAF health
WAF_HEALTH=$(curl -s http://localhost:8080/api/waf/health | jq -r '.status')
if [ "$WAF_HEALTH" != "healthy" ]; then
    echo "ERROR: WAF is unhealthy"
    exit 1
fi

# Prometheus health
PROM_HEALTH=$(docker exec mirage-prometheus wget -qO- http://localhost:9090/-/healthy 2>/dev/null)
if [ "$PROM_HEALTH" != "Prometheus is Healthy." ]; then
    echo "ERROR: Prometheus is unhealthy"
    exit 1
fi

# Grafana health
GRAFANA_HEALTH=$(curl -s http://localhost:3000/api/health | jq -r '.database')
if [ "$GRAFANA_HEALTH" != "ok" ]; then
    echo "ERROR: Grafana is unhealthy"
    exit 1
fi

# Redis health
REDIS_HEALTH=$(docker exec mirage-redis redis-cli -a "$REDIS_PASSWORD" ping 2>/dev/null)
if [ "$REDIS_HEALTH" != "PONG" ]; then
    echo "ERROR: Redis is unhealthy"
    exit 1
fi

echo "✅ All services healthy"
```

### Security Verification

```bash
#!/bin/bash
# security_check.sh

# Redis should NOT be accessible externally
if nmap -p 6379 localhost | grep -q "open"; then
    echo "⚠️ WARNING: Redis port is exposed!"
fi

# API should require authentication
if curl -s http://localhost:8080/api/waf/rules | grep -q "401"; then
    echo "✅ API authentication is enforced"
else
    echo "⚠️ WARNING: API authentication may not be working"
fi

# HSTS header should be present (if behind reverse proxy)
if curl -sI https://waf.yourdomain.com | grep -q "Strict-Transport-Security"; then
    echo "✅ HSTS is enabled"
else
    echo "⚠️ WARNING: HSTS header not found"
fi
```

---

## Performance Tuning

### WAF Service

**Worker Processes:**

```yaml
# docker-compose.production.yml
environment:
  - WORKERS=4  # Set to number of CPU cores
```

**Resource Limits:**

```yaml
# Increase for high-traffic environments
deploy:
  resources:
    limits:
      cpus: '4'      # More cores = higher throughput
      memory: 4G     # More memory = larger cache
```

### Redis Optimization

**Memory Policy:**

```yaml
# docker-compose.production.yml (Redis command section)
--maxmemory 1gb               # Increase for more caching
--maxmemory-policy allkeys-lru  # Keep most recently used
```

### Prometheus Retention

```yaml
# docker-compose.production.yml (Prometheus command section)
- '--storage.tsdb.retention.time=30d'  # Increase for longer history
```

### Performance Benchmarking

```bash
# Run baseline traffic test
python3 tests/baseline_traffic_test.py

# Run ML performance benchmark
python3 ml/performance_optimizer.py

# Load testing with Apache Bench
ab -n 1000 -c 10 -H "Content-Type: application/json" \
   -p payload.json http://localhost:8080/api/waf/analyze
```

**Target Metrics:**
- ML Latency P95: <5ms ✅
- Throughput: >200 req/s ✅
- Accuracy: >99% ✅
- False Positive Rate: <1% ✅

---

## Troubleshooting

### Common Issues

#### 1. Services Won't Start

```bash
# Check Docker daemon
sudo systemctl status docker

# Check logs
docker-compose -f docker-compose.production.yml logs

# Check resource usage
docker stats

# Check disk space
df -h
```

#### 2. Redis Connection Errors

```bash
# Verify Redis is running
docker-compose -f docker-compose.production.yml ps redis

# Check Redis logs
docker-compose -f docker-compose.production.yml logs redis

# Test connection
docker exec mirage-redis redis-cli -a "$REDIS_PASSWORD" ping
```

#### 3. ML Model Not Loading

```bash
# Verify models exist
ls -lh models/

# Check WAF logs for errors
docker-compose -f docker-compose.production.yml logs waf | grep -i "model"

# Test model manually
docker exec -it mirage-waf python3 -c "from ml.dual_layer_inference import DualLayerPredictor; p = DualLayerPredictor(); print('OK')"
```

#### 4. High Latency

```bash
# Check Grafana "ML Performance" dashboard

# Run performance benchmark
docker exec -it mirage-waf python3 ml/performance_optimizer.py

# Check resource limits
docker stats mirage-waf

# Increase workers/resources if needed
```

#### 5. Grafana Dashboards Not Loading

```bash
# Check provisioning
docker exec mirage-grafana ls -la /etc/grafana/provisioning/dashboards/json/

# Verify datasource
docker exec mirage-grafana curl -s http://prometheus:9090/api/v1/status/config

# Restart Grafana
docker-compose -f docker-compose.production.yml restart grafana
```

---

## Maintenance & Updates

### Update WAF

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose -f docker-compose.production.yml up -d --build waf

# Verify
curl http://localhost:8080/api/waf/health
```

### Retrain ML Models

```bash
# Backup old models
cp -r models models_backup_$(date +%Y%m%d)

# Train new models
python3 ml/train_dual_layer.py

# Test new models
python3 tests/test_ml_model.py

# Deploy (restart WAF to load new models)
docker-compose -f docker-compose.production.yml restart waf
```

### Backup & Restore

**Backup:**

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups/mirage-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup volumes
docker run --rm -v mirage-waf_redis-data:/data \
  -v "$BACKUP_DIR":/backup alpine tar czf /backup/redis-data.tar.gz /data

docker run --rm -v mirage-waf_prometheus-data:/prometheus \
  -v "$BACKUP_DIR":/backup alpine tar czf /backup/prometheus-data.tar.gz /prometheus

docker run --rm -v mirage-waf_grafana-data:/var/lib/grafana \
  -v "$BACKUP_DIR":/backup alpine tar czf /backup/grafana-data.tar.gz /var/lib/grafana

# Backup configuration
cp .env "$BACKUP_DIR/"
cp docker-compose.production.yml "$BACKUP_DIR/"
cp -r models "$BACKUP_DIR/"

echo "Backup complete: $BACKUP_DIR"
```

**Restore:**

```bash
#!/bin/bash
# restore.sh

BACKUP_DIR="$1"

# Stop services
docker-compose -f docker-compose.production.yml down

# Restore volumes
docker run --rm -v mirage-waf_redis-data:/data \
  -v "$BACKUP_DIR":/backup alpine sh -c "cd /data && tar xzf /backup/redis-data.tar.gz --strip 1"

# Restore configuration
cp "$BACKUP_DIR/.env" .
cp "$BACKUP_DIR/docker-compose.production.yml" .
cp -r "$BACKUP_DIR/models" .

# Restart services
docker-compose -f docker-compose.production.yml up -d

echo "Restore complete"
```

### Log Rotation

```bash
# /etc/logrotate.d/docker-mirage

/var/lib/docker/containers/*/*.log {
    rotate 7
    daily
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    maxsize 100M
    postrotate
        docker kill --signal=USR1 mirage-waf 2>/dev/null || true
    endscript
}
```

---

## Security Hardening

### Post-Deployment Security

1. **Delete Secret Generation Files:**
   ```bash
   rm -f secrets.txt generate_secrets.sh
   ```

2. **Harden Docker:**
   ```bash
   # Enable user namespaces
   sudo dockerd --userns-remap=default

   # Disable inter-container communication
   sudo dockerd --icc=false
   ```

3. **Enable Audit Logging:**
   ```bash
   # Install auditd
   sudo apt install auditd

   # Monitor Docker
   sudo auditctl -w /var/lib/docker -p wa
   sudo auditctl -w /etc/docker -p wa
   ```

4. **Regular Security Scans:**
   ```bash
   # Scan Docker images
   docker scan mirage-waf

   # Check for vulnerabilities
   trivy image mirage-waf:latest
   ```

5. **Implement Fail2Ban:**
   ```bash
   # /etc/fail2ban/jail.d/mirage.conf
   [mirage-waf]
   enabled = true
   port = 8080
   filter = mirage
   logpath = /var/log/mirage/access.log
   maxretry = 5
   bantime = 3600
   ```

### Monitoring Security

- Review Grafana security dashboard daily
- Check for zero-day detections
- Monitor false positive rates
- Audit admin access logs
- Review blocked attack patterns

---

## Support & Additional Resources

- **Documentation:** `docs/`
- **API Reference:** `docs/API_REFERENCE.md`
- **ML Training Guide:** `docs/ML_TRAINING_GUIDE.md`
- **Integration Guide:** `integrations/INTEGRATION_GUIDE.md`
- **Compliance Report:** `NAVAL_SWAVLAMBAN_2025_COMPLIANCE.md`

For issues or questions, contact your security team or refer to the project repository.
