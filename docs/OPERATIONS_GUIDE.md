# DECEPTICON WAF - Operations Guide

## Table of Contents

1. [Monitoring](#monitoring)
2. [Performance Testing](#performance-testing)
3. [Security Testing](#security-testing)
4. [Log Management](#log-management)
5. [Incident Response](#incident-response)
6. [Maintenance Tasks](#maintenance-tasks)
7. [Backup & Recovery](#backup--recovery)
8. [Scaling](#scaling)
9. [Automation](#automation)

---

## Monitoring

### Grafana Dashboards

#### 1. WAF Overview Dashboard

**Key Metrics:**
- WAF status (online/offline)
- Request rate (req/s)
- Block rate (%)
- Top attack categories
- Geographic distribution of attacks
- ML prediction latency (P50, P95, P99)

**Access:** `http://your-server:3000` → WAF Overview

**Alerts:**
- WAF service down
- High block rate (>20% for 5 minutes)
- ML latency spike (>10ms P95)

#### 2. ML Performance Dashboard

**Key Metrics:**
- Model accuracy (%)
- False positive rate (%)
- False negative count
- Feature importance
- Cache hit rate (%)
- Tier distribution (fast/cache/ml)

**Access:** `http://your-server:3000` → ML Performance

**Alerts:**
- High FP rate (>5%)
- FN detection (any false negative)
- Low cache hit rate (<30%)

#### 3. Security Metrics Dashboard

**Key Metrics:**
- Attack timeline (time-series)
- Zero-day detections
- Attack campaigns
- Bot activity
- API abuse events
- Anomaly spikes

**Access:** `http://your-server:3000` → Security Metrics

**Alerts:**
- Zero-day spike (>5 detections/5min)
- Attack campaign detected
- Coordinated attack (>10 sources)

### Prometheus Queries

**Request Metrics:**

```promql
# Total requests per second
rate(waf_requests_total[1m])

# Blocked requests per second
rate(waf_requests_blocked_total[1m])

# Block rate percentage
100 * rate(waf_requests_blocked_total[1m]) / rate(waf_requests_total[1m])

# Requests by attack category
sum by (attack_category) (waf_requests_blocked_total)
```

**Performance Metrics:**

```promql
# ML latency P50
histogram_quantile(0.50, rate(waf_ml_prediction_latency_seconds_bucket[1m])) * 1000

# ML latency P95
histogram_quantile(0.95, rate(waf_ml_prediction_latency_seconds_bucket[1m])) * 1000

# ML latency P99
histogram_quantile(0.99, rate(waf_ml_prediction_latency_seconds_bucket[1m])) * 1000

# Cache hit rate
waf_cache_hit_rate
```

**Security Metrics:**

```promql
# False positive rate
waf_false_positive_rate

# False negatives in last hour
increase(waf_false_negatives_total[1h])

# Zero-day detections
rate(waf_zero_day_detections_total[5m])

# Anomaly score (current)
waf_anomaly_score
```

**System Metrics:**

```promql
# CPU usage (container)
rate(container_cpu_usage_seconds_total{name="decepticon-waf"}[1m]) * 100

# Memory usage (container)
container_memory_usage_bytes{name="decepticon-waf"} / 1024 / 1024

# Redis memory usage
redis_memory_used_bytes / 1024 / 1024
```

### Custom Alerts

**Critical Alerts:**

```yaml
# config/prometheus_rules/custom_alerts.yml

groups:
  - name: waf_critical
    rules:
      # Service down
      - alert: WAFServiceDown
        expr: up{job="waf-metrics"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WAF service is down"
          description: "WAF has been down for more than 1 minute"

      # Zero-day attack
      - alert: ZeroDayAttack
        expr: rate(waf_zero_day_detections_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Zero-day attack detected"
          description: "Unknown attack pattern detected: {{ $value }} detections/5min"

      # False negative detected
      - alert: FalseNegativeDetected
        expr: increase(waf_false_negatives_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "False negative detected"
          description: "Attack bypassed detection: {{ $value }} FNs in 5min"

  - name: waf_warning
    rules:
      # High latency
      - alert: HighMLLatency
        expr: histogram_quantile(0.95, rate(waf_ml_prediction_latency_seconds_bucket[1m])) > 0.010
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High ML prediction latency"
          description: "P95 latency is {{ $value }}s (target: <5ms)"

      # High false positive rate
      - alert: HighFalsePositiveRate
        expr: waf_false_positive_rate > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High false positive rate"
          description: "FP rate is {{ $value }} (target: <1%)"
```

---

## Performance Testing

### Baseline Traffic Test

**Run comprehensive baseline scenarios:**

```bash
python3 tests/baseline_traffic_test.py
```

**Output:**
```
=== BASELINE TRAFFIC TEST ===

Scenario 1: Normal User Browsing
✓ Requests: 100
✓ Accuracy: 100.0%
✓ False Positives: 0 (0.0%)
✓ False Negatives: 0 (0.0%)
✓ Average Latency: 2.3ms

Scenario 2: Mixed Attack Traffic
✓ Requests: 200
✓ Accuracy: 98.5%
✓ False Positives: 3 (1.5%)
✓ False Negatives: 0 (0.0%)
✓ Average Latency: 3.1ms

... (7 scenarios total)

=== SUMMARY ===
Total Requests: 1000
Overall Accuracy: 99.2%
Overall FP Rate: 0.8%
Overall FN Rate: 0.0%
Average Latency: 2.8ms
```

### ML Performance Benchmark

**Run performance optimizer:**

```bash
python3 ml/performance_optimizer.py
```

**Expected Output:**
```
=== ML PERFORMANCE OPTIMIZER ===

Testing individual predictions:

✓ SQLi: malicious=True, confidence=99%, latency=2.10ms, tier=ml
✓ XSS: malicious=True, confidence=98%, latency=0.45ms, tier=fast
✓ RCE: malicious=True, confidence=97%, latency=0.08ms, tier=cache
✓ Path Traversal: malicious=True, confidence=96%, latency=2.30ms, tier=ml
✓ SSRF: malicious=True, confidence=99%, latency=0.42ms, tier=fast
✓ Benign: malicious=False, confidence=95%, latency=2.15ms, tier=ml

============================================================

Running performance benchmark: 1000 predictions...

=== PERFORMANCE RESULTS ===
Total Predictions: 1000
Total Time: 3.21s
Throughput: 312 req/s

Latency Metrics:
  Average:  3.21ms
  P50:      2.10ms
  P95:      4.80ms ✅ (Target: <5ms)
  P99:      6.20ms

Cache Hit Rate: 45.2%

✅ TARGET MET: P95 latency 4.80ms < 5ms
```

### Load Testing

**Apache Bench:**

```bash
# Create test payload
cat > payload.json << EOF
{
  "method": "GET",
  "path": "/api/users",
  "query": "page=1",
  "headers": {"user-agent": "Mozilla/5.0"},
  "source_ip": "192.168.1.100"
}
EOF

# Run load test
ab -n 10000 -c 100 -T "application/json" \
   -p payload.json \
   http://localhost:8080/api/waf/analyze

# Expected results:
# Requests per second: 300+ req/s
# Time per request: <5ms (95th percentile)
# Failed requests: 0
```

**wrk (Advanced):**

```bash
# Install wrk
sudo apt install wrk  # Ubuntu/Debian

# Run load test
wrk -t4 -c100 -d30s --latency \
    -s test_script.lua \
    http://localhost:8080/api/waf/analyze

# test_script.lua:
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body = '{"method":"GET","path":"/api/users","query":"page=1"}'
```

### Stress Testing

**Find breaking point:**

```bash
#!/bin/bash
# stress_test.sh

for concurrency in 10 50 100 200 500 1000; do
    echo "Testing with $concurrency concurrent requests..."

    ab -n 10000 -c $concurrency -T "application/json" \
       -p payload.json \
       http://localhost:8080/api/waf/analyze \
       | grep -E "Requests per second|Time per request|Failed"

    echo "---"
done
```

---

## Security Testing

### Attack Simulation

**Test detection capabilities:**

```bash
#!/bin/bash
# attack_simulation.sh

API_URL="http://localhost:8080/api/waf/analyze"

declare -A attacks=(
    ["SQLi"]='{"method":"GET","path":"/users","query":"id=1 OR 1=1--"}'
    ["XSS"]='{"method":"POST","path":"/comment","body":"<script>alert(1)</script>"}'
    ["RCE"]='{"method":"GET","path":"/exec","query":"cmd=; cat /etc/passwd"}'
    ["PathTraversal"]='{"method":"GET","path":"/files","query":"path=../../../etc/passwd"}'
    ["SSRF"]='{"method":"GET","path":"/proxy","query":"url=http://169.254.169.254/"}'
    ["SSTI"]='{"method":"POST","path":"/template","body":"{{7*7}}"}'
    ["NoSQLi"]='{"method":"POST","path":"/login","body":"{\\"username\\":{\\"$ne\\":null}}"}'
)

echo "=== ATTACK DETECTION TEST ==="
echo ""

for attack_type in "${!attacks[@]}"; do
    echo "Testing $attack_type..."

    response=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "${attacks[$attack_type]}")

    is_malicious=$(echo "$response" | jq -r '.is_malicious')
    category=$(echo "$response" | jq -r '.category')
    confidence=$(echo "$response" | jq -r '.confidence')

    if [ "$is_malicious" = "true" ]; then
        echo "✅ DETECTED: $category (confidence: $confidence)"
    else
        echo "❌ MISSED: Not detected"
    fi
    echo ""
done
```

### Bypass Testing

**Test evasion techniques:**

```bash
#!/bin/bash
# bypass_test.sh

API_URL="http://localhost:8080/api/waf/analyze"

# Evasion techniques
evasions=(
    # URL encoding
    '{"method":"GET","path":"/users","query":"id=1%20OR%201=1--"}'

    # Double encoding
    '{"method":"GET","path":"/users","query":"id=1%2520OR%25201=1--"}'

    # Case variation
    '{"method":"GET","path":"/users","query":"id=1 oR 1=1--"}'

    # Comment injection
    '{"method":"GET","path":"/users","query":"id=1/**/OR/**/1=1--"}'

    # Whitespace variation
    '{"method":"GET","path":"/users","query":"id=1\tOR\t1=1--"}'
)

echo "=== BYPASS/EVASION TEST ==="
echo ""

for i in "${!evasions[@]}"; do
    echo "Testing evasion technique $((i+1))..."

    response=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "${evasions[$i]}")

    is_malicious=$(echo "$response" | jq -r '.is_malicious')

    if [ "$is_malicious" = "true" ]; then
        echo "✅ BLOCKED: Evasion detected"
    else
        echo "❌ BYPASSED: Evasion successful (SECURITY ISSUE!)"
    fi
    echo ""
done
```

### False Positive Testing

**Test benign requests:**

```bash
#!/bin/bash
# false_positive_test.sh

API_URL="http://localhost:8080/api/waf/analyze"

benign_requests=(
    # Normal API calls
    '{"method":"GET","path":"/api/users","query":"page=1&sort=name"}'
    '{"method":"GET","path":"/api/products","query":"category=electronics"}'

    # Search queries
    '{"method":"GET","path":"/search","query":"q=how to select items from database"}'

    # JSON data
    '{"method":"POST","path":"/api/user","body":"{\\"name\\":\\"John\\"}"}'

    # URLs in content
    '{"method":"POST","path":"/api/bookmark","body":"{\\"url\\":\\"https://example.com\\"}"}'

    # Code snippets (legitimate)
    '{"method":"POST","path":"/api/code","body":"SELECT * FROM users WHERE id = ?"}'
)

echo "=== FALSE POSITIVE TEST ==="
echo ""

fp_count=0
total=${#benign_requests[@]}

for i in "${!benign_requests[@]}"; do
    echo "Testing benign request $((i+1))..."

    response=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "${benign_requests[$i]}")

    is_malicious=$(echo "$response" | jq -r '.is_malicious')

    if [ "$is_malicious" = "false" ]; then
        echo "✅ ALLOWED: Correctly identified as benign"
    else
        echo "❌ BLOCKED: False positive detected!"
        ((fp_count++))
    fi
    echo ""
done

echo "=== RESULTS ==="
echo "Total benign requests: $total"
echo "False positives: $fp_count"
echo "FP rate: $(echo "scale=2; $fp_count * 100 / $total" | bc)%"
```

---

## Log Management

### Log Locations

**Docker Logs:**
```bash
# WAF logs
docker logs decepticon-waf

# All logs with timestamps
docker-compose -f docker-compose.production.yml logs -f --timestamps
```

**Application Logs:**
```bash
# Inside container
docker exec -it decepticon-waf ls /app/logs/

# View logs
docker exec -it decepticon-waf tail -f /app/logs/waf.log
```

### Log Rotation

**Configure logrotate:**

```bash
# /etc/logrotate.d/docker-decepticon

/var/lib/docker/containers/*/*.log {
    rotate 14
    daily
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    maxsize 100M

    postrotate
        docker kill --signal=USR1 decepticon-waf 2>/dev/null || true
        docker kill --signal=USR1 decepticon-prometheus 2>/dev/null || true
        docker kill --signal=USR1 decepticon-grafana 2>/dev/null || true
    endscript
}
```

### Log Analysis

**Search for attacks:**

```bash
# SQLi attacks
docker logs decepticon-waf 2>&1 | grep -i "sqli"

# High confidence detections
docker logs decepticon-waf 2>&1 | grep "confidence.*0.9"

# Blocked requests
docker logs decepticon-waf 2>&1 | grep "BLOCKED"

# False positives reported
docker logs decepticon-waf 2>&1 | grep "false_positive"
```

**Count by attack type:**

```bash
docker logs decepticon-waf 2>&1 | \
    grep "category" | \
    sed 's/.*category":\s*"\([^"]*\)".*/\1/' | \
    sort | uniq -c | sort -rn
```

---

## Incident Response

### Attack Detection Workflow

1. **Alert Received** (via Grafana/Prometheus)
   - High block rate
   - Zero-day detection
   - Attack campaign

2. **Initial Assessment**
   ```bash
   # Check Grafana Security Metrics dashboard
   # Identify attack patterns
   # Determine scope (single IP vs coordinated)
   ```

3. **Containment**
   ```bash
   # Block attacker IP (if needed)
   # Update firewall rules
   # Increase WAF sensitivity temporarily
   ```

4. **Investigation**
   ```bash
   # Export attack logs
   docker logs decepticon-waf --since 1h > incident_$(date +%Y%m%d_%H%M).log

   # Analyze attack patterns
   cat incident_*.log | grep "BLOCKED" | jq .

   # Check for successful bypasses
   cat incident_*.log | grep "false_negative"
   ```

5. **Response**
   - Update ML model if new patterns detected
   - Add custom rules for zero-day patterns
   - Report to security team
   - Update documentation

6. **Recovery**
   - Verify no data exfiltration
   - Check for persistence mechanisms
   - Reset compromised credentials (if any)

### Incident Response Scripts

**Export attack data:**

```bash
#!/bin/bash
# export_incident.sh

INCIDENT_ID="$1"
TIME_RANGE="${2:-1h}"  # Default: last hour

mkdir -p incidents/$INCIDENT_ID

# Export logs
docker logs decepticon-waf --since $TIME_RANGE \
    > incidents/$INCIDENT_ID/waf.log

# Export Prometheus metrics
curl -s "http://localhost:9090/api/v1/query_range?query=waf_requests_blocked_total&start=$(date -d "$TIME_RANGE ago" +%s)&end=$(date +%s)&step=60" \
    > incidents/$INCIDENT_ID/metrics.json

# Export blocked IPs
docker logs decepticon-waf --since $TIME_RANGE | \
    grep "BLOCKED" | \
    jq -r '.source_ip' | \
    sort | uniq -c | sort -rn \
    > incidents/$INCIDENT_ID/blocked_ips.txt

echo "Incident data exported to incidents/$INCIDENT_ID/"
```

---

## Maintenance Tasks

### Daily Tasks

```bash
#!/bin/bash
# daily_maintenance.sh

# Check service health
docker-compose -f docker-compose.production.yml ps

# Check resource usage
docker stats --no-stream

# Check disk usage
df -h

# Review yesterday's attacks
docker logs decepticon-waf --since 24h | grep "BLOCKED" | wc -l

# Check for false positives
docker logs decepticon-waf --since 24h | grep "false_positive" | wc -l
```

### Weekly Tasks

```bash
#!/bin/bash
# weekly_maintenance.sh

# Update Docker images
docker-compose -f docker-compose.production.yml pull

# Prune unused images
docker image prune -f

# Check Prometheus storage
du -sh /var/lib/docker/volumes/decepticon-waf_prometheus-data

# Review Grafana dashboards
# - Check for new attack patterns
# - Verify all panels loading
# - Review alert history

# Backup volumes
./backup.sh
```

### Monthly Tasks

```bash
#!/bin/bash
# monthly_maintenance.sh

# Retrain ML models with recent data
python3 ml/train_dual_layer.py

# Update PayloadsAllTheThings
cd data/payloads/PayloadsAllTheThings && git pull

# Review false positive patterns
python3 metrics/false_positive_monitor.py --analyze-patterns

# Security audit
# - Review blocked IPs
# - Check for persistent attackers
# - Update blocklists

# Performance review
# - Check latency trends
# - Review resource usage
# - Plan capacity upgrades
```

---

## Backup & Recovery

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups/decepticon-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Starting backup..."

# Backup Docker volumes
docker run --rm -v decepticon-waf_redis-data:/data \
    -v "$BACKUP_DIR":/backup alpine tar czf /backup/redis-data.tar.gz /data

docker run --rm -v decepticon-waf_prometheus-data:/prometheus \
    -v "$BACKUP_DIR":/backup alpine tar czf /backup/prometheus-data.tar.gz /prometheus

docker run --rm -v decepticon-waf_grafana-data:/var/lib/grafana \
    -v "$BACKUP_DIR":/backup alpine tar czf /backup/grafana-data.tar.gz /var/lib/grafana

# Backup configuration
cp .env "$BACKUP_DIR/" 2>/dev/null
cp docker-compose.production.yml "$BACKUP_DIR/"

# Backup ML models
cp -r models "$BACKUP_DIR/"

# Backup custom rules
cp -r rules "$BACKUP_DIR/" 2>/dev/null

# Create backup manifest
cat > "$BACKUP_DIR/manifest.txt" << EOF
Backup Date: $(date)
WAF Version: $(docker exec decepticon-waf python -c "import ml; print(getattr(ml, '__version__', 'unknown'))" 2>/dev/null || echo "unknown")
Docker Compose Version: $(docker-compose version --short)
Volumes Backed Up:
- Redis data
- Prometheus data
- Grafana data
Configuration Files:
- .env
- docker-compose.production.yml
- models/
- rules/
EOF

echo "Backup complete: $BACKUP_DIR"
ls -lh "$BACKUP_DIR"
```

### Restore Script

```bash
#!/bin/bash
# restore.sh

BACKUP_DIR="$1"

if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup_directory>"
    exit 1
fi

echo "Restoring from: $BACKUP_DIR"

# Stop services
docker-compose -f docker-compose.production.yml down

# Restore volumes
docker run --rm -v decepticon-waf_redis-data:/data \
    -v "$BACKUP_DIR":/backup alpine sh -c "cd /data && tar xzf /backup/redis-data.tar.gz --strip 1"

docker run --rm -v decepticon-waf_prometheus-data:/prometheus \
    -v "$BACKUP_DIR":/backup alpine sh -c "cd /prometheus && tar xzf /backup/prometheus-data.tar.gz --strip 1"

docker run --rm -v decepticon-waf_grafana-data:/var/lib/grafana \
    -v "$BACKUP_DIR":/backup alpine sh -c "cd /var/lib/grafana && tar xzf /backup/grafana-data.tar.gz --strip 1"

# Restore configuration
cp "$BACKUP_DIR/.env" . 2>/dev/null
cp "$BACKUP_DIR/docker-compose.production.yml" .

# Restore ML models
cp -r "$BACKUP_DIR/models" .

# Restore custom rules
cp -r "$BACKUP_DIR/rules" . 2>/dev/null

# Start services
docker-compose -f docker-compose.production.yml up -d

echo "Restore complete!"
```

---

## Scaling

### Horizontal Scaling

**Deploy multiple WAF instances:**

```yaml
# docker-compose.scale.yml

version: '3.8'

services:
  waf:
    # ... existing configuration ...
    deploy:
      replicas: 3  # Run 3 WAF instances

  # Add load balancer
  nginx-lb:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - waf
```

**Nginx load balancer config:**

```nginx
# nginx-lb.conf

upstream waf_backend {
    least_conn;  # Load balancing method

    server waf_1:8080 max_fails=3 fail_timeout=30s;
    server waf_2:8080 max_fails=3 fail_timeout=30s;
    server waf_3:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;

    location / {
        proxy_pass http://waf_backend;
        proxy_next_upstream error timeout http_500;
    }
}
```

### Vertical Scaling

**Increase resources:**

```yaml
# docker-compose.production.yml

services:
  waf:
    environment:
      - WORKERS=8  # Increase workers
    deploy:
      resources:
        limits:
          cpus: '4'   # Increase CPU
          memory: 8G  # Increase memory
```

---

## Automation

### Systemd Service

**Auto-start on boot:**

```bash
# /etc/systemd/system/decepticon-waf.service

[Unit]
Description=DECEPTICON WAF
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/decepticon-waf
ExecStart=/usr/local/bin/docker-compose -f docker-compose.production.yml up -d
ExecStop=/usr/local/bin/docker-compose -f docker-compose.production.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

**Enable service:**

```bash
sudo systemctl enable decepticon-waf
sudo systemctl start decepticon-waf
```

### Cron Jobs

**Scheduled maintenance:**

```bash
# /etc/cron.d/decepticon-waf

# Daily health check (6 AM)
0 6 * * * root /opt/decepticon-waf/scripts/daily_maintenance.sh >> /var/log/decepticon/maintenance.log 2>&1

# Weekly backup (Sunday 2 AM)
0 2 * * 0 root /opt/decepticon-waf/scripts/backup.sh >> /var/log/decepticon/backup.log 2>&1

# Monthly model retraining (1st of month, 3 AM)
0 3 1 * * root cd /opt/decepticon-waf && python3 ml/train_dual_layer.py >> /var/log/decepticon/training.log 2>&1
```

---

## Additional Resources

- **Deployment Guide:** `DEPLOYMENT_GUIDE.md`
- **Quick Start:** `../QUICKSTART.md`
- **ML Training Guide:** `ML_TRAINING_GUIDE.md`
- **Integration Guide:** `../integrations/INTEGRATION_GUIDE.md`
- **API Reference:** `API_REFERENCE.md`
- **Compliance Report:** `../NAVAL_SWAVLAMBAN_2025_COMPLIANCE.md`
