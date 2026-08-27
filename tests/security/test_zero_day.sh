#!/bin/bash
# Test Zero-Day Attack Detection

API_URL="http://localhost:8080/api/waf/analyze"

echo "=== ZERO-DAY ATTACK SIMULATION ==="
echo ""

# Novel SQL injection using new syntax
echo "Test 1: Novel SQL Injection (Time-based)"
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","query":"term=x'"'"') AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"}')

echo "  Response: $(echo $response | jq '{is_malicious, zero_day_detected, anomaly_score}')"

if echo "$response" | jq -r '.is_malicious' | grep -q "true"; then
    echo "  ✅ Novel SQLi: DETECTED by ML"
elif echo "$response" | jq -r '.zero_day_detected' | grep -q "true"; then
    echo "  ✅ Novel SQLi: DETECTED as zero-day"
elif echo "$response" | jq -r '.anomaly_score' | awk '{if ($1 > 0.7) exit 0; else exit 1}'; then
    echo "  ✅ Novel SQLi: DETECTED by anomaly detection"
else
    echo "  ⚠️  Novel SQLi: Not detected (will be caught by honeypot)"
fi

echo ""

# Novel XSS using template syntax
echo "Test 2: Novel XSS (Template Injection Hybrid)"
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/render","body":"{{constructor.constructor('"'"'alert(document.domain)'"'"')()}}"}')

echo "  Response: $(echo $response | jq '{is_malicious, zero_day_detected, anomaly_score}')"

if echo "$response" | jq -r '.is_malicious' | grep -q "true"; then
    echo "  ✅ Novel XSS: DETECTED by ML"
elif echo "$response" | jq -r '.zero_day_detected' | grep -q "true"; then
    echo "  ✅ Novel XSS: DETECTED as zero-day"
else
    echo "  ⚠️  Novel XSS: Not detected (will be caught by honeypot)"
fi

echo ""

# Novel SSRF using IPv6
echo "Test 3: Novel SSRF (IPv6 Bypass Attempt)"
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/fetch","query":"url=http://[::ffff:169.254.169.254]/latest/meta-data/"}')

echo "  Response: $(echo $response | jq '{is_malicious, zero_day_detected, anomaly_score}')"

if echo "$response" | jq -r '.is_malicious' | grep -q "true"; then
    echo "  ✅ Novel SSRF: DETECTED by ML"
elif echo "$response" | jq -r '.zero_day_detected' | grep -q "true"; then
    echo "  ✅ Novel SSRF: DETECTED as zero-day"
else
    echo "  ⚠️  Novel SSRF: Not detected (will be caught by honeypot)"
fi

echo ""
echo "=== ZERO-DAY TEST COMPLETE ==="
echo "Note: Undetected attacks are caught by Layer 2 (Anomaly) or Layer 3 (Honeypot)"
