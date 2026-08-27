#!/bin/bash
# Test Layer 1: ML Detection

API_URL="http://localhost:8080/api/waf/analyze"

echo "=== LAYER 1: ML DETECTION TEST ==="
echo ""

passed=0
total=0

# Test SQLi
echo "Test 1: SQL Injection Detection"
((total++))
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/users","query":"id=1 OR 1=1--"}')

if echo "$response" | jq -r '.is_malicious' | grep -q "true"; then
    echo "  ✅ SQLi Detection: PASS"
    ((passed++))
else
    echo "  ❌ SQLi Detection: FAIL"
fi

# Test XSS
echo "Test 2: XSS Detection"
((total++))
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/comment","body":"<script>alert(1)</script>"}')

if echo "$response" | jq -r '.is_malicious' | grep -q "true"; then
    echo "  ✅ XSS Detection: PASS"
    ((passed++))
else
    echo "  ❌ XSS Detection: FAIL"
fi

# Test RCE
echo "Test 3: RCE Detection"
((total++))
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/exec","query":"cmd=; cat /etc/passwd"}')

if echo "$response" | jq -r '.is_malicious' | grep -q "true"; then
    echo "  ✅ RCE Detection: PASS"
    ((passed++))
else
    echo "  ❌ RCE Detection: FAIL"
fi

# Test Path Traversal
echo "Test 4: Path Traversal Detection"
((total++))
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/file","query":"path=../../../../etc/passwd"}')

if echo "$response" | jq -r '.is_malicious' | grep -q "true"; then
    echo "  ✅ Path Traversal Detection: PASS"
    ((passed++))
else
    echo "  ❌ Path Traversal Detection: FAIL"
fi

# Test SSRF
echo "Test 5: SSRF Detection"
((total++))
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/proxy","query":"url=http://169.254.169.254/"}')

if echo "$response" | jq -r '.is_malicious' | grep -q "true"; then
    echo "  ✅ SSRF Detection: PASS"
    ((passed++))
else
    echo "  ❌ SSRF Detection: FAIL"
fi

# Test benign traffic
echo "Test 6: Benign Traffic (Should Allow)"
((total++))
response=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/products","query":"page=1&sort=name"}')

if echo "$response" | jq -r '.is_malicious' | grep -q "false"; then
    echo "  ✅ Benign Traffic: PASS"
    ((passed++))
else
    echo "  ❌ Benign Traffic: FAIL (false positive)"
fi

echo ""
echo "=== LAYER 1 RESULTS ==="
echo "Total tests: $total"
echo "Passed: $passed"
echo "Detection rate: $(echo "scale=2; $passed * 100 / $total" | bc)%"
echo "Expected: 100%"

if [ $passed -eq $total ]; then
    echo "✅ ALL TESTS PASSED"
    exit 0
else
    echo "❌ SOME TESTS FAILED"
    exit 1
fi
