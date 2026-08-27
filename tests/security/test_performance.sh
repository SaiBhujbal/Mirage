#!/bin/bash
# Test Performance (Latency & Throughput)

API_URL="http://localhost:8080/api/waf/analyze"

echo "=== PERFORMANCE TEST ==="
echo ""

total_time=0
iterations=100

echo "Running $iterations requests to measure latency..."

for i in $(seq 1 $iterations); do
    response_time=$(curl -s -o /dev/null -w "%{time_total}" -X POST "$API_URL" \
      -H "Content-Type: application/json" \
      -d '{"method":"GET","path":"/test","query":"page=1"}')

    total_time=$(echo "$total_time + $response_time" | bc)
done

# Calculate metrics
avg_latency=$(echo "scale=3; ($total_time / $iterations) * 1000" | bc)
throughput=$(echo "scale=2; $iterations / $total_time" | bc)

echo ""
echo "=== RESULTS ==="
echo "Total requests:    $iterations"
echo "Total time:        ${total_time}s"
echo "Average latency:   ${avg_latency}ms"
echo "Throughput:        ${throughput} req/s"
echo ""
echo "Targets:"
echo "  Latency:         < 5ms (P95)"
echo "  Throughput:      > 200 req/s"
echo ""

# Check if targets met
latency_pass=$(echo "$avg_latency < 5" | bc -l)
throughput_pass=$(echo "$throughput > 200" | bc -l)

if [ "$latency_pass" -eq 1 ]; then
    echo "✅ Latency: PASS (${avg_latency}ms < 5ms)"
else
    echo "⚠️  Latency: ${avg_latency}ms (target: < 5ms)"
fi

if [ "$throughput_pass" -eq 1 ]; then
    echo "✅ Throughput: PASS (${throughput} > 200 req/s)"
else
    echo "⚠️  Throughput: ${throughput} req/s (target: > 200)"
fi

echo ""

if [ "$latency_pass" -eq 1 ] && [ "$throughput_pass" -eq 1 ]; then
    echo "✅ PERFORMANCE TARGETS MET"
    exit 0
else
    echo "⚠️  PERFORMANCE TARGETS NOT FULLY MET"
    exit 1
fi
