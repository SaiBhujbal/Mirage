#!/usr/bin/env python3
"""
Benchmark ML Model Performance
Tests inference speed and throughput of the trained model
"""

import time
from ml.dual_layer_inference import DualLayerPredictor

print('=== ML MODEL PERFORMANCE BENCHMARK ===')
print()

# Initialize predictor
predictor = DualLayerPredictor(models_dir='./models')
print(f'Models directory: {predictor.models_dir}')
print(f'HTTP model loaded: {predictor.http_classifier is not None}')
print()

# Benchmark parameters
test_payloads = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "; cat /etc/passwd",
    "../../../etc/passwd",
    "http://169.254.169.254/",
]
iterations = 200  # 200 iterations * 5 payloads = 1000 predictions

print(f'Running benchmark: {iterations * len(test_payloads)} predictions...')
print()

# Warm-up (first prediction loads everything)
_ = predictor.predict(payload="warmup")

# Benchmark
start = time.time()
for _ in range(iterations):
    for payload in test_payloads:
        result = predictor.predict(payload=payload)
elapsed = time.time() - start

total_predictions = iterations * len(test_payloads)

print('=== RESULTS ===')
print(f'Total predictions: {total_predictions}')
print(f'Total time: {elapsed:.2f}s')
print(f'Average latency: {(elapsed/total_predictions)*1000:.2f}ms per prediction')
print(f'Throughput: {total_predictions/elapsed:.0f} predictions/second')
print()

# Performance assessment
avg_latency_ms = (elapsed/total_predictions)*1000
if avg_latency_ms < 3:
    performance = "EXCELLENT ⚡"
elif avg_latency_ms < 5:
    performance = "GOOD ✅"
elif avg_latency_ms < 10:
    performance = "ACCEPTABLE ⚠️"
else:
    performance = "NEEDS OPTIMIZATION ❌"

print(f'Performance: {performance}')
print(f'Target: <5ms per prediction')
print()

# Test with a single payload to show detailed timing
print('=== DETAILED SINGLE PREDICTION ===')
test_payload = "' OR 1=1--"
result = predictor.predict(payload=test_payload)
print(f'Payload: {test_payload}')
print(f'Malicious: {result.is_malicious}')
print(f'Confidence: {result.confidence:.4f}')
print(f'Category: {result.unified_category}')
"""

Benchmark ML Model Performance

Tests inference speed and throughput of the trained model

"""

 

import time

from ml.dual_layer_inference import DualLayerPredictor

 

print('=== ML MODEL PERFORMANCE BENCHMARK ===')

print()

 

# Initialize predictor

predictor = DualLayerPredictor(models_dir='./models')

print(f'Models directory: {predictor.models_dir}')

print(f'HTTP model loaded: {predictor.http_classifier is not None}')

print()

 

# Benchmark parameters

test_payloads = [

    "' OR 1=1--",

    "<script>alert(1)</script>",

    "; cat /etc/passwd",

    "../../../etc/passwd",

    "http://169.254.169.254/",

]

iterations = 200  # 200 iterations * 5 payloads = 1000 predictions

 

print(f'Running benchmark: {iterations * len(test_payloads)} predictions...')

print()

 

# Warm-up (first prediction loads everything)

_ = predictor.predict(payload="warmup")

 

# Benchmark

start = time.time()

for _ in range(iterations):

    for payload in test_payloads:

        result = predictor.predict(payload=payload)

elapsed = time.time() - start

 

total_predictions = iterations * len(test_payloads)

 

print('=== RESULTS ===')

print(f'Total predictions: {total_predictions}')

print(f'Total time: {elapsed:.2f}s')

print(f'Average latency: {(elapsed/total_predictions)*1000:.2f}ms per prediction')

print(f'Throughput: {total_predictions/elapsed:.0f} predictions/second')

print()

 

# Performance assessment

avg_latency_ms = (elapsed/total_predictions)*1000

if avg_latency_ms < 3:

    performance = "EXCELLENT ⚡"

elif avg_latency_ms < 5:

    performance = "GOOD ✅"

elif avg_latency_ms < 10:

    performance = "ACCEPTABLE ⚠️"

else:

    performance = "NEEDS OPTIMIZATION ❌"

 

print(f'Performance: {performance}')

print(f'Target: <5ms per prediction')

print()

 

# Test with a single payload to show detailed timing

print('=== DETAILED SINGLE PREDICTION ===')

test_payload = "' OR 1=1--"

result = predictor.predict(payload=test_payload)

print(f'Payload: {test_payload}')

print(f'Malicious: {result.is_malicious}')

print(f'Confidence: {result.confidence:.4f}')

print(f'Category: {result.unified_category}')

print(f'Latency: {result.latency_ms:.2f}ms')
