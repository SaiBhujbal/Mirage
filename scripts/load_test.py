#!/usr/bin/env python3
"""
MIRAGE WAF Load Testing
Performance and stress testing for the WAF
"""
import time
import uuid
import threading
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import RequestContext, Action
from core.waf_engine import WAFEngine

@dataclass
class LoadTestResult:
    """Results from a load test"""
    total_requests: int = 0
    successful: int = 0
    blocked: int = 0
    errors: int = 0
    
    latencies: List[float] = field(default_factory=list)
    start_time: float = 0
    end_time: float = 0
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time
    
    @property
    def rps(self) -> float:
        if self.duration > 0:
            return self.total_requests / self.duration
        return 0
    
    @property
    def avg_latency(self) -> float:
        if self.latencies:
            return statistics.mean(self.latencies)
        return 0
    
    @property
    def p50_latency(self) -> float:
        if self.latencies:
            return statistics.median(self.latencies)
        return 0
    
    @property
    def p95_latency(self) -> float:
        if self.latencies:
            sorted_lat = sorted(self.latencies)
            idx = int(len(sorted_lat) * 0.95)
            return sorted_lat[idx]
        return 0
    
    @property
    def p99_latency(self) -> float:
        if self.latencies:
            sorted_lat = sorted(self.latencies)
            idx = int(len(sorted_lat) * 0.99)
            return sorted_lat[idx]
        return 0
    
    @property
    def max_latency(self) -> float:
        if self.latencies:
            return max(self.latencies)
        return 0


class LoadTester:
    """Load testing framework for MIRAGE WAF"""
    
    # Test payloads
    ATTACK_PAYLOADS = [
        "' OR 1=1--",
        "' UNION SELECT * FROM users--",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "; cat /etc/passwd",
        "../../../etc/passwd",
        "http://169.254.169.254/",
    ]
    
    BENIGN_PAYLOADS = [
        "hello world",
        "search query",
        "page=1&limit=10",
        "user@example.com",
        "product_id=12345",
    ]
    
    def __init__(self):
        self.waf = WAFEngine()
        self.results = LoadTestResult()
        self.lock = threading.Lock()
    
    def _make_request(self, payload: str, is_attack: bool = False) -> Dict:
        """Make a single request through the WAF"""
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            client_ip=f"192.168.{threading.current_thread().ident % 255}.{time.time_ns() % 255}",
            client_port=12345,
            server_ip="10.0.0.1",
            server_port=8080,
            method="GET",
            path="/api/test",
            query_string=f"input={payload}",
            headers={"user-agent": "LoadTester/1.0"},
            body=b"",
        )
        
        result = self.waf.analyze_request(ctx)
        
        return {
            "latency_ms": result.latency_ms,
            "action": result.action,
            "blocked": result.action >= Action.BLOCK,
            "is_attack": is_attack,
        }
    
    def _worker(self, payload: str, is_attack: bool) -> Dict:
        """Worker function for concurrent testing"""
        try:
            result = self._make_request(payload, is_attack)
            
            with self.lock:
                self.results.total_requests += 1
                self.results.latencies.append(result["latency_ms"])
                
                if result["blocked"]:
                    self.results.blocked += 1
                else:
                    self.results.successful += 1
            
            return result
        except Exception as e:
            with self.lock:
                self.results.errors += 1
            return {"error": str(e)}
    
    def run_load_test(self, 
                      requests: int = 10000,
                      concurrency: int = 10,
                      attack_ratio: float = 0.3,
                      duration: Optional[float] = None) -> LoadTestResult:
        """
        Run load test
        
        Args:
            requests: Total number of requests (ignored if duration set)
            concurrency: Number of concurrent workers
            attack_ratio: Ratio of attack vs benign payloads
            duration: Test duration in seconds (overrides requests)
        """
        self.results = LoadTestResult()
        self.results.start_time = time.perf_counter()
        
        print(f"\n🔥 Starting load test...")
        print(f"   Concurrency: {concurrency}")
        print(f"   Attack ratio: {attack_ratio:.0%}")
        
        if duration:
            print(f"   Duration: {duration}s")
            self._run_duration_test(duration, concurrency, attack_ratio)
        else:
            print(f"   Requests: {requests}")
            self._run_request_test(requests, concurrency, attack_ratio)
        
        self.results.end_time = time.perf_counter()
        
        return self.results
    
    def _run_request_test(self, requests: int, concurrency: int, attack_ratio: float):
        """Run test for fixed number of requests"""
        import random
        
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            
            for i in range(requests):
                # Select payload
                if random.random() < attack_ratio:
                    payload = random.choice(self.ATTACK_PAYLOADS)
                    is_attack = True
                else:
                    payload = random.choice(self.BENIGN_PAYLOADS)
                    is_attack = False
                
                future = executor.submit(self._worker, payload, is_attack)
                futures.append(future)
                
                # Progress update every 1000 requests
                if (i + 1) % 1000 == 0:
                    print(f"   Submitted {i + 1}/{requests} requests...")
            
            # Wait for completion
            for future in as_completed(futures):
                pass
    
    def _run_duration_test(self, duration: float, concurrency: int, attack_ratio: float):
        """Run test for fixed duration"""
        import random
        
        end_time = time.time() + duration
        
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            
            while time.time() < end_time:
                # Select payload
                if random.random() < attack_ratio:
                    payload = random.choice(self.ATTACK_PAYLOADS)
                    is_attack = True
                else:
                    payload = random.choice(self.BENIGN_PAYLOADS)
                    is_attack = False
                
                future = executor.submit(self._worker, payload, is_attack)
                futures.append(future)
                
                # Limit queue depth
                if len(futures) > concurrency * 10:
                    done = [f for f in futures if f.done()]
                    futures = [f for f in futures if not f.done()]
            
            # Wait for remaining
            for future in as_completed(futures):
                pass
    
    def print_results(self):
        """Print formatted results"""
        r = self.results
        
        print("\n" + "="*70)
        print("LOAD TEST RESULTS")
        print("="*70)
        
        print(f"\n📊 Request Statistics:")
        print(f"   Total Requests:  {r.total_requests:,}")
        print(f"   Successful:      {r.successful:,}")
        print(f"   Blocked:         {r.blocked:,}")
        print(f"   Errors:          {r.errors:,}")
        
        print(f"\n⚡ Performance:")
        print(f"   Duration:        {r.duration:.2f}s")
        print(f"   Throughput:      {r.rps:,.0f} req/s")
        
        print(f"\n⏱️  Latency:")
        print(f"   Average:         {r.avg_latency:.3f}ms")
        print(f"   P50 (median):    {r.p50_latency:.3f}ms")
        print(f"   P95:             {r.p95_latency:.3f}ms")
        print(f"   P99:             {r.p99_latency:.3f}ms")
        print(f"   Max:             {r.max_latency:.3f}ms")
        
        # Check against requirements
        print(f"\n✅ Latency Budget Check:")
        
        if r.avg_latency < 5.0:
            print(f"   Average < 5ms:   ✅ PASS ({r.avg_latency:.3f}ms)")
        else:
            print(f"   Average < 5ms:   ❌ FAIL ({r.avg_latency:.3f}ms)")
        
        if r.p99_latency < 50.0:
            print(f"   P99 < 50ms:      ✅ PASS ({r.p99_latency:.3f}ms)")
        else:
            print(f"   P99 < 50ms:      ❌ FAIL ({r.p99_latency:.3f}ms)")
        
        if r.max_latency < 200.0:
            print(f"   Max < 200ms:     ✅ PASS ({r.max_latency:.3f}ms)")
        else:
            print(f"   Max < 200ms:     ❌ FAIL ({r.max_latency:.3f}ms)")
        
        print("\n" + "="*70)


def run_stress_test():
    """Run escalating stress test"""
    print("\n🔥 MIRAGE WAF Stress Test")
    print("="*70)
    
    tester = LoadTester()
    
    concurrency_levels = [1, 5, 10, 25, 50, 100]
    
    print("\nConcurrency | Requests | Duration | RPS      | Avg Lat | P99 Lat")
    print("-" * 70)
    
    for concurrency in concurrency_levels:
        results = tester.run_load_test(
            requests=5000,
            concurrency=concurrency,
            attack_ratio=0.3
        )
        
        print(f"{concurrency:11} | {results.total_requests:8} | {results.duration:7.2f}s | "
              f"{results.rps:8.0f} | {results.avg_latency:7.3f}ms | {results.p99_latency:7.3f}ms")
    
    print("\n✅ Stress test complete!")


def run_sustained_test(duration: int = 60):
    """Run sustained load test"""
    print(f"\n🔥 MIRAGE WAF Sustained Load Test ({duration}s)")
    print("="*70)
    
    tester = LoadTester()
    
    results = tester.run_load_test(
        duration=duration,
        concurrency=20,
        attack_ratio=0.3
    )
    
    tester.print_results()


def main():
    parser = argparse.ArgumentParser(description="MIRAGE WAF Load Tester")
    
    subparsers = parser.add_subparsers(dest="command", help="Test type")
    
    # Quick test
    quick_parser = subparsers.add_parser("quick", help="Quick load test (1000 requests)")
    
    # Standard test
    std_parser = subparsers.add_parser("standard", help="Standard load test")
    std_parser.add_argument("-n", "--requests", type=int, default=10000, help="Number of requests")
    std_parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrency level")
    std_parser.add_argument("-a", "--attack-ratio", type=float, default=0.3, help="Attack payload ratio")
    
    # Stress test
    stress_parser = subparsers.add_parser("stress", help="Escalating stress test")
    
    # Sustained test
    sustained_parser = subparsers.add_parser("sustained", help="Sustained load test")
    sustained_parser.add_argument("-d", "--duration", type=int, default=60, help="Duration in seconds")
    
    args = parser.parse_args()
    
    if args.command == "quick":
        tester = LoadTester()
        results = tester.run_load_test(requests=1000, concurrency=5)
        tester.print_results()
    
    elif args.command == "standard":
        tester = LoadTester()
        results = tester.run_load_test(
            requests=args.requests,
            concurrency=args.concurrency,
            attack_ratio=args.attack_ratio
        )
        tester.print_results()
    
    elif args.command == "stress":
        run_stress_test()
    
    elif args.command == "sustained":
        run_sustained_test(args.duration)
    
    else:
        # Default quick test
        tester = LoadTester()
        results = tester.run_load_test(requests=5000, concurrency=10)
        tester.print_results()


if __name__ == "__main__":
    main()
