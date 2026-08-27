#!/usr/bin/env python3
"""
MIRAGE WAF Test Client
Send test requests to the WAF and view results
"""
import httpx
import json
import argparse
import sys
from typing import Optional

BASE_URL = "http://localhost:8080"

class WAFTestClient:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.client = httpx.Client(timeout=30.0)
    
    def analyze(self, method: str = "GET", path: str = "/", 
                query: str = "", body: str = "", 
                headers: Optional[dict] = None) -> dict:
        """Send request to WAF analyze endpoint"""
        payload = {
            "method": method,
            "path": path,
            "query_string": query,
            "body": body,
            "headers": headers or {},
            "client_ip": "192.168.1.100",
        }
        
        response = self.client.post(
            f"{self.base_url}/api/waf/analyze",
            json=payload
        )
        return response.json()
    
    def test_payloads(self, payloads: list) -> dict:
        """Test multiple payloads"""
        response = self.client.post(
            f"{self.base_url}/api/waf/test",
            json={"payloads": payloads}
        )
        return response.json()
    
    def get_metrics(self) -> dict:
        """Get WAF metrics"""
        response = self.client.get(f"{self.base_url}/metrics")
        return response.json()
    
    def get_health(self) -> dict:
        """Get WAF health"""
        response = self.client.get(f"{self.base_url}/health")
        return response.json()
    
    def get_rules(self) -> dict:
        """Get auto-generated rules"""
        response = self.client.get(f"{self.base_url}/api/waf/rules")
        return response.json()
    
    def get_sessions(self) -> dict:
        """Get active sessions"""
        response = self.client.get(f"{self.base_url}/api/waf/sessions")
        return response.json()
    
    def get_honeypots(self) -> dict:
        """Get honeypot sessions"""
        response = self.client.get(f"{self.base_url}/api/deception/honeypots")
        return response.json()
    
    def get_canaries(self) -> dict:
        """Get triggered canary tokens"""
        response = self.client.get(f"{self.base_url}/api/deception/canaries")
        return response.json()
    
    def send_attack(self, attack_type: str) -> dict:
        """Send a specific attack type"""
        attacks = {
            "sqli": ("GET", "/api/users", "id=' OR 1=1--", ""),
            "sqli_union": ("GET", "/api/data", "id=' UNION SELECT * FROM users--", ""),
            "xss": ("GET", "/search", "q=<script>alert(1)</script>", ""),
            "xss_event": ("GET", "/page", "name=<img src=x onerror=alert(1)>", ""),
            "rce": ("GET", "/api/ping", "host=; cat /etc/passwd", ""),
            "lfi": ("GET", "/api/download", "file=../../../etc/passwd", ""),
            "ssrf": ("POST", "/api/fetch", "", '{"url": "http://169.254.169.254/"}'),
        }
        
        if attack_type not in attacks:
            print(f"Unknown attack type: {attack_type}")
            print(f"Available: {', '.join(attacks.keys())}")
            return {}
        
        method, path, query, body = attacks[attack_type]
        return self.analyze(method, path, query, body)

def print_result(result: dict, verbose: bool = False):
    """Pretty print analysis result"""
    action = result.get('action', 'UNKNOWN')
    risk = result.get('risk_level', 'UNKNOWN')
    latency = result.get('latency_ms', 0)
    
    # Color codes
    colors = {
        'ALLOW': '\033[92m',      # Green
        'MONITOR': '\033[93m',    # Yellow
        'CHALLENGE': '\033[93m',  # Yellow
        'THROTTLE': '\033[91m',   # Red
        'HONEYPOT': '\033[95m',   # Magenta
        'BLOCK': '\033[91m',      # Red
    }
    reset = '\033[0m'
    
    color = colors.get(action, '')
    print(f"\n{color}Action: {action}{reset}")
    print(f"Risk Level: {risk}")
    print(f"Latency: {latency:.3f}ms")
    
    if result.get('detections'):
        print("\nDetections:")
        for det in result['detections']:
            print(f"  - {det['category']} ({det['confidence']:.0%})")
            if det.get('matched_pattern'):
                print(f"    Pattern: {det['matched_pattern']}")
    
    if result.get('is_zero_day'):
        print(f"\n⚠️  ZERO-DAY DETECTED: {result.get('zero_day_signature')}")
    
    if verbose:
        print("\nFull Result:")
        print(json.dumps(result, indent=2))

def main():
    parser = argparse.ArgumentParser(description="MIRAGE WAF Test Client")
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a request')
    analyze_parser.add_argument('-m', '--method', default='GET', help='HTTP method')
    analyze_parser.add_argument('-p', '--path', default='/', help='Request path')
    analyze_parser.add_argument('-q', '--query', default='', help='Query string')
    analyze_parser.add_argument('-b', '--body', default='', help='Request body')
    analyze_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Attack command
    attack_parser = subparsers.add_parser('attack', help='Send a predefined attack')
    attack_parser.add_argument('type', help='Attack type (sqli, xss, rce, lfi, ssrf)')
    attack_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test multiple payloads')
    test_parser.add_argument('payloads', nargs='+', help='Payloads to test')
    
    # Status commands
    subparsers.add_parser('health', help='Get WAF health')
    subparsers.add_parser('metrics', help='Get WAF metrics')
    subparsers.add_parser('rules', help='Get auto-generated rules')
    subparsers.add_parser('sessions', help='Get active sessions')
    subparsers.add_parser('honeypots', help='Get honeypot sessions')
    subparsers.add_parser('canaries', help='Get triggered canaries')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    client = WAFTestClient()
    
    try:
        if args.command == 'analyze':
            result = client.analyze(args.method, args.path, args.query, args.body)
            print_result(result, args.verbose)
        
        elif args.command == 'attack':
            result = client.send_attack(args.type)
            print_result(result, args.verbose)
        
        elif args.command == 'test':
            result = client.test_payloads(args.payloads)
            print(f"\nTotal: {result['total']}")
            print(f"Blocked: {result['blocked']}")
            print(f"Detection Rate: {result['detection_rate']:.1f}%")
            print("\nResults:")
            for r in result['results']:
                status = '🛡️' if r['blocked'] else '✅'
                print(f"  {status} {r['payload'][:50]:50} -> {r['action']}")
        
        elif args.command == 'health':
            result = client.get_health()
            status = result.get('status', 'unknown')
            emoji = '✅' if status == 'healthy' else '⚠️' if status == 'degraded' else '❌'
            print(f"\n{emoji} WAF Status: {status}")
            if result.get('issues'):
                print("Issues:")
                for issue in result['issues']:
                    print(f"  - {issue}")
            print(f"\nMetrics:")
            metrics = result.get('metrics', {})
            print(f"  Total Requests: {metrics.get('total_requests', 0)}")
            print(f"  Blocked: {metrics.get('blocked_requests', 0)}")
            print(f"  Avg Latency: {metrics.get('avg_latency_ms', 0):.2f}ms")
        
        elif args.command == 'metrics':
            result = client.get_metrics()
            print(json.dumps(result, indent=2))
        
        elif args.command == 'rules':
            result = client.get_rules()
            print(f"\nAuto-Generated Rules: {len(result.get('auto_generated', []))}")
            print(f"Zero-Day Signatures: {len(result.get('zero_day_signatures', []))}")
            if result.get('auto_generated'):
                print("\nRules:")
                for rule in result['auto_generated']:
                    status = '✅' if rule.get('is_active') else '❌'
                    print(f"  {status} {rule['rule_id']}: {rule['category']}")
        
        elif args.command == 'sessions':
            result = client.get_sessions()
            print(f"\nTotal Sessions: {result.get('total_sessions', 0)}")
            for session in result.get('sessions', [])[:10]:
                status = '⚠️' if session.get('is_suspicious') else '👤'
                print(f"  {status} {session['client_ip']:15} | Reqs: {session['request_count']:4} | Blocked: {session['blocked_count']}")
        
        elif args.command == 'honeypots':
            result = client.get_honeypots()
            print(f"\nHoneypot Sessions: {result.get('total_sessions', 0)}")
            for session in result.get('sessions', []):
                print(f"  🍯 {session['client_ip']} | Type: {session['honeypot_type']} | Payloads: {len(session.get('payloads', []))}")
        
        elif args.command == 'canaries':
            result = client.get_canaries()
            print(f"\nTriggered Canaries: {result.get('total_triggered', 0)}")
            for canary in result.get('canaries', []):
                print(f"  🚨 {canary['type']} | From: {canary['triggered_from']} | Token: {canary['token_id']}")
    
    except httpx.ConnectError:
        print("❌ Cannot connect to WAF server. Is it running?")
        print(f"   Expected at: {BASE_URL}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
