"""
DECEPTICON Enhanced Honeypot
Anti-fingerprinting measures with randomized responses

Addresses: "Honeypot Detection" vulnerability
- Randomized fake data
- Timing variations
- Response header randomization
- Realistic error injection
"""
import time
import random
import hashlib
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import threading

# ============================================================================
# RANDOMIZED DATA GENERATORS
# ============================================================================

class FakeDataGenerator:
    """
    Generate realistic fake data that varies on each request
    Prevents fingerprinting through pattern analysis
    """
    
    # Name pools
    FIRST_NAMES = [
        "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph",
        "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica",
        "Amit", "Priya", "Raj", "Sunita", "Vikram", "Anita", "Rahul", "Deepa",
        "Wei", "Fang", "Ming", "Xiu", "Chen", "Li", "Zhang", "Wang",
    ]
    
    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
        "Rodriguez", "Martinez", "Hernandez", "Lopez", "Wilson", "Anderson", "Thomas",
        "Sharma", "Patel", "Kumar", "Singh", "Gupta", "Mehta", "Joshi", "Verma",
        "Wang", "Li", "Zhang", "Liu", "Chen", "Yang", "Huang", "Zhao",
    ]
    
    DOMAINS = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "company.com",
        "work.org", "mail.com", "email.com", "inbox.com", "proton.me",
    ]
    
    DEPARTMENTS = [
        "Engineering", "Sales", "Marketing", "Finance", "HR", "IT", "Operations",
        "Support", "Legal", "Research", "Product", "Design", "Security",
    ]
    
    ROLES = [
        "Engineer", "Manager", "Director", "Analyst", "Specialist", "Lead",
        "Coordinator", "Administrator", "Developer", "Architect", "Consultant",
    ]
    
    def __init__(self, seed: int = None):
        """
        Initialize with optional seed
        Different seed = different but consistent fake data
        """
        self.rng = random.Random(seed)
    
    def reseed(self, context: str = None):
        """Reseed based on context for varied responses"""
        if context:
            seed = int(hashlib.sha256(context.encode()).hexdigest()[:16], 16)
            seed ^= int(time.time()) % 10000  # Add time-based variation
        else:
            seed = int(time.time() * 1000) % (2**31)
        self.rng = random.Random(seed)
    
    def fake_name(self) -> str:
        return f"{self.rng.choice(self.FIRST_NAMES)} {self.rng.choice(self.LAST_NAMES)}"
    
    def fake_username(self) -> str:
        first = self.rng.choice(self.FIRST_NAMES).lower()
        last = self.rng.choice(self.LAST_NAMES).lower()
        num = self.rng.randint(1, 999)
        
        patterns = [
            f"{first}.{last}",
            f"{first}{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{first}.{last}{num}",
            f"{first}_{last}",
        ]
        return self.rng.choice(patterns)
    
    def fake_email(self) -> str:
        username = self.fake_username()
        domain = self.rng.choice(self.DOMAINS)
        return f"{username}@{domain}"
    
    def fake_password_hash(self) -> str:
        """Generate fake bcrypt-like hash"""
        salt = ''.join(self.rng.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./', k=22))
        hash_part = ''.join(self.rng.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./', k=31))
        return f"$2b$10${salt}{hash_part}"
    
    def fake_phone(self) -> str:
        patterns = [
            f"+1-{self.rng.randint(200,999)}-{self.rng.randint(200,999)}-{self.rng.randint(1000,9999)}",
            f"({self.rng.randint(200,999)}) {self.rng.randint(200,999)}-{self.rng.randint(1000,9999)}",
            f"+91-{self.rng.randint(70000,99999)}{self.rng.randint(10000,99999)}",
        ]
        return self.rng.choice(patterns)
    
    def fake_ip(self) -> str:
        # Private IPs only (realistic for internal data)
        ranges = [
            (10, 0, 0, 0, 10, 255, 255, 255),
            (172, 16, 0, 0, 172, 31, 255, 255),
            (192, 168, 0, 0, 192, 168, 255, 255),
        ]
        r = self.rng.choice(ranges)
        return f"{self.rng.randint(r[0], r[4])}.{self.rng.randint(r[1], r[5])}.{self.rng.randint(r[2], r[6])}.{self.rng.randint(r[3], r[7])}"
    
    def fake_uuid(self) -> str:
        hex_chars = '0123456789abcdef'
        return '-'.join([
            ''.join(self.rng.choices(hex_chars, k=8)),
            ''.join(self.rng.choices(hex_chars, k=4)),
            '4' + ''.join(self.rng.choices(hex_chars, k=3)),
            self.rng.choice('89ab') + ''.join(self.rng.choices(hex_chars, k=3)),
            ''.join(self.rng.choices(hex_chars, k=12)),
        ])
    
    def fake_credit_card(self) -> str:
        """Fake CC that passes Luhn but isn't real"""
        # Use test prefixes that are known to be fake
        prefixes = ['4111111111111', '5500000000000', '340000000000']
        prefix = self.rng.choice(prefixes)
        remaining = 16 - len(prefix) - 1
        number = prefix + ''.join(str(self.rng.randint(0, 9)) for _ in range(remaining))
        
        # Calculate Luhn check digit
        digits = [int(d) for d in number]
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        check = (10 - sum(digits) % 10) % 10
        
        return number + str(check)
    
    def fake_user_record(self) -> Dict:
        """Generate complete fake user record"""
        user_id = self.rng.randint(1000, 99999)
        created = time.time() - self.rng.randint(86400, 86400 * 365 * 3)
        
        return {
            "id": user_id,
            "username": self.fake_username(),
            "email": self.fake_email(),
            "password_hash": self.fake_password_hash(),
            "full_name": self.fake_name(),
            "phone": self.fake_phone() if self.rng.random() > 0.3 else None,
            "department": self.rng.choice(self.DEPARTMENTS),
            "role": self.rng.choice(self.ROLES),
            "is_active": self.rng.random() > 0.1,
            "last_login": time.time() - self.rng.randint(0, 86400 * 30),
            "created_at": created,
            "updated_at": created + self.rng.randint(0, 86400 * 100),
        }
    
    def fake_database_rows(self, count: int = None) -> List[Dict]:
        """Generate fake database result set"""
        if count is None:
            count = self.rng.randint(3, 15)
        return [self.fake_user_record() for _ in range(count)]


# ============================================================================
# TIMING VARIATION
# ============================================================================

class TimingRandomizer:
    """
    Add realistic timing variations to prevent timing-based fingerprinting
    """
    
    def __init__(self):
        self.base_latency_ms = 50  # Base response time
        self.variation_ms = 100   # Random variation
        self.slow_probability = 0.05  # 5% chance of slow response
        self.slow_factor = 5  # Slow responses are 5x slower
    
    def get_delay(self, request_type: str = "normal") -> float:
        """
        Get delay in seconds based on request type
        
        Types:
        - normal: Standard variation
        - database: Slightly slower (simulating DB query)
        - file: Variable (simulating file read)
        - error: Quick (errors are fast)
        """
        base = self.base_latency_ms
        
        if request_type == "database":
            base = 100
            variation = 200
        elif request_type == "file":
            base = 30
            variation = 150
        elif request_type == "error":
            base = 10
            variation = 20
        else:
            variation = self.variation_ms
        
        delay = base + random.uniform(0, variation)
        
        # Occasionally add significant delay (simulating slow query)
        if random.random() < self.slow_probability:
            delay *= self.slow_factor
        
        return delay / 1000.0  # Convert to seconds
    
    def apply_delay(self, request_type: str = "normal"):
        """Sleep for appropriate delay"""
        delay = self.get_delay(request_type)
        time.sleep(delay)


# ============================================================================
# RESPONSE HEADER RANDOMIZATION
# ============================================================================

class HeaderRandomizer:
    """
    Randomize response headers to prevent fingerprinting
    """
    
    SERVER_HEADERS = [
        "Apache/2.4.41 (Ubuntu)",
        "nginx/1.18.0",
        "Microsoft-IIS/10.0",
        "Apache/2.4.46",
        "nginx/1.19.0",
        "gunicorn/20.1.0",
    ]
    
    POWERED_BY = [
        "PHP/7.4.3",
        "ASP.NET",
        "Express",
        "Django",
        "Flask",
        None,  # Sometimes omit
    ]
    
    def __init__(self, consistent_per_session: bool = True):
        self.consistent = consistent_per_session
        self.session_headers: Dict[str, Dict] = {}
        self.lock = threading.Lock()
    
    def get_headers(self, session_id: str = None) -> Dict[str, str]:
        """Get randomized headers for response"""
        
        if self.consistent and session_id:
            with self.lock:
                if session_id not in self.session_headers:
                    self.session_headers[session_id] = self._generate_headers()
                return self.session_headers[session_id].copy()
        
        return self._generate_headers()
    
    def _generate_headers(self) -> Dict[str, str]:
        """Generate random but realistic headers"""
        headers = {
            "Server": random.choice(self.SERVER_HEADERS),
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
        }
        
        powered_by = random.choice(self.POWERED_BY)
        if powered_by:
            headers["X-Powered-By"] = powered_by
        
        # Random cache headers
        if random.random() > 0.5:
            headers["Cache-Control"] = random.choice([
                "no-cache",
                "no-store",
                "private, max-age=0",
                "public, max-age=300",
            ])
        
        # Sometimes add custom headers (realistic)
        if random.random() > 0.7:
            headers["X-Request-ID"] = hashlib.sha256(str(time.time()).encode()).hexdigest()[:32]
        
        return headers


# ============================================================================
# ERROR INJECTION
# ============================================================================

class RealisticErrorInjector:
    """
    Inject realistic errors to make honeypot more believable
    Real systems have occasional errors!
    """
    
    def __init__(self, error_rate: float = 0.02):
        self.error_rate = error_rate
        
        self.errors = [
            (500, "Internal Server Error", {"error": "An unexpected error occurred"}),
            (502, "Bad Gateway", {"error": "The server received an invalid response"}),
            (503, "Service Unavailable", {"error": "Service temporarily unavailable"}),
            (504, "Gateway Timeout", {"error": "The server timed out waiting for response"}),
            (429, "Too Many Requests", {"error": "Rate limit exceeded", "retry_after": 60}),
        ]
    
    def should_inject_error(self) -> bool:
        """Randomly decide if we should inject an error"""
        return random.random() < self.error_rate
    
    def get_error(self) -> Tuple[int, str, Dict]:
        """Get a random error response"""
        return random.choice(self.errors)


# ============================================================================
# ENHANCED HONEYPOT RESPONSE GENERATOR
# ============================================================================

class EnhancedHoneypotResponder:
    """
    Generate honeypot responses with anti-fingerprinting measures
    """
    
    def __init__(self):
        self.fake_data = FakeDataGenerator()
        self.timing = TimingRandomizer()
        self.headers = HeaderRandomizer()
        self.errors = RealisticErrorInjector()
    
    def generate_response(self, 
                          attack_type: str,
                          payload: str,
                          session_id: str,
                          request_context: Dict = None) -> Dict:
        """
        Generate honeypot response based on attack type
        
        Returns:
        {
            "status_code": int,
            "headers": Dict,
            "body": Dict or str,
            "delay_seconds": float,
        }
        """
        # Reseed for this request (varied but deterministic within session)
        context = f"{session_id}:{attack_type}:{int(time.time() / 60)}"
        self.fake_data.reseed(context)
        
        # Check if we should inject an error
        if self.errors.should_inject_error():
            status, message, body = self.errors.get_error()
            return {
                "status_code": status,
                "headers": self.headers.get_headers(session_id),
                "body": body,
                "delay_seconds": self.timing.get_delay("error"),
            }
        
        # Generate response based on attack type
        if attack_type in ("SQLI", "SQL_INJECTION"):
            response = self._sqli_response(payload)
        elif attack_type in ("XSS", "CROSS_SITE_SCRIPTING"):
            response = self._xss_response(payload)
        elif attack_type in ("LFI", "PATH_TRAVERSAL"):
            response = self._lfi_response(payload)
        elif attack_type in ("RCE", "COMMAND_INJECTION"):
            response = self._rce_response(payload)
        elif attack_type == "SSRF":
            response = self._ssrf_response(payload)
        else:
            response = self._generic_response()
        
        response["headers"] = self.headers.get_headers(session_id)
        response["delay_seconds"] = self.timing.get_delay(
            "database" if attack_type in ("SQLI",) else "normal"
        )
        
        return response
    
    def _sqli_response(self, payload: str) -> Dict:
        """Generate fake SQL injection response"""
        # Detect what attacker is trying to extract
        payload_lower = payload.lower()
        
        if "union" in payload_lower and "select" in payload_lower:
            # UNION-based injection - return fake data
            rows = self.fake_data.fake_database_rows(random.randint(5, 20))
            return {
                "status_code": 200,
                "body": {"users": rows, "total": len(rows)},
            }
        
        elif "or" in payload_lower and ("1=1" in payload_lower or "true" in payload_lower):
            # Boolean-based - return all records
            rows = self.fake_data.fake_database_rows(random.randint(10, 50))
            return {
                "status_code": 200,
                "body": {"data": rows, "success": True},
            }
        
        elif "sleep" in payload_lower or "waitfor" in payload_lower or "benchmark" in payload_lower:
            # Time-based - actually delay (but not too much)
            return {
                "status_code": 200,
                "body": {"result": "ok"},
                "extra_delay": random.uniform(1.0, 3.0),  # Simulate sleep
            }
        
        else:
            # Generic SQL error that reveals "vulnerability"
            return {
                "status_code": 200,
                "body": {
                    "error": f"SQL syntax error near '{payload[:20]}...'",
                    "query": f"SELECT * FROM users WHERE id = {payload[:30]}",
                },
            }
    
    def _xss_response(self, payload: str) -> Dict:
        """Generate fake XSS response (reflects payload)"""
        return {
            "status_code": 200,
            "body": {
                "message": f"Search results for: {payload}",
                "results": [],
                "html": f"<div class='result'>{payload}</div>",  # "Reflected"
            },
        }
    
    def _lfi_response(self, payload: str) -> Dict:
        """Generate fake LFI response"""
        payload_lower = payload.lower()
        
        if "passwd" in payload_lower:
            # Fake /etc/passwd
            users = []
            for _ in range(random.randint(10, 25)):
                username = self.fake_data.fake_username()
                uid = random.randint(1000, 65000)
                users.append(f"{username}:x:{uid}:{uid}::/home/{username}:/bin/bash")
            
            content = "root:x:0:0:root:/root:/bin/bash\n"
            content += "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            content += "\n".join(users)
            
            return {
                "status_code": 200,
                "body": content,
                "content_type": "text/plain",
            }
        
        elif "shadow" in payload_lower:
            # Fake /etc/shadow (honeypot gold!)
            users = []
            for _ in range(random.randint(5, 15)):
                username = self.fake_data.fake_username()
                hash_val = self.fake_data.fake_password_hash()
                users.append(f"{username}:{hash_val}:18000:0:99999:7:::")
            
            return {
                "status_code": 200,
                "body": "\n".join(users),
                "content_type": "text/plain",
            }
        
        else:
            # Generic file content
            return {
                "status_code": 200,
                "body": f"# Configuration file\n# Generated at {time.ctime()}\n\nkey=value\nsecret={self.fake_data.fake_uuid()}\n",
                "content_type": "text/plain",
            }
    
    def _rce_response(self, payload: str) -> Dict:
        """Generate fake RCE response"""
        payload_lower = payload.lower()
        
        commands = {
            "whoami": "www-data",
            "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            "pwd": "/var/www/html",
            "ls": "index.php\nconfig.php\nuploads\nbackup",
            "cat": f"<?php\n$db_password = '{self.fake_data.fake_uuid()}';\n",
            "uname": "Linux webserver 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux",
            "ifconfig": f"eth0: inet {self.fake_data.fake_ip()} netmask 255.255.255.0",
            "env": f"DB_PASSWORD={self.fake_data.fake_uuid()}\nAPI_KEY={self.fake_data.fake_uuid()}",
        }
        
        for cmd, output in commands.items():
            if cmd in payload_lower:
                return {
                    "status_code": 200,
                    "body": output,
                    "content_type": "text/plain",
                }
        
        return {
            "status_code": 200,
            "body": "command not found",
            "content_type": "text/plain",
        }
    
    def _ssrf_response(self, payload: str) -> Dict:
        """Generate fake SSRF response"""
        payload_lower = payload.lower()
        
        if "169.254.169.254" in payload_lower:
            # AWS metadata - this is what attackers really want!
            return {
                "status_code": 200,
                "body": {
                    "instanceId": f"i-{self.fake_data.fake_uuid()[:17]}",
                    "region": random.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]),
                    "availabilityZone": "us-east-1a",
                    "credentials": {
                        "AccessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
                        "SecretAccessKey": self.fake_data.fake_uuid(),
                        "Token": self.fake_data.fake_uuid() * 4,
                        "Expiration": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
                    },
                },
            }
        
        elif "localhost" in payload_lower or "127.0.0.1" in payload_lower:
            # Internal service
            return {
                "status_code": 200,
                "body": {"status": "healthy", "service": "internal-api", "version": "1.2.3"},
            }
        
        else:
            return {
                "status_code": 200,
                "body": "<html><body>Internal Page</body></html>",
                "content_type": "text/html",
            }
    
    def _generic_response(self) -> Dict:
        """Generic successful response"""
        return {
            "status_code": 200,
            "body": {"success": True, "message": "Operation completed"},
        }


# ============================================================================
# CANARY TOKEN SECURITY
# ============================================================================

class SecureCanaryStorage:
    """
    Secure storage for canary tokens
    
    Addresses: "Canary Token Leakage" vulnerability
    """
    
    def __init__(self, encryption_key: bytes = None):
        self.tokens: Dict[str, Dict] = {}
        self.lock = threading.Lock()
        
        # Generate encryption key if not provided
        if encryption_key:
            self.encryption_key = encryption_key
        else:
            import os
            self.encryption_key = os.urandom(32)
    
    def store_token(self, token_id: str, token_data: Dict):
        """Store token securely (metadata only, not the token value)"""
        with self.lock:
            # Don't store the actual token value, just metadata
            safe_data = {
                "token_id": token_id,
                "token_type": token_data.get("type"),
                "created_at": token_data.get("created_at", time.time()),
                "created_for": token_data.get("session_id"),
                "hash": hashlib.sha256(token_data.get("value", "").encode()).hexdigest()[:32],
            }
            self.tokens[token_id] = safe_data
    
    def verify_token(self, token_value: str) -> Optional[str]:
        """Verify token and return token_id if valid"""
        token_hash = hashlib.sha256(token_value.encode()).hexdigest()[:32]
        
        with self.lock:
            for token_id, data in self.tokens.items():
                if data.get("hash") == token_hash:
                    return token_id
        return None
    
    def record_trigger(self, token_id: str, context: Dict):
        """Record that a token was triggered"""
        with self.lock:
            if token_id in self.tokens:
                self.tokens[token_id]["triggered"] = True
                self.tokens[token_id]["triggered_at"] = time.time()
                # Store context hash, not full context (security)
                self.tokens[token_id]["trigger_hash"] = hashlib.sha256(
                    json.dumps(context, sort_keys=True).encode()
                ).hexdigest()[:32]


# Global instances
enhanced_responder = EnhancedHoneypotResponder()
secure_canary_storage = SecureCanaryStorage()
