"""
DECEPTICON Deception Layer
Honeypot routing, canary tokens, and tarpit functionality
"""
import time
import hashlib
import uuid
import json
import asyncio
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from collections import defaultdict
import threading
import re

from core.models import RequestContext, SessionState, WAFResult, RiskLevel, Action

@dataclass
class CanaryToken:
    """Trackable canary token"""
    token_id: str
    token_type: str  # credential, file, dns, url
    token_value: str
    created_at: float
    created_for_session: str
    triggered: bool = False
    triggered_at: Optional[float] = None
    triggered_from_ip: Optional[str] = None
    triggered_context: Optional[Dict] = None

@dataclass
class HoneypotSession:
    """Active honeypot session"""
    session_id: str
    honeypot_id: str
    client_ip: str
    started_at: float
    last_activity: float
    request_count: int = 0
    payloads_captured: List[str] = field(default_factory=list)
    commands_attempted: List[str] = field(default_factory=list)
    files_accessed: List[str] = field(default_factory=list)
    credentials_tried: List[Tuple[str, str]] = field(default_factory=list)
    canary_tokens_served: List[str] = field(default_factory=list)

class CanaryFactory:
    """
    Generate various types of canary tokens
    These phone home when accessed
    """
    
    def __init__(self, callback_url: str = "http://localhost:8080/api/canary/callback"):
        self.callback_url = callback_url
        self.tokens: Dict[str, CanaryToken] = {}
        self.lock = threading.Lock()
    
    def create_credential_token(self, session_id: str) -> Tuple[str, str]:
        """
        Create fake credentials that alert when used
        """
        token_id = uuid.uuid4().hex[:16]
        
        # Generate realistic-looking credentials
        usernames = ['admin_backup', 'sysadmin', 'root_user', 'db_admin', 'api_user']
        passwords = [
            'Navy2024Secure!', 'Tr0ub4dor&3', 'SecurePass123!',
            'Admin@2024', 'Qwerty123!'
        ]
        
        import random
        username = random.choice(usernames) + '_' + token_id[:4]
        password = random.choice(passwords)
        
        token = CanaryToken(
            token_id=token_id,
            token_type='credential',
            token_value=f"{username}:{password}",
            created_at=time.time(),
            created_for_session=session_id,
        )
        
        with self.lock:
            self.tokens[f"{username}:{password}"] = token
        
        return username, password
    
    def create_dns_token(self, session_id: str) -> str:
        """
        Create DNS canary - alerts when domain is resolved
        Works even through Tor (DNS leaks)
        """
        token_id = uuid.uuid4().hex[:8]
        domain = f"{token_id}.canary.decepticon.local"
        
        token = CanaryToken(
            token_id=token_id,
            token_type='dns',
            token_value=domain,
            created_at=time.time(),
            created_for_session=session_id,
        )
        
        with self.lock:
            self.tokens[domain] = token
        
        return domain
    
    def create_url_token(self, session_id: str, 
                          description: str = "classified_data") -> str:
        """
        Create URL canary - alerts when accessed
        """
        token_id = uuid.uuid4().hex[:16]
        
        # Create trackable URL
        url = f"{self.callback_url}/{token_id}/{description}"
        
        token = CanaryToken(
            token_id=token_id,
            token_type='url',
            token_value=url,
            created_at=time.time(),
            created_for_session=session_id,
        )
        
        with self.lock:
            self.tokens[token_id] = token
        
        return url
    
    def create_aws_key_token(self, session_id: str) -> Tuple[str, str]:
        """
        Create fake AWS credentials
        Very attractive to attackers!
        """
        import random
        import string
        
        token_id = uuid.uuid4().hex[:8]
        
        # Generate fake AWS-like keys
        access_key = 'AKIA' + ''.join(random.choices(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16
        ))
        secret_key = ''.join(random.choices(
            string.ascii_letters + string.digits + '+/', k=40
        ))
        
        token = CanaryToken(
            token_id=token_id,
            token_type='aws_key',
            token_value=f"{access_key}:{secret_key}",
            created_at=time.time(),
            created_for_session=session_id,
        )
        
        with self.lock:
            self.tokens[access_key] = token
        
        return access_key, secret_key
    
    def check_token(self, value: str) -> Optional[CanaryToken]:
        """
        Check if a value matches a canary token
        Returns token if found
        """
        with self.lock:
            # Direct lookup
            if value in self.tokens:
                return self.tokens[value]
            
            # Check partial matches (for credentials)
            for key, token in self.tokens.items():
                if value in key or key in value:
                    return token
        
        return None
    
    def trigger_token(self, token: CanaryToken, ip: str, 
                      context: Dict) -> None:
        """
        Mark token as triggered
        """
        token.triggered = True
        token.triggered_at = time.time()
        token.triggered_from_ip = ip
        token.triggered_context = context
    
    def get_triggered_tokens(self) -> List[CanaryToken]:
        """Get all triggered tokens"""
        return [t for t in self.tokens.values() if t.triggered]

class HoneypotRouter:
    """
    Route suspicious traffic to honeypots
    """
    
    def __init__(self):
        # Active honeypot sessions
        self.sessions: Dict[str, HoneypotSession] = {}
        
        # Honeypot response generators
        self.response_generators: Dict[str, Callable] = {}
        
        # Canary factory
        self.canary_factory = CanaryFactory()
        
        # Lock
        self.lock = threading.Lock()
        
        # Register default generators
        self._register_default_generators()
    
    def _register_default_generators(self):
        """Register default honeypot response generators"""
        
        # SQL Injection honeypot
        def sqli_honeypot(ctx: RequestContext, session: HoneypotSession) -> Dict:
            # Capture payload
            payload = ctx.query_string + ctx.body_str
            session.payloads_captured.append(payload[:500])
            
            # Generate fake database response
            creds = self.canary_factory.create_credential_token(session.session_id)
            session.canary_tokens_served.append(creds[0])
            
            return {
                'status': 200,
                'body': json.dumps({
                    'status': 'success',
                    'results': [
                        {'id': 1, 'username': creds[0], 'password': creds[1]},
                        {'id': 2, 'username': 'backup_admin', 'password': 'Backup123!'},
                    ],
                    'total': 2
                }),
                'headers': {'Content-Type': 'application/json'}
            }
        
        # XSS honeypot
        def xss_honeypot(ctx: RequestContext, session: HoneypotSession) -> Dict:
            payload = ctx.query_string + ctx.body_str
            session.payloads_captured.append(payload[:500])
            
            # Reflect the XSS with tracking
            url_token = self.canary_factory.create_url_token(
                session.session_id, 'xss_callback'
            )
            
            return {
                'status': 200,
                'body': f'''
                <html>
                <head><title>Admin Panel</title></head>
                <body>
                <h1>Welcome to Admin Panel</h1>
                <p>Search results for: {payload[:100]}</p>
                <script src="{url_token}"></script>
                <img src="{url_token}/pixel.gif" style="display:none"/>
                </body>
                </html>
                ''',
                'headers': {'Content-Type': 'text/html'}
            }
        
        # Command injection honeypot
        def rce_honeypot(ctx: RequestContext, session: HoneypotSession) -> Dict:
            payload = ctx.query_string + ctx.body_str
            session.payloads_captured.append(payload[:500])
            
            # Extract attempted commands
            cmd_patterns = [
                r';[\s]*(\w+)',
                r'\|[\s]*(\w+)',
                r'`([^`]+)`',
                r'\$\(([^)]+)\)'
            ]
            
            for pattern in cmd_patterns:
                matches = re.findall(pattern, payload)
                for cmd in matches:
                    session.commands_attempted.append(cmd[:50])
            
            # Generate fake command output
            fake_outputs = {
                'whoami': 'www-data',
                'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
                'pwd': '/var/www/html',
                'ls': 'config.php\nindex.php\nuploads/\nbackup/',
                'cat': '[Access Denied]',
                'uname': 'Linux webserver 5.4.0-42-generic',
            }
            
            output = "Command executed.\n"
            for cmd, out in fake_outputs.items():
                if cmd in payload.lower():
                    output += f"\n{out}\n"
            
            return {
                'status': 200,
                'body': output,
                'headers': {'Content-Type': 'text/plain'}
            }
        
        # File inclusion honeypot
        def lfi_honeypot(ctx: RequestContext, session: HoneypotSession) -> Dict:
            payload = ctx.query_string + ctx.body_str
            session.payloads_captured.append(payload[:500])
            
            # Track accessed files
            file_patterns = re.findall(r'(?:\.\./|\.\.\\)+([^&\s]+)', payload)
            session.files_accessed.extend(file_patterns[:10])
            
            # Serve fake sensitive file with canary
            dns_canary = self.canary_factory.create_dns_token(session.session_id)
            aws_keys = self.canary_factory.create_aws_key_token(session.session_id)
            
            fake_passwd = f'''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:admin:/home/admin:/bin/bash

# AWS Keys (for deployment)
# Access Key: {aws_keys[0]}
# Secret: {aws_keys[1]}
# Check: {dns_canary}
'''
            session.canary_tokens_served.append(aws_keys[0])
            
            return {
                'status': 200,
                'body': fake_passwd,
                'headers': {'Content-Type': 'text/plain'}
            }
        
        # Admin panel honeypot
        def admin_honeypot(ctx: RequestContext, session: HoneypotSession) -> Dict:
            # Check for login attempts
            if ctx.method == 'POST':
                body = ctx.body_str
                
                # Extract credentials
                user_match = re.search(r'(?:user(?:name)?|login)\s*[=:]\s*([^&\s]+)', body, re.I)
                pass_match = re.search(r'(?:pass(?:word)?|pwd)\s*[=:]\s*([^&\s]+)', body, re.I)
                
                if user_match and pass_match:
                    session.credentials_tried.append((user_match.group(1), pass_match.group(1)))
                    
                    # Check if using our canary creds
                    cred_token = self.canary_factory.check_token(
                        f"{user_match.group(1)}:{pass_match.group(1)}"
                    )
                    
                    if cred_token:
                        self.canary_factory.trigger_token(
                            cred_token, 
                            ctx.client_ip,
                            {'path': ctx.path, 'session': session.session_id}
                        )
                
                # Fake successful login
                return {
                    'status': 200,
                    'body': json.dumps({
                        'status': 'success',
                        'message': 'Login successful',
                        'redirect': '/admin/dashboard'
                    }),
                    'headers': {'Content-Type': 'application/json'}
                }
            
            # Serve fake admin panel
            return {
                'status': 200,
                'body': '''
                <html>
                <head><title>Admin Login</title></head>
                <body>
                <h1>Naval Admin Portal</h1>
                <form method="POST">
                    <input name="username" placeholder="Username"><br>
                    <input name="password" type="password" placeholder="Password"><br>
                    <button type="submit">Login</button>
                </form>
                </body>
                </html>
                ''',
                'headers': {'Content-Type': 'text/html'}
            }
        
        self.response_generators = {
            'SQLI': sqli_honeypot,
            'XSS': xss_honeypot,
            'RCE': rce_honeypot,
            'LFI': lfi_honeypot,
            'ADMIN': admin_honeypot,
            'DEFAULT': admin_honeypot,
        }
    
    def should_route_to_honeypot(self, result: WAFResult, 
                                   session_state: SessionState) -> bool:
        """
        Determine if request should be routed to honeypot
        """
        # High confidence attacks - engage attacker
        if result.risk_level >= RiskLevel.HIGH:
            return True
        
        # Suspicious session with multiple blocked attempts
        if session_state.blocked_count >= 3:
            return True
        
        # Known scanner behavior
        if session_state.is_scanner:
            return True
        
        return False
    
    def get_honeypot_type(self, result: WAFResult) -> str:
        """
        Determine appropriate honeypot type based on attack
        """
        for detection in result.detections:
            if detection.category in self.response_generators:
                return detection.category
        
        return 'DEFAULT'
    
    def route_to_honeypot(self, ctx: RequestContext, 
                           result: WAFResult,
                           honeypot_type: str = 'DEFAULT') -> Dict:
        """
        Route request to honeypot and generate response
        """
        # Get or create session
        session_id = f"hp_{ctx.client_ip}_{ctx.request_id[:8]}"
        
        with self.lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = HoneypotSession(
                    session_id=session_id,
                    honeypot_id=honeypot_type,
                    client_ip=ctx.client_ip,
                    started_at=time.time(),
                    last_activity=time.time(),
                )
            
            session = self.sessions[session_id]
            session.request_count += 1
            session.last_activity = time.time()
        
        # Get response generator
        generator = self.response_generators.get(
            honeypot_type, 
            self.response_generators['DEFAULT']
        )
        
        # Generate response
        response = generator(ctx, session)
        
        # Update result
        result.route_to_honeypot = True
        result.honeypot_id = session_id
        
        return response
    
    def get_session_intel(self, session_id: str) -> Optional[Dict]:
        """
        Get intelligence gathered from honeypot session
        """
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            'session_id': session.session_id,
            'honeypot_type': session.honeypot_id,
            'client_ip': session.client_ip,
            'duration': time.time() - session.started_at,
            'request_count': session.request_count,
            'payloads': session.payloads_captured[:10],
            'commands': session.commands_attempted[:10],
            'files': session.files_accessed[:10],
            'credentials': session.credentials_tried[:10],
            'canary_tokens': session.canary_tokens_served,
        }
    
    def get_captured_payloads(self, session_id: str) -> List[str]:
        """
        Get captured payloads from a honeypot session
        Used by rule generator to create rules from honeypot intel
        """
        session = self.sessions.get(session_id)
        if not session:
            return []
        return session.payloads_captured
    
    def route_request(self, ctx: RequestContext, 
                     attack_category: str = "UNKNOWN",
                     confidence: float = 0.5) -> Dict:
        """
        Simple wrapper for route_to_honeypot
        Called by WAF engine when attack is detected
        """
        from core.models import WAFResult, RiskLevel
        
        # Create a minimal result object
        result = WAFResult(
            request_id=ctx.request_id,
            action=Action.CHALLENGE,
            risk_level=RiskLevel.MEDIUM,
            detections=[],
            start_time=time.time(),
        )
        
        # Map attack category to honeypot type
        honeypot_type = attack_category if attack_category in self.response_generators else 'DEFAULT'
        
        return self.route_to_honeypot(ctx, result, honeypot_type)
    
    def get_all_triggered_canaries(self) -> List[Dict]:
        """
        Get all triggered canary tokens
        """
        tokens = self.canary_factory.get_triggered_tokens()
        return [
            {
                'token_id': t.token_id,
                'type': t.token_type,
                'created_for': t.created_for_session,
                'triggered_at': t.triggered_at,
                'triggered_from': t.triggered_from_ip,
                'context': t.triggered_context,
            }
            for t in tokens
        ]

class Tarpit:
    """
    Waste attacker time and resources
    """
    
    @staticmethod
    async def slow_response(delay_ms: int = 5000) -> bytes:
        """
        Generate infinitely slow response
        """
        chunk_delay = delay_ms / 100  # Send 100 chunks
        
        yield b"HTTP/1.1 200 OK\r\n"
        yield b"Content-Type: text/html\r\n"
        yield b"Transfer-Encoding: chunked\r\n\r\n"
        
        # Send tiny chunks very slowly
        words = [
            b"Loading", b"...", b"Please", b"wait", b"...",
            b"Processing", b"...", b"Almost", b"done", b"..."
        ]
        
        for i in range(100):  # 100 iterations
            await asyncio.sleep(chunk_delay / 1000)
            chunk = words[i % len(words)] + b" "
            yield f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
        
        yield b"0\r\n\r\n"  # End of chunked response
    
    @staticmethod
    def generate_infinite_maze() -> Dict:
        """
        Generate fake directory structure to waste scanner time
        """
        import random
        
        folders = []
        for i in range(random.randint(5, 15)):
            folder_type = random.choice(['admin', 'backup', 'config', 'data', 'logs', 'temp'])
            folder_name = f"{folder_type}_{random.randint(100, 999)}"
            folders.append({
                'name': folder_name,
                'type': 'directory',
                'modified': '2024-01-15 10:30:00',
            })
        
        files = []
        for i in range(random.randint(3, 8)):
            file_type = random.choice(['config', 'backup', 'data', 'credentials', 'secret'])
            file_ext = random.choice(['.txt', '.bak', '.sql', '.xml', '.conf'])
            files.append({
                'name': f"{file_type}_{random.randint(100, 999)}{file_ext}",
                'type': 'file',
                'size': random.randint(1000, 100000),
            })
        
        return {
            'status': 200,
            'body': json.dumps({
                'entries': folders + files,
                'total': len(folders) + len(files),
                'page': 1,
            }),
            'headers': {'Content-Type': 'application/json'}
        }

# Global instances
honeypot_router = HoneypotRouter()
canary_factory = CanaryFactory()
