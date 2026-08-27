"""
MIRAGE Comprehensive Honeypot System
=========================================
Naval SWAVLAMBAN 2025 Challenge 3

Honeypot responses for ALL attack types:
- SQL Injection: Fake database responses with canary credentials
- XSS: Reflected payloads with tracking pixels
- RCE: Fake shell outputs with honeypot commands
- Path Traversal/LFI: Fake sensitive files with canaries
- SSRF: Fake internal service responses
- XXE: Fake XML parsing with entity expansion tracking
- SSTI: Fake template engine outputs
- NoSQL: Fake MongoDB responses
- JWT: Fake token acceptance with logging
- GraphQL: Fake schema introspection
- Prototype Pollution: Fake object modification success
- Deserialization: Fake object loading responses
- LDAP: Fake directory responses
- CRLF: Fake header injection success
- Open Redirect: Redirect tracking

Author: MIRAGE Team
Date: December 2025
"""

import time
import hashlib
import uuid
import json
import re
import threading
import random
from typing import Dict, List, Optional, Tuple, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime

from core.models import RequestContext, WAFResult, RiskLevel


@dataclass
class AttackerProfile:
    """Profile built from attacker behavior"""
    ip_address: str
    first_seen: float
    last_seen: float
    total_requests: int = 0
    attack_types: List[str] = field(default_factory=list)
    payloads_captured: List[str] = field(default_factory=list)
    canaries_triggered: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    tools_detected: List[str] = field(default_factory=list)
    sophistication_score: float = 0.0
    

@dataclass
class CanaryToken:
    """Trackable canary token"""
    token_id: str
    token_type: str
    token_value: str
    created_at: float
    attack_type: str
    session_id: str
    triggered: bool = False
    triggered_at: Optional[float] = None
    triggered_context: Optional[Dict] = None


class ComprehensiveHoneypot:
    """
    Comprehensive honeypot system with responses for ALL attack types.
    
    Features:
    - Attack-specific fake responses
    - Canary token generation and tracking
    - Attacker profiling and fingerprinting
    - Payload capture for threat intelligence
    - Tool detection (sqlmap, nikto, etc.)
    """
    
    def __init__(self, callback_domain: str = "canary.mirage.local"):
        self.callback_domain = callback_domain
        self.canaries: Dict[str, CanaryToken] = {}
        self.attacker_profiles: Dict[str, AttackerProfile] = {}
        self.captured_payloads: List[Dict] = []
        self.lock = threading.Lock()
        
        # Initialize response generators for ALL attack types
        self.response_generators = {
            'sqli': self._sqli_response,
            'SQLI': self._sqli_response,
            'sql_injection': self._sqli_response,
            
            'xss': self._xss_response,
            'XSS': self._xss_response,
            'cross_site_scripting': self._xss_response,
            
            'rce': self._rce_response,
            'RCE': self._rce_response,
            'remote_code_execution': self._rce_response,
            'command_injection': self._rce_response,
            
            'path_traversal': self._path_traversal_response,
            'PATH_TRAVERSAL': self._path_traversal_response,
            'lfi': self._lfi_response,
            'LFI': self._lfi_response,
            'local_file_inclusion': self._lfi_response,
            'rfi': self._rfi_response,
            'RFI': self._rfi_response,
            
            'ssrf': self._ssrf_response,
            'SSRF': self._ssrf_response,
            'server_side_request_forgery': self._ssrf_response,
            
            'xxe': self._xxe_response,
            'XXE': self._xxe_response,
            'xml_external_entity': self._xxe_response,
            
            'ssti': self._ssti_response,
            'SSTI': self._ssti_response,
            'server_side_template_injection': self._ssti_response,
            
            'nosql': self._nosql_response,
            'NOSQL': self._nosql_response,
            'nosql_injection': self._nosql_response,
            
            'jwt': self._jwt_response,
            'JWT': self._jwt_response,
            'jwt_attack': self._jwt_response,
            
            'graphql': self._graphql_response,
            'GRAPHQL': self._graphql_response,
            'graphql_attack': self._graphql_response,
            
            'prototype_pollution': self._prototype_pollution_response,
            'PROTOTYPE_POLLUTION': self._prototype_pollution_response,
            
            'deserialization': self._deserialization_response,
            'DESERIALIZATION': self._deserialization_response,
            'insecure_deserialization': self._deserialization_response,
            
            'ldap': self._ldap_response,
            'LDAP': self._ldap_response,
            'ldap_injection': self._ldap_response,
            
            'crlf': self._crlf_response,
            'CRLF': self._crlf_response,
            'crlf_injection': self._crlf_response,
            
            'open_redirect': self._open_redirect_response,
            'OPEN_REDIRECT': self._open_redirect_response,
            
            'scanner': self._scanner_response,
            'SCANNER': self._scanner_response,
            
            'default': self._default_response,
            'DEFAULT': self._default_response,
        }
    
    def _create_canary(self, attack_type: str, session_id: str, 
                       token_type: str = "credential") -> str:
        """Create a trackable canary token"""
        token_id = uuid.uuid4().hex[:16]
        
        if token_type == "credential":
            value = f"admin_{token_id[:8]}:Navy2025Secure!"
        elif token_type == "aws_key":
            value = f"AKIA{token_id.upper()[:16]}"
        elif token_type == "api_key":
            value = f"sk-{token_id}"
        elif token_type == "dns":
            value = f"{token_id}.{self.callback_domain}"
        else:
            value = token_id
        
        canary = CanaryToken(
            token_id=token_id,
            token_type=token_type,
            token_value=value,
            created_at=time.time(),
            attack_type=attack_type,
            session_id=session_id
        )
        
        with self.lock:
            self.canaries[token_id] = canary
        
        return value
    
    def _update_attacker_profile(self, ctx: RequestContext, 
                                  attack_type: str, payload: str):
        """Update attacker profile with new activity"""
        with self.lock:
            ip = ctx.client_ip
            
            if ip not in self.attacker_profiles:
                self.attacker_profiles[ip] = AttackerProfile(
                    ip_address=ip,
                    first_seen=time.time(),
                    last_seen=time.time()
                )
            
            profile = self.attacker_profiles[ip]
            profile.last_seen = time.time()
            profile.total_requests += 1
            
            if attack_type not in profile.attack_types:
                profile.attack_types.append(attack_type)
            
            profile.payloads_captured.append(payload[:200])
            
            # Detect tools
            ua = ctx.headers.get('user-agent', '').lower()
            tools = ['sqlmap', 'nikto', 'nmap', 'burp', 'zap', 'nuclei', 
                     'ffuf', 'gobuster', 'wfuzz', 'hydra', 'metasploit']
            for tool in tools:
                if tool in ua and tool not in profile.tools_detected:
                    profile.tools_detected.append(tool)
            
            # Calculate sophistication
            profile.sophistication_score = self._calculate_sophistication(profile)
    
    def _calculate_sophistication(self, profile: AttackerProfile) -> float:
        """Calculate attacker sophistication score (0-10)"""
        score = 0.0
        
        # Multiple attack types = more sophisticated
        score += min(len(profile.attack_types) * 0.5, 3.0)
        
        # Using known tools = moderate sophistication
        score += min(len(profile.tools_detected) * 0.3, 2.0)
        
        # Long engagement = dedicated attacker
        duration = profile.last_seen - profile.first_seen
        if duration > 3600:  # > 1 hour
            score += 1.0
        if duration > 86400:  # > 1 day
            score += 1.0
        
        # Many requests = persistent
        if profile.total_requests > 100:
            score += 1.0
        if profile.total_requests > 1000:
            score += 1.0
        
        return min(score, 10.0)
    
    def _capture_payload(self, ctx: RequestContext, attack_type: str):
        """Capture payload for threat intelligence"""
        payload_data = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'client_ip': ctx.client_ip,
            'method': ctx.method,
            'path': ctx.path,
            'query': ctx.query_string[:500] if ctx.query_string else None,
            'body': ctx.body_str[:1000] if ctx.body_str else None,
            'user_agent': ctx.headers.get('user-agent', '')[:200],
            'headers': {k: v[:100] for k, v in list(ctx.headers.items())[:10]}
        }
        
        with self.lock:
            self.captured_payloads.append(payload_data)
            # Keep last 10000 payloads
            if len(self.captured_payloads) > 10000:
                self.captured_payloads = self.captured_payloads[-10000:]
    
    # ========================================================================
    # ATTACK-SPECIFIC RESPONSE GENERATORS
    # ========================================================================
    
    def _sqli_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake SQL injection success response"""
        cred_canary = self._create_canary('sqli', session_id, 'credential')
        api_canary = self._create_canary('sqli', session_id, 'api_key')
        
        fake_users = [
            {'id': 1, 'username': 'admin', 'password': cred_canary.split(':')[1], 
             'email': 'admin@navy.mil', 'role': 'superadmin'},
            {'id': 2, 'username': cred_canary.split(':')[0], 'password': 'hashed_pw_12345',
             'email': 'backup@navy.mil', 'role': 'admin'},
            {'id': 3, 'username': 'operator', 'password': 'op3r4t0r!',
             'email': 'ops@navy.mil', 'role': 'user', 'api_key': api_canary},
        ]
        
        return {
            'status': 200,
            'body': json.dumps({
                'status': 'success',
                'query': 'SELECT * FROM users',
                'results': fake_users,
                'rows_returned': len(fake_users)
            }, indent=2),
            'headers': {
                'Content-Type': 'application/json',
                'X-Database': 'mysql-8.0.28',
                'X-Query-Time': '0.023s'
            }
        }
    
    def _xss_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate XSS reflection response with tracking"""
        payload = ctx.query_string or ctx.body_str or ''
        dns_canary = self._create_canary('xss', session_id, 'dns')
        
        # Reflect payload but add tracking
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Search Results - Naval Portal</title>
    <script src="https://{dns_canary}/tracking.js"></script>
</head>
<body>
    <h1>Naval Information Portal</h1>
    <div class="results">
        <p>Search results for: {payload[:200]}</p>
        <p>No results found.</p>
    </div>
    <img src="https://{dns_canary}/pixel.gif" style="display:none" />
</body>
</html>'''
        
        return {
            'status': 200,
            'body': html,
            'headers': {
                'Content-Type': 'text/html',
                'X-XSS-Protection': '0'  # Intentionally disabled to "allow" XSS
            }
        }
    
    def _rce_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake command execution output"""
        payload = ctx.query_string + (ctx.body_str or '')
        dns_canary = self._create_canary('rce', session_id, 'dns')
        
        # Detect what command they're trying
        fake_outputs = {
            'whoami': 'www-data',
            'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
            'pwd': '/var/www/html/api',
            'ls': f'config.php\nindex.php\n.env\nbackup_{dns_canary}.sql',
            'cat': f'DB_HOST=localhost\nDB_USER=root\nDB_PASS=N4vyS3cr3t!\nCANARY={dns_canary}',
            'uname': 'Linux naval-webserver 5.15.0-generic #1 SMP x86_64 GNU/Linux',
            'ifconfig': 'eth0: inet 10.0.0.15 netmask 255.255.255.0',
            'curl': f'Connected to {dns_canary}',
            'wget': f'Connecting to {dns_canary}... connected.',
            'ping': f'PING {dns_canary} (10.0.0.1): 56 data bytes',
            'nc': 'Connection established',
            'bash': '[Interactive shell started]',
            'python': 'Python 3.9.7',
            'php': 'PHP 8.1.0',
        }
        
        output = "Command output:\n" + "=" * 40 + "\n"
        found_cmd = False
        for cmd, out in fake_outputs.items():
            if cmd in payload.lower():
                output += f"$ {cmd}\n{out}\n\n"
                found_cmd = True
        
        if not found_cmd:
            output += "$ command\nsh: command: not found\n"
        
        return {
            'status': 200,
            'body': output,
            'headers': {'Content-Type': 'text/plain'}
        }
    
    def _path_traversal_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake file contents for path traversal"""
        return self._lfi_response(ctx, session_id)
    
    def _lfi_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake sensitive file contents"""
        payload = ctx.query_string + (ctx.body_str or '')
        aws_canary = self._create_canary('lfi', session_id, 'aws_key')
        cred_canary = self._create_canary('lfi', session_id, 'credential')
        
        # Determine which file they're trying to access
        if 'passwd' in payload.lower():
            content = f'''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
naval_admin:x:1000:1000:Naval Admin,,,:/home/naval_admin:/bin/bash
{cred_canary.split(':')[0]}:x:1001:1001:Backup User:/home/backup:/bin/bash
'''
        elif 'shadow' in payload.lower():
            content = f'''root:$6$xyz$hashed_password:19000:0:99999:7:::
naval_admin:$6$abc${cred_canary.split(':')[1]}:19000:0:99999:7:::
'''
        elif '.env' in payload.lower() or 'config' in payload.lower():
            content = f'''# Naval Application Config
DB_HOST=localhost
DB_NAME=naval_ops
DB_USER=root
DB_PASSWORD=N4vyD4t4b4s3!

AWS_ACCESS_KEY_ID={aws_canary}
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

API_KEY={self._create_canary('lfi', session_id, 'api_key')}
'''
        elif 'ssh' in payload.lower() or 'id_rsa' in payload.lower():
            content = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQT+[FAKE_KEY_FOR_HONEYPOT]+
-----END OPENSSH PRIVATE KEY-----
'''
        else:
            content = f'''# Sensitive Configuration File
# Naval Operations System
SECRET_KEY={cred_canary}
AWS_KEY={aws_canary}
'''
        
        return {
            'status': 200,
            'body': content,
            'headers': {'Content-Type': 'text/plain'}
        }
    
    def _rfi_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake remote file inclusion response"""
        return self._lfi_response(ctx, session_id)
    
    def _ssrf_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake SSRF response (internal service/cloud metadata)"""
        payload = ctx.query_string + (ctx.body_str or '')
        aws_canary = self._create_canary('ssrf', session_id, 'aws_key')
        
        # AWS metadata emulation
        if '169.254.169.254' in payload or 'meta-data' in payload:
            if 'iam' in payload.lower() and 'credentials' in payload.lower():
                content = json.dumps({
                    'Code': 'Success',
                    'LastUpdated': datetime.now().isoformat(),
                    'Type': 'AWS-HMAC',
                    'AccessKeyId': aws_canary,
                    'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYNAVYKEY',
                    'Token': 'FwoGZXIvYXdzEBYaDK...[truncated]',
                    'Expiration': '2025-12-31T23:59:59Z'
                }, indent=2)
            elif 'instance-id' in payload:
                content = 'i-0abc123def456789'
            elif 'hostname' in payload:
                content = 'naval-internal-server.ec2.internal'
            else:
                content = '''ami-id
instance-id
instance-type
local-hostname
local-ipv4
public-hostname
public-ipv4
security-groups
iam/'''
        
        # Internal service emulation
        elif 'localhost' in payload or '127.0.0.1' in payload:
            if ':6379' in payload:  # Redis
                content = '+OK\r\n$5\r\nredis\r\n'
            elif ':11211' in payload:  # Memcached
                content = 'STAT version 1.6.9\r\nEND\r\n'
            elif ':9200' in payload:  # Elasticsearch
                content = json.dumps({
                    'name': 'naval-es-node',
                    'cluster_name': 'naval-cluster',
                    'version': {'number': '8.6.0'}
                })
            else:
                content = json.dumps({
                    'status': 'ok',
                    'internal_service': True,
                    'hostname': 'naval-internal'
                })
        else:
            content = json.dumps({
                'status': 'connected',
                'response': 'Internal service response'
            })
        
        return {
            'status': 200,
            'body': content,
            'headers': {
                'Content-Type': 'application/json',
                'X-Internal-Service': 'true'
            }
        }
    
    def _xxe_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake XXE response showing entity expansion"""
        cred_canary = self._create_canary('xxe', session_id, 'credential')
        
        # Fake file content from XXE
        fake_content = f'''<?xml version="1.0"?>
<response>
    <status>success</status>
    <data>
        <!-- Entity expansion result -->
        <file_content>root:x:0:0:root:/root:/bin/bash
{cred_canary.split(':')[0]}:x:1000:1000::/home/admin:/bin/bash</file_content>
    </data>
    <debug>Entity 'xxe' expanded successfully</debug>
</response>'''
        
        return {
            'status': 200,
            'body': fake_content,
            'headers': {'Content-Type': 'application/xml'}
        }
    
    def _ssti_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake SSTI response showing template execution"""
        payload = ctx.query_string + (ctx.body_str or '')
        dns_canary = self._create_canary('ssti', session_id, 'dns')
        
        # Detect template syntax and respond accordingly
        if '{{' in payload and '}}' in payload:  # Jinja2/Twig
            if '7*7' in payload:
                result = '49'
            elif 'config' in payload.lower():
                result = f"<Config {{'SECRET_KEY': '{dns_canary}'}}>"
            elif 'os.popen' in payload or 'system' in payload:
                result = 'www-data'
            else:
                result = f'[Template rendered: {dns_canary}]'
        elif '${' in payload:  # Freemarker/Velocity
            result = f'FreeMarker output: {dns_canary}'
        elif '<%' in payload:  # ERB
            result = f'ERB result: {dns_canary}'
        else:
            result = f'Template processed: {dns_canary}'
        
        return {
            'status': 200,
            'body': f'''<!DOCTYPE html>
<html>
<body>
<h1>Template Result</h1>
<div class="output">{result}</div>
</body>
</html>''',
            'headers': {'Content-Type': 'text/html'}
        }
    
    def _nosql_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake NoSQL injection success response"""
        cred_canary = self._create_canary('nosql', session_id, 'credential')
        
        fake_docs = [
            {
                '_id': '507f1f77bcf86cd799439011',
                'username': 'admin',
                'password': cred_canary.split(':')[1],
                'role': 'superadmin',
                'email': 'admin@navy.mil'
            },
            {
                '_id': '507f1f77bcf86cd799439012', 
                'username': cred_canary.split(':')[0],
                'password': 'backup_pass_123',
                'role': 'admin',
                'apiKey': self._create_canary('nosql', session_id, 'api_key')
            }
        ]
        
        return {
            'status': 200,
            'body': json.dumps({
                'ok': 1,
                'cursor': {
                    'firstBatch': fake_docs,
                    'id': 0,
                    'ns': 'naval_db.users'
                }
            }, indent=2),
            'headers': {
                'Content-Type': 'application/json',
                'X-MongoDB-Version': '6.0.3'
            }
        }
    
    def _jwt_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake JWT acceptance response"""
        api_canary = self._create_canary('jwt', session_id, 'api_key')
        
        # Create a fake "accepted" JWT response
        fake_user = {
            'user_id': 1,
            'username': 'admin',
            'role': 'superadmin',
            'permissions': ['read', 'write', 'delete', 'admin'],
            'api_key': api_canary
        }
        
        return {
            'status': 200,
            'body': json.dumps({
                'authenticated': True,
                'message': 'JWT token accepted',
                'user': fake_user,
                'new_token': 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.'
            }, indent=2),
            'headers': {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer accepted'
            }
        }
    
    def _graphql_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake GraphQL introspection/mutation response"""
        payload = ctx.body_str or ctx.query_string or ''
        cred_canary = self._create_canary('graphql', session_id, 'credential')
        
        # Introspection response
        if '__schema' in payload or '__type' in payload:
            response = {
                'data': {
                    '__schema': {
                        'types': [
                            {'name': 'User', 'fields': ['id', 'username', 'password', 'apiKey']},
                            {'name': 'Secret', 'fields': ['id', 'key', 'value']},
                            {'name': 'Config', 'fields': ['database', 'apiEndpoint', 'secretKey']},
                            {'name': 'Mutation', 'fields': ['createUser', 'deleteUser', 'updateConfig']}
                        ],
                        'queryType': {'name': 'Query'},
                        'mutationType': {'name': 'Mutation'}
                    }
                }
            }
        else:
            # Regular query response with fake data
            response = {
                'data': {
                    'users': [
                        {'id': '1', 'username': 'admin', 'password': cred_canary.split(':')[1]},
                        {'id': '2', 'username': cred_canary.split(':')[0], 'apiKey': 'sk-navy123'}
                    ],
                    'config': {
                        'secretKey': self._create_canary('graphql', session_id, 'api_key')
                    }
                }
            }
        
        return {
            'status': 200,
            'body': json.dumps(response, indent=2),
            'headers': {'Content-Type': 'application/json'}
        }
    
    def _prototype_pollution_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake prototype pollution success response"""
        dns_canary = self._create_canary('prototype_pollution', session_id, 'dns')
        
        return {
            'status': 200,
            'body': json.dumps({
                'status': 'success',
                'message': 'Object updated successfully',
                'object': {
                    'name': 'config',
                    'admin': True,  # "Successfully polluted"
                    'isAdmin': True,
                    '__proto__': {'polluted': True},
                    'debug': dns_canary
                }
            }, indent=2),
            'headers': {'Content-Type': 'application/json'}
        }
    
    def _deserialization_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake deserialization response"""
        dns_canary = self._create_canary('deserialization', session_id, 'dns')
        
        return {
            'status': 200,
            'body': json.dumps({
                'status': 'success',
                'message': 'Object deserialized successfully',
                'result': {
                    'class': 'java.lang.Runtime',
                    'executed': True,
                    'output': f'Command executed. Callback: {dns_canary}'
                }
            }, indent=2),
            'headers': {'Content-Type': 'application/json'}
        }
    
    def _ldap_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate fake LDAP query response"""
        cred_canary = self._create_canary('ldap', session_id, 'credential')
        
        fake_ldap = f'''dn: cn=admin,dc=navy,dc=mil
cn: admin
sn: Administrator
userPassword: {cred_canary.split(':')[1]}
mail: admin@navy.mil

dn: cn={cred_canary.split(':')[0]},dc=navy,dc=mil
cn: {cred_canary.split(':')[0]}
userPassword: backup_password
mail: backup@navy.mil
'''
        
        return {
            'status': 200,
            'body': fake_ldap,
            'headers': {'Content-Type': 'text/plain'}
        }
    
    def _crlf_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate response showing CRLF injection 'success'"""
        dns_canary = self._create_canary('crlf', session_id, 'dns')
        
        return {
            'status': 200,
            'body': f'Redirecting...\n\nSet-Cookie: session={dns_canary}; HttpOnly\n',
            'headers': {
                'Content-Type': 'text/html',
                'X-Injected': 'true',
                'Set-Cookie': f'honeypot={dns_canary}'
            }
        }
    
    def _open_redirect_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate open redirect tracking response"""
        dns_canary = self._create_canary('open_redirect', session_id, 'dns')
        
        return {
            'status': 302,
            'body': f'Redirecting to: https://{dns_canary}/tracking',
            'headers': {
                'Location': f'https://{dns_canary}/redirect-logged',
                'X-Redirect-Logged': 'true'
            }
        }
    
    def _scanner_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Generate response for detected scanners"""
        # Slow down scanners with tarpit
        time.sleep(random.uniform(0.5, 2.0))
        
        return {
            'status': 200,
            'body': json.dumps({
                'status': 'ok',
                'version': '1.0.0',
                'endpoints': ['/api/v1/users', '/api/v1/admin', '/api/v1/config']
            }),
            'headers': {'Content-Type': 'application/json'}
        }
    
    def _default_response(self, ctx: RequestContext, session_id: str) -> Dict:
        """Default honeypot response"""
        return {
            'status': 200,
            'body': json.dumps({
                'status': 'success',
                'message': 'Request processed'
            }),
            'headers': {'Content-Type': 'application/json'}
        }
    
    # ========================================================================
    # PUBLIC API
    # ========================================================================
    
    def generate_response(self, ctx: RequestContext, 
                          attack_type: str,
                          result: Optional[WAFResult] = None) -> Dict:
        """
        Generate honeypot response for detected attack.
        
        Args:
            ctx: Request context
            attack_type: Type of attack detected
            result: Optional WAF result with detection details
            
        Returns:
            Dict with status, body, headers for fake response
        """
        session_id = f"hp_{ctx.client_ip}_{uuid.uuid4().hex[:8]}"
        
        # Update attacker profile
        payload = (ctx.query_string or '') + (ctx.body_str or '')
        self._update_attacker_profile(ctx, attack_type, payload)
        
        # Capture payload for threat intelligence
        self._capture_payload(ctx, attack_type)
        
        # Get appropriate response generator
        generator = self.response_generators.get(
            attack_type.lower(),
            self.response_generators['default']
        )
        
        # Generate response
        response = generator(ctx, session_id)
        
        # Add common honeypot headers (subtle)
        response['headers']['X-Request-ID'] = session_id
        
        return response
    
    def get_attacker_profile(self, ip: str) -> Optional[AttackerProfile]:
        """Get attacker profile by IP"""
        return self.attacker_profiles.get(ip)
    
    def get_all_profiles(self) -> Dict[str, AttackerProfile]:
        """Get all attacker profiles"""
        return dict(self.attacker_profiles)
    
    def get_triggered_canaries(self) -> List[CanaryToken]:
        """Get all triggered canary tokens"""
        return [c for c in self.canaries.values() if c.triggered]
    
    def get_captured_payloads(self, attack_type: Optional[str] = None,
                               limit: int = 100) -> List[Dict]:
        """Get captured payloads, optionally filtered by attack type"""
        payloads = self.captured_payloads
        
        if attack_type:
            payloads = [p for p in payloads if p['attack_type'] == attack_type]
        
        return payloads[-limit:]
    
    def check_canary(self, value: str) -> Optional[CanaryToken]:
        """Check if a value matches a canary token"""
        for canary in self.canaries.values():
            if canary.token_value == value or value in canary.token_value:
                return canary
        return None
    
    def trigger_canary(self, token_id: str, context: Dict):
        """Mark a canary as triggered"""
        with self.lock:
            if token_id in self.canaries:
                self.canaries[token_id].triggered = True
                self.canaries[token_id].triggered_at = time.time()
                self.canaries[token_id].triggered_context = context
    
    def get_statistics(self) -> Dict:
        """Get honeypot statistics"""
        return {
            'total_attackers': len(self.attacker_profiles),
            'total_canaries': len(self.canaries),
            'triggered_canaries': len(self.get_triggered_canaries()),
            'captured_payloads': len(self.captured_payloads),
            'attack_type_distribution': self._get_attack_distribution(),
            'top_sophisticated_attackers': self._get_top_attackers(5)
        }
    
    def _get_attack_distribution(self) -> Dict[str, int]:
        """Get distribution of attack types"""
        distribution = {}
        for payload in self.captured_payloads:
            attack_type = payload['attack_type']
            distribution[attack_type] = distribution.get(attack_type, 0) + 1
        return distribution
    
    def _get_top_attackers(self, n: int) -> List[Dict]:
        """Get top N most sophisticated attackers"""
        profiles = sorted(
            self.attacker_profiles.values(),
            key=lambda p: p.sophistication_score,
            reverse=True
        )[:n]
        
        return [
            {
                'ip': p.ip_address,
                'sophistication': p.sophistication_score,
                'attack_types': p.attack_types,
                'tools': p.tools_detected,
                'requests': p.total_requests
            }
            for p in profiles
        ]


# Singleton instance
comprehensive_honeypot = ComprehensiveHoneypot()


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    print("MIRAGE Comprehensive Honeypot")
    print("=" * 60)
    
    honeypot = ComprehensiveHoneypot()
    
    # Test all attack types
    attack_types = [
        'sqli', 'xss', 'rce', 'lfi', 'ssrf', 'xxe', 'ssti',
        'nosql', 'jwt', 'graphql', 'prototype_pollution',
        'deserialization', 'ldap', 'crlf', 'open_redirect'
    ]
    
    # Create mock context
    class MockContext:
        def __init__(self):
            self.client_ip = '192.168.1.100'
            self.method = 'POST'
            self.path = '/api/test'
            self.query_string = "id=1' OR '1'='1"
            self.body_str = '{"test": "payload"}'
            self.headers = {'user-agent': 'sqlmap/1.6'}
            self.request_id = 'test123'
    
    ctx = MockContext()
    
    print(f"\nTesting {len(attack_types)} attack type responses:\n")
    
    for attack in attack_types:
        response = honeypot.generate_response(ctx, attack)
        print(f"✓ {attack:25s} -> Status {response['status']}, "
              f"Body: {len(response['body'])} bytes")
    
    # Show statistics
    stats = honeypot.get_statistics()
    print(f"\n{'=' * 60}")
    print("STATISTICS:")
    print(f"  Canaries created: {stats['total_canaries']}")
    print(f"  Payloads captured: {stats['captured_payloads']}")
    print(f"  Attack distribution: {stats['attack_type_distribution']}")
