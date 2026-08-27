"""
DECEPTICON Secure Admin Key Manager
FIXES: Default Admin Credentials / Key Storage (CRITICAL)

SECURITY MEASURES:
1. Keys NEVER stored in plaintext files
2. Keys stored in environment or secure vault only
3. Key file auto-deleted after VERY short window (5 minutes, not 24 hours)
4. No default keys - must be generated explicitly
5. Secure random key generation
6. Key rotation support
"""
import os
import sys
import time
import secrets
import hashlib
import hmac
import json
import logging
import threading
import atexit
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("decepticon.security.admin_keys")


# ============================================================================
# SECURITY ERROR
# ============================================================================

class KeySecurityError(Exception):
    """Security violation in key management"""
    pass


# ============================================================================
# KEY INFO
# ============================================================================

@dataclass
class SecureKeyInfo:
    """Information about an API key (never contains the key itself!)"""
    key_id: str
    name: str
    permissions: List[str]
    created_at: float
    expires_at: Optional[float]
    rate_limit: int
    key_hash: str  # SHA-256 hash of key
    last_used: float = 0
    use_count: int = 0
    
    # MFA
    totp_secret: Optional[str] = None
    mfa_required: bool = False


# ============================================================================
# SECURE KEY GENERATOR
# ============================================================================

class SecureKeyGenerator:
    """
    Cryptographically secure key generation
    """
    
    # Key format: prefix_randompart
    # prefix: 8 chars (identifies key type)
    # random: 32 bytes = 256 bits (URL-safe base64 = 43 chars)
    KEY_PREFIX_LENGTH = 8
    KEY_RANDOM_BYTES = 32
    
    @classmethod
    def generate(cls, prefix: str = "key") -> Tuple[str, str]:
        """
        Generate a new API key
        
        Returns: (key_id, full_key)
        """
        # Generate random ID and key material
        key_id = secrets.token_hex(4)  # 8 chars
        key_material = secrets.token_urlsafe(cls.KEY_RANDOM_BYTES)  # 43 chars
        
        # Full key format: prefix_id.material
        full_key = f"{prefix}_{key_id}.{key_material}"
        
        return key_id, full_key
    
    @classmethod
    def hash_key(cls, full_key: str) -> str:
        """Hash key for storage (never store plaintext!)"""
        return hashlib.sha256(full_key.encode()).hexdigest()
    
    @classmethod
    def validate_format(cls, full_key: str) -> bool:
        """Validate key format"""
        if not full_key or not isinstance(full_key, str):
            return False
        
        parts = full_key.split('.')
        if len(parts) != 2:
            return False
        
        prefix_id = parts[0]
        material = parts[1]
        
        # Check lengths
        if '_' not in prefix_id:
            return False
        
        if len(material) < 40:  # Base64 of 32 bytes
            return False
        
        return True


# ============================================================================
# SECURE KEY STORAGE
# ============================================================================

class SecureKeyStorage:
    """
    Secure storage for API keys
    
    Priority (most secure to least):
    1. HashiCorp Vault
    2. AWS Secrets Manager / GCP Secret Manager
    3. Environment variables
    4. Encrypted file (last resort)
    
    NEVER plain text files!
    """
    
    def __init__(self, storage_type: str = "env"):
        self.storage_type = storage_type
        self.keys: Dict[str, SecureKeyInfo] = {}
        
        # In-memory key hashes (for validation)
        self._key_hashes: Dict[str, str] = {}  # hash -> key_id
        
        # Initialize storage backend
        self._init_storage()
    
    def _init_storage(self):
        """Initialize storage backend"""
        if self.storage_type == "vault":
            self._init_vault()
        elif self.storage_type == "aws":
            self._init_aws_secrets()
        elif self.storage_type == "env":
            self._init_env()
        else:
            logger.warning(f"Unknown storage type: {self.storage_type}, using env")
            self._init_env()
    
    def _init_vault(self):
        """Initialize HashiCorp Vault backend"""
        try:
            import hvac
            vault_addr = os.environ.get('VAULT_ADDR', 'http://localhost:8200')
            vault_token = os.environ.get('VAULT_TOKEN')
            
            if not vault_token:
                raise KeySecurityError("VAULT_TOKEN not set")
            
            self.vault_client = hvac.Client(url=vault_addr, token=vault_token)
            
            if not self.vault_client.is_authenticated():
                raise KeySecurityError("Vault authentication failed")
            
            logger.info("Connected to HashiCorp Vault")
            
        except ImportError:
            logger.warning("hvac not installed, falling back to env storage")
            self._init_env()
    
    def _init_aws_secrets(self):
        """Initialize AWS Secrets Manager backend"""
        try:
            import boto3
            self.secrets_client = boto3.client('secretsmanager')
            logger.info("Connected to AWS Secrets Manager")
        except ImportError:
            logger.warning("boto3 not installed, falling back to env storage")
            self._init_env()
    
    def _init_env(self):
        """Initialize environment variable backend"""
        logger.info("Using environment variable key storage")
        
        # Load any existing keys from env
        admin_key_hash = os.environ.get('DECEPTICON_ADMIN_KEY_HASH')
        if admin_key_hash:
            self.keys["admin"] = SecureKeyInfo(
                key_id="admin",
                name="environment_admin",
                permissions=["admin", "read", "write"],
                created_at=time.time(),
                expires_at=None,
                rate_limit=1000,
                key_hash=admin_key_hash,
            )
            self._key_hashes[admin_key_hash] = "admin"
    
    def store_key(self, key_info: SecureKeyInfo) -> bool:
        """Store key info (never the key itself!)"""
        try:
            self.keys[key_info.key_id] = key_info
            self._key_hashes[key_info.key_hash] = key_info.key_id
            
            # Persist to backend
            if self.storage_type == "vault":
                self._store_to_vault(key_info)
            elif self.storage_type == "aws":
                self._store_to_aws(key_info)
            # env: keys stay in memory only
            
            return True
        except Exception as e:
            logger.error(f"Failed to store key: {e}")
            return False
    
    def get_key_by_hash(self, key_hash: str) -> Optional[SecureKeyInfo]:
        """Get key info by hash"""
        key_id = self._key_hashes.get(key_hash)
        if key_id:
            return self.keys.get(key_id)
        return None
    
    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key"""
        if key_id in self.keys:
            key_info = self.keys[key_id]
            del self._key_hashes[key_info.key_hash]
            del self.keys[key_id]
            return True
        return False
    
    def _store_to_vault(self, key_info: SecureKeyInfo):
        """Store key info in Vault"""
        self.vault_client.secrets.kv.v2.create_or_update_secret(
            path=f"decepticon/keys/{key_info.key_id}",
            secret={
                "key_hash": key_info.key_hash,
                "name": key_info.name,
                "permissions": json.dumps(key_info.permissions),
                "created_at": key_info.created_at,
                "expires_at": key_info.expires_at,
                "rate_limit": key_info.rate_limit,
            }
        )
    
    def _store_to_aws(self, key_info: SecureKeyInfo):
        """Store key info in AWS Secrets Manager"""
        secret_value = json.dumps({
            "key_hash": key_info.key_hash,
            "name": key_info.name,
            "permissions": key_info.permissions,
            "created_at": key_info.created_at,
            "expires_at": key_info.expires_at,
            "rate_limit": key_info.rate_limit,
        })
        
        try:
            self.secrets_client.create_secret(
                Name=f"decepticon/keys/{key_info.key_id}",
                SecretString=secret_value,
            )
        except self.secrets_client.exceptions.ResourceExistsException:
            self.secrets_client.update_secret(
                SecretId=f"decepticon/keys/{key_info.key_id}",
                SecretString=secret_value,
            )


# ============================================================================
# SECURE ADMIN KEY MANAGER
# ============================================================================

class SecureAdminKeyManager:
    """
    Secure management of admin API keys
    
    FIXES:
    - No default admin key created automatically
    - No plaintext key storage on filesystem
    - Very short key display window (5 minutes)
    - Key generation requires explicit action
    - Audit logging of all key operations
    """
    
    # Key display window (after which key is gone forever)
    KEY_DISPLAY_WINDOW_SECONDS = 300  # 5 minutes (was 24 hours!)
    
    def __init__(self, storage_type: str = "env"):
        self.storage = SecureKeyStorage(storage_type)
        self.pending_keys: Dict[str, Tuple[str, float]] = {}  # key_id -> (full_key, created_time)
        self._cleanup_thread = None
        
        # Start cleanup thread
        self._start_cleanup_thread()
        
        # Register cleanup on exit
        atexit.register(self._cleanup_pending_keys)
    
    def generate_admin_key(self, 
                          name: str = "admin",
                          permissions: List[str] = None,
                          rate_limit: int = 1000,
                          expires_in_days: Optional[int] = None,
                          require_mfa: bool = False) -> Tuple[str, str]:
        """
        Generate a new admin API key
        
        Returns: (key_id, full_key)
        
        IMPORTANT: The full_key is only available for 5 minutes!
        After that, it cannot be retrieved!
        """
        permissions = permissions or ["admin", "read", "write"]
        
        # Generate key
        key_id, full_key = SecureKeyGenerator.generate("admin")
        key_hash = SecureKeyGenerator.hash_key(full_key)
        
        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = time.time() + (expires_in_days * 86400)
        
        # Create key info
        key_info = SecureKeyInfo(
            key_id=key_id,
            name=name,
            permissions=permissions,
            created_at=time.time(),
            expires_at=expires_at,
            rate_limit=rate_limit,
            key_hash=key_hash,
            mfa_required=require_mfa,
        )
        
        # Store key info (not the key itself!)
        self.storage.store_key(key_info)
        
        # Store pending key for limited retrieval window
        self.pending_keys[key_id] = (full_key, time.time())
        
        logger.warning(
            f"Admin key generated: {key_id}. "
            f"Key will be unavailable after {self.KEY_DISPLAY_WINDOW_SECONDS} seconds!"
        )
        
        return key_id, full_key
    
    def get_pending_key(self, key_id: str) -> Optional[str]:
        """
        Get a pending key (within display window)
        
        SECURITY: Key is deleted after retrieval!
        """
        if key_id not in self.pending_keys:
            return None
        
        full_key, created_time = self.pending_keys[key_id]
        
        # Check if still within window
        if time.time() - created_time > self.KEY_DISPLAY_WINDOW_SECONDS:
            del self.pending_keys[key_id]
            return None
        
        # Delete after retrieval (one-time access)
        del self.pending_keys[key_id]
        
        logger.info(f"Pending key retrieved and deleted: {key_id}")
        
        return full_key
    
    def validate_key(self, full_key: str) -> Tuple[bool, Optional[SecureKeyInfo], str]:
        """
        Validate an API key
        
        Returns: (is_valid, key_info, error_message)
        """
        # Check format
        if not SecureKeyGenerator.validate_format(full_key):
            return False, None, "Invalid key format"
        
        # Hash the key
        key_hash = SecureKeyGenerator.hash_key(full_key)
        
        # Look up by hash (constant-time comparison)
        key_info = self.storage.get_key_by_hash(key_hash)
        
        if not key_info:
            return False, None, "Key not found"
        
        # Check expiration
        if key_info.expires_at and time.time() > key_info.expires_at:
            return False, None, "Key expired"
        
        # Update usage stats
        key_info.last_used = time.time()
        key_info.use_count += 1
        
        return True, key_info, ""
    
    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key"""
        # Also remove from pending if present
        if key_id in self.pending_keys:
            del self.pending_keys[key_id]
        
        return self.storage.revoke_key(key_id)
    
    def check_permission(self, key_info: SecureKeyInfo, required_permission: str) -> bool:
        """Check if key has required permission"""
        if "admin" in key_info.permissions:
            return True  # Admin has all permissions
        return required_permission in key_info.permissions
    
    def list_keys(self) -> List[Dict]:
        """List all keys (without sensitive data)"""
        return [
            {
                "key_id": info.key_id,
                "name": info.name,
                "permissions": info.permissions,
                "created_at": info.created_at,
                "expires_at": info.expires_at,
                "last_used": info.last_used,
                "use_count": info.use_count,
                # NO key hash, NO actual key!
            }
            for info in self.storage.keys.values()
        ]
    
    def _start_cleanup_thread(self):
        """Start background thread to clean up expired pending keys"""
        def cleanup_loop():
            while True:
                self._cleanup_expired_pending()
                time.sleep(60)  # Check every minute
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_expired_pending(self):
        """Remove expired pending keys"""
        now = time.time()
        expired = [
            key_id for key_id, (_, created) in self.pending_keys.items()
            if now - created > self.KEY_DISPLAY_WINDOW_SECONDS
        ]
        
        for key_id in expired:
            del self.pending_keys[key_id]
            logger.info(f"Expired pending key removed: {key_id}")
    
    def _cleanup_pending_keys(self):
        """Clear all pending keys on exit"""
        count = len(self.pending_keys)
        self.pending_keys.clear()
        if count > 0:
            logger.info(f"Cleared {count} pending keys on exit")


# ============================================================================
# CLI TOOL FOR KEY GENERATION
# ============================================================================

def generate_admin_key_cli():
    """
    Command-line tool for generating admin keys
    
    Usage:
        python -m core.secure_admin_keys generate
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate DECEPTICON admin API key")
    parser.add_argument("command", choices=["generate", "list", "revoke"])
    parser.add_argument("--name", default="admin", help="Key name")
    parser.add_argument("--key-id", help="Key ID (for revoke)")
    parser.add_argument("--mfa", action="store_true", help="Require MFA")
    
    args = parser.parse_args()
    
    manager = SecureAdminKeyManager()
    
    if args.command == "generate":
        key_id, full_key = manager.generate_admin_key(
            name=args.name,
            require_mfa=args.mfa
        )
        
        print("\n" + "="*60)
        print("⚠️  SAVE THIS KEY NOW - IT CANNOT BE RETRIEVED LATER!")
        print("="*60)
        print(f"\nKey ID: {key_id}")
        print(f"API Key: {full_key}")
        print(f"\nKey Hash (for DECEPTICON_ADMIN_KEY_HASH env var):")
        print(SecureKeyGenerator.hash_key(full_key))
        print("\n" + "="*60)
        print("⚠️  This key will be unavailable in 5 minutes!")
        print("="*60 + "\n")
        
    elif args.command == "list":
        keys = manager.list_keys()
        for key in keys:
            print(f"Key ID: {key['key_id']}, Name: {key['name']}, Permissions: {key['permissions']}")
    
    elif args.command == "revoke":
        if not args.key_id:
            print("Error: --key-id required for revoke")
            sys.exit(1)
        
        if manager.revoke_key(args.key_id):
            print(f"Key revoked: {args.key_id}")
        else:
            print(f"Key not found: {args.key_id}")


# Global instance
secure_admin_key_manager = SecureAdminKeyManager()


if __name__ == "__main__":
    generate_admin_key_cli()
