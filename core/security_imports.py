"""
MIRAGE Security Import Blocker
===================================
This module MUST be imported FIRST in any entry point.
It blocks direct imports of vulnerable modules and forces use of secure alternatives.

Usage:
    # At the very top of api/app.py, core/waf_engine.py, main.py:
    import core.security_imports  # Must be first import!

This ensures:
1. Vulnerable pickle-based ML inference cannot be imported
2. Vulnerable MD5-based session manager cannot be imported  
3. Non-atomic rate limiter cannot be imported
4. Plaintext admin key files cannot be created
"""
import sys
import os
import warnings

# ============================================================================
# SECURITY: Block vulnerable module imports
# ============================================================================

class VulnerableModuleError(ImportError):
    """Raised when attempting to import a vulnerable module directly"""
    pass


class SecureImportBlocker:
    """
    Import hook that blocks vulnerable modules
    """
    
    # Modules that should NEVER be imported directly
    BLOCKED_MODULES = {
        'ml.inference': 'ml.secure_inference',
        'core.session_manager': 'core.secure_session',
        'core.rate_limiter': 'core.atomic_rate_limiter',
    }
    
    def __init__(self):
        self.warnings_issued = set()
        # SECURITY: Always block in production, warn in dev
        self.strict_mode = os.environ.get('ENV') == 'production'
    
    def find_module(self, fullname, path=None):
        """Check if module is blocked"""
        if fullname in self.BLOCKED_MODULES:
            # Return self to handle the import
            return self
        return None
    
    def load_module(self, fullname):
        """Block loading of vulnerable module"""
        secure_alt = self.BLOCKED_MODULES.get(fullname)
        
        # ALWAYS raise error now - no fallback to vulnerable code!
        # The secure modules exist and work, there's no reason to use vulnerable ones
        raise VulnerableModuleError(
            f"\n{'='*60}\n"
            f"⛔ SECURITY ERROR: Attempted to import vulnerable module!\n"
            f"   Blocked: {fullname}\n"
            f"   Use instead: {secure_alt}\n"
            f"\n"
            f"   The vulnerable module contains known security flaws:\n"
            f"   - ml.inference: Pickle RCE (CVSS 10.0)\n"
            f"   - core.session_manager: Predictable session IDs (CVSS 9.1)\n"
            f"   - core.rate_limiter: Race conditions (CVSS 7.4)\n"
            f"\n"
            f"   Fix: Update your imports to use the secure version.\n"
            f"{'='*60}\n"
        )


# ============================================================================
# SECURITY: Verify environment on import
# ============================================================================

def _verify_security_config():
    """Verify security-critical environment variables"""
    warnings_list = []
    
    # Check for admin key file (should not exist!)
    dangerous_paths = [
        './data/security/ADMIN_KEY.txt',
        './ADMIN_KEY.txt',
        '/app/data/security/ADMIN_KEY.txt',
        './data/audit/.audit_key',
    ]
    
    for path in dangerous_paths:
        if os.path.exists(path):
            warnings_list.append(f"⚠️  SECURITY: Dangerous file exists: {path} - DELETE IT!")
    
    # Check for required environment variables in production
    if os.environ.get('ENV') == 'production':
        required_vars = [
            'REDIS_PASSWORD',
            'MODEL_SIGNING_KEY',
            'MIRAGE_ADMIN_KEY_HASH',
        ]
        
        for var in required_vars:
            if not os.environ.get(var):
                warnings_list.append(f"⚠️  SECURITY: Required variable not set: {var}")
    
    # Print all warnings
    if warnings_list:
        print("\n" + "="*60)
        print("SECURITY CONFIGURATION WARNINGS")
        print("="*60)
        for warning in warnings_list:
            print(warning)
        print("="*60 + "\n")
    
    return len(warnings_list) == 0


# ============================================================================
# SECURITY: Delete dangerous files on startup
# ============================================================================

def _cleanup_dangerous_files():
    """Remove dangerous plaintext credential files"""
    dangerous_files = [
        './data/security/ADMIN_KEY.txt',
        './ADMIN_KEY.txt',
        './data/audit/.audit_key',
    ]
    
    for filepath in dangerous_files:
        if os.path.exists(filepath):
            try:
                # Read content first for warning
                with open(filepath, 'r') as f:
                    content_preview = f.read(50)
                
                # Delete the file
                os.remove(filepath)
                
                print(f"⚠️  SECURITY: Deleted dangerous file: {filepath}")
                print(f"   Content started with: {content_preview[:20]}...")
                print(f"   This file should NEVER exist in production!")
                
            except Exception as e:
                print(f"⚠️  Could not delete {filepath}: {e}")


# ============================================================================
# Install import blocker
# ============================================================================

_import_blocker = SecureImportBlocker()

# Install at the front of meta_path
if _import_blocker not in sys.meta_path:
    sys.meta_path.insert(0, _import_blocker)

# Verify configuration on import
_config_ok = _verify_security_config()

# In production, clean up dangerous files
if os.environ.get('ENV') == 'production':
    _cleanup_dangerous_files()

# ============================================================================
# Exported functions
# ============================================================================

def get_security_status() -> dict:
    """Get current security module status"""
    status = {
        "import_blocker_active": _import_blocker in sys.meta_path,
        "blocked_modules": list(SecureImportBlocker.BLOCKED_MODULES.keys()),
        "config_verified": _config_ok,
        "environment": os.environ.get('ENV', 'development'),
    }
    
    # Check which secure modules are available
    secure_modules = {
        "secure_session": False,
        "secure_inference": False,
        "atomic_rate_limiter": False,
        "secure_admin_keys": False,
        "safe_patterns": False,
    }
    
    for module in secure_modules:
        try:
            __import__(f"core.{module}" if module != "secure_inference" else f"ml.{module}")
            secure_modules[module] = True
        except ImportError:
            pass
    
    status["secure_modules"] = secure_modules
    
    return status


def enforce_production_security():
    """
    Call this in production to enforce all security requirements.
    Will raise errors if security is not properly configured.
    """
    if os.environ.get('ENV') != 'production':
        return
    
    errors = []
    
    # Check required environment variables
    required = [
        ('REDIS_PASSWORD', 'Redis authentication'),
        ('MODEL_SIGNING_KEY', 'ML model integrity'),
        ('MIRAGE_ADMIN_KEY_HASH', 'Admin authentication'),
    ]
    
    for var, purpose in required:
        if not os.environ.get(var):
            errors.append(f"Missing {var} ({purpose})")
    
    # Check for dangerous files
    if os.path.exists('./data/security/ADMIN_KEY.txt'):
        errors.append("ADMIN_KEY.txt exists - delete it!")
    
    if os.path.exists('./data/audit/.audit_key'):
        errors.append(".audit_key file exists - use AUDIT_SIGNING_KEY env var!")
    
    if errors:
        raise SecurityError(
            f"\n{'='*60}\n"
            f"⛔ PRODUCTION SECURITY REQUIREMENTS NOT MET:\n"
            + "\n".join(f"  - {e}" for e in errors)
            + f"\n{'='*60}\n"
        )


class SecurityError(Exception):
    """Security configuration error"""
    pass


# Print status on import
print(f"[SECURITY] Security imports initialized (ENV={os.environ.get('ENV', 'development')})")
