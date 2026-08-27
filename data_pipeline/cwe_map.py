"""
CWE -> attack-category mapping.

CVE/KEV records carry CWE identifiers (Common Weakness Enumeration), not attack
labels. This table maps the CWEs relevant to web-application attacks onto the
canonical categories the WAF model classifies. Used to turn CISA KEV / NVD feeds
into per-category threat signals.

Only web-app-injection-relevant CWEs are mapped; everything else -> None (ignored
for a payload classifier, honestly, because e.g. a use-after-free CVE has no HTTP
payload to learn from).
"""
CWE_TO_CATEGORY = {
    "CWE-89": "sqli",                 # SQL Injection
    "CWE-564": "sqli",                # Hibernate/ORM injection
    "CWE-79": "xss",                  # Cross-site Scripting
    "CWE-80": "xss", "CWE-83": "xss",
    "CWE-78": "rce",                  # OS Command Injection
    "CWE-77": "rce",                  # Command Injection
    "CWE-94": "rce", "CWE-95": "rce", # Code Injection / eval
    "CWE-98": "rce",                  # PHP file inclusion
    "CWE-22": "path_traversal",       # Path Traversal
    "CWE-23": "path_traversal", "CWE-36": "path_traversal",
    "CWE-918": "ssrf",                # SSRF
    "CWE-611": "xxe",                 # XML External Entity
    "CWE-776": "xxe",                 # XML entity expansion
    "CWE-1336": "ssti",               # Server-Side Template Injection
    "CWE-917": "ssti",                # Expression Language injection
    "CWE-943": "nosql",               # NoSQL / data-query injection
    "CWE-90": "ldap",                 # LDAP Injection
    "CWE-502": "deserialization",     # Insecure Deserialization
    "CWE-1321": "prototype_pollution",# Prototype Pollution
    "CWE-93": "crlf",                 # CRLF Injection
    "CWE-113": "crlf",                # HTTP response splitting
    "CWE-601": "open_redirect",       # Open Redirect
    "CWE-74": "generic_injection",    # Injection (parent)
    "CWE-20": "generic_injection",    # Improper input validation
    "CWE-116": "generic_injection",
}


def map_cwes(cwes):
    """List of CWE ids -> set of attack categories (may be empty)."""
    out = set()
    for c in cwes or []:
        c = str(c).upper().strip()
        if c in CWE_TO_CATEGORY:
            out.add(CWE_TO_CATEGORY[c])
    return out
