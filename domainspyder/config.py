"""
DomainSpyder configuration and constants.

Centralizes all configuration values, constants, and mappings
used throughout the application.
"""

VERSION = "0.0.2"
APP_NAME = "DOMAIN SPYDER"
DESCRIPTION = "Domain Intelligence Framework"
AUTHOR = "Amaan Khan"

# ---------------------------------------------------------------------------
# DNS Configuration
# ---------------------------------------------------------------------------

DNS_SERVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

RESOLVER_POOL_SIZE = 10

# ---------------------------------------------------------------------------
# Brute-Force Profiles
# ---------------------------------------------------------------------------

BRUTE_CONFIG = {
    "fast":      {"delay": 0.001, "threads": 80},
    "balanced":  {"delay": 0.005, "threads": 50},
    "stealth":   {"delay": 0.01,  "threads": 20},
}

DEFAULT_BRUTE_MODE = "balanced"
DEFAULT_THREADS = 50

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

HEADERS = {"User-Agent": "DomainSpyder/2.0"}
REQUEST_TIMEOUT = 10
ALIVE_TIMEOUT = 3
ALIVE_DELAY = 0.005

# ---------------------------------------------------------------------------
# Email Provider Mapping
# ---------------------------------------------------------------------------

PROVIDER_MAP = {
    "google":    "Google Workspace",
    "zoho":      "Zoho Mail",
    "microsoft": "Microsoft 365",
    "amazon":    "Amazon SES",
}

# ---------------------------------------------------------------------------
# Default Wordlist
# ---------------------------------------------------------------------------

DEFAULT_WORDLIST = "wordlists/default.txt"
