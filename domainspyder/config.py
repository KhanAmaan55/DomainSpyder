"""
DomainSpyder configuration and constants.

Centralizes all configuration values, constants, and mappings
used throughout the application.
"""

VERSION = "0.5.0"
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

# ---------------------------------------------------------------------------
# Port Scanning
# ---------------------------------------------------------------------------

DEFAULT_PORTS = [
    21, 22, 25, 53, 80, 110, 139, 143,
    443, 445, 3306, 3389, 8080, 8443
]

PORT_SCAN_TIMEOUT = 1.0
PORT_SCAN_THREADS = 50

# ---------------------------------------------------------------------------
# Port Presets (Top ports like Nmap)
# ---------------------------------------------------------------------------

TOP_PORTS_100 = [
    80, 443, 22, 21, 25, 53, 110, 143, 445, 3306,
    3389, 8080, 8443, 139, 5900, 1723, 111, 995,
    993, 587
]

TOP_PORTS_1000 = list(range(1, 1001))
FULL_PORT_RANGE = list(range(1, 65536))