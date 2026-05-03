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

# ---------------------------------------------------------------------------
# WHOIS / Domain Info
# ---------------------------------------------------------------------------

WHOIS_TIMEOUT = 10
RDAP_BASE_URL = "https://rdap.org/domain/"

DOMAIN_AGE_THRESHOLDS = {
    "new":         1,    # < 1 year
    "established": 5,    # 1–5 years
    "mature":      10,   # 5–10 years
    "veteran":     10,   # 10+ years
}

EXPIRY_WARNING_DAYS = 90
SSL_EXPIRY_WARNING_DAYS = 30

WHOIS_PRIVACY_INDICATORS = [
    "redacted for privacy",
    "data protected",
    "whoisguard",
    "domains by proxy",
    "privacy protect",
    "contact privacy",
    "withheld for privacy",
    "statutory masking",
]

EPP_STATUS_MAP = {
    "clientDeleteProhibited": "Domain cannot be deleted by registrar",
    "clientTransferProhibited": "Domain cannot be transferred",
    "clientUpdateProhibited": "Domain cannot be modified",
    "serverDeleteProhibited": "Registry prevents deletion",
    "serverTransferProhibited": "Registry prevents transfer",
    "serverUpdateProhibited": "Registry prevents modification",
    "clientHold": "Domain is suspended (not resolving)",
    "serverHold": "Registry has suspended the domain",
    "redemptionPeriod": "Domain is in redemption grace period",
    "pendingDelete": "Domain is pending deletion",
    "addPeriod": "Domain is within add grace period",
    "renewPeriod": "Domain is within renew grace period",
    "autoRenewPeriod": "Domain was auto-renewed",
    "ok": "Domain is active and has no pending operations",
    "active": "Domain is active and has no pending operations",
}


# ---------------------------------------------------------------------------
# Tech Detection — Favicon Hash Database
# ---------------------------------------------------------------------------
# MD5 hashes of /favicon.ico → platform identification.
# Curated list of common platforms with stable favicons.

FAVICON_HASHES: dict[str, dict[str, str]] = {
    "1109a2a8dc6ef41b9e0fbb55ba2a5ee4": {"name": "Jira", "category": "Server"},
    "71e30c09d0ba64be1fa20a9c6a8b8159": {"name": "Grafana", "category": "Server"},
    "4a2da6c5a3a3b52cf310fb28d579e5b1": {"name": "Jenkins", "category": "Server"},
    "d090e456b04ae7f2f0d4d1057d18e5c5": {"name": "GitLab", "category": "Server"},
    "b4699c1413e8a83c73c2aaeca34b57a4": {"name": "Apache Tomcat", "category": "Server"},
    "44a07a94abe596045f11a0bf19ebd9f1": {"name": "phpMyAdmin", "category": "Server"},
    "2cc9e228e5078a96f1a0bff3f2d1a959": {"name": "Plesk", "category": "Server"},
    "9fb5641e3ef2a0b0632b375c5a5e6805": {"name": "cPanel", "category": "Server"},
    "73e2d0b2cf62ac0c8e4e4e1ae038bc4a": {"name": "Confluence", "category": "Server"},
    "c2be2cf5e30ab78c4bd01a33d0a67a2e": {"name": "Bitbucket", "category": "Server"},
    "b1aefee44e29f3e7dd08bc5e4b3cd51e": {"name": "SonarQube", "category": "Server"},
    "3a7b97f06d9a855b4dae0ea5ccc3bfe1": {"name": "Kibana", "category": "Server"},
    "a57e42e4dfd5f6989ca7503e863e0c10": {"name": "Webmin", "category": "Server"},
    "5d41402abc4b2a76b9719d911017c592": {"name": "Keycloak", "category": "Server"},
    "be86e9e8bb4e8e2c2aeb14e887e7c316": {"name": "Mattermost", "category": "Server"},
    "d41d8cd98f00b204e9800998ecf8427e": {"name": "Empty Favicon", "category": ""},
}


# ---------------------------------------------------------------------------
# Tech Detection — Cookie → Technology Map
# ---------------------------------------------------------------------------

COOKIE_TECH_MAP: dict[str, str] = {
    "_ga": "Google Analytics",
    "_gid": "Google Analytics",
    "_gat": "Google Analytics",
    "_fbp": "Facebook Pixel",
    "_fbc": "Facebook Pixel",
    "_shopify": "Shopify",
    "wp_woocommerce": "WooCommerce",
    "_cf_bm": "Cloudflare Bot Management",
    "awsalb": "AWS ALB",
    "awsalbcors": "AWS ALB",
    "__stripe": "Stripe",
    "_hjid": "Hotjar",
    "_hjsession": "Hotjar",
    "intercom-": "Intercom",
    "hubspotutk": "HubSpot",
    "__hssc": "HubSpot",
    "__hstc": "HubSpot",
    "crisp-client": "Crisp",
    "_pk_id": "Matomo Analytics",
    "_pk_ses": "Matomo Analytics",
    "ajs_user_id": "Segment",
    "ajs_anonymous_id": "Segment",
    "mp_": "Mixpanel",
    "optimizelyEndUserId": "Optimizely",
    "__cfduid": "Cloudflare",
}


# ---------------------------------------------------------------------------
# Tech Detection — Sitemap CMS Patterns
# ---------------------------------------------------------------------------

SITEMAP_CMS_PATTERNS: dict[str, str] = {
    "wp-content": "WordPress",
    "wp-json": "WordPress",
    "/collections/": "Shopify",
    "/products/": "Shopify",
    "myshopify.com": "Shopify",
    "hubspot.com": "HubSpot",
    "/node/": "Drupal",
    "/taxonomy/term": "Drupal",
    "squarespace.com": "Squarespace",
    "wix.com": "Wix",
    "webflow.io": "Webflow",
    "ghost.io": "Ghost",
    "/catalog/product": "Magento",
}