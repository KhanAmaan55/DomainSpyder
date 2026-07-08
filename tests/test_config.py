"""Tests for domainspyder.config constants."""

from domainspyder.config import (
    APP_NAME,
    BRUTE_CONFIG,
    COOKIE_TECH_MAP,
    DEFAULT_BRUTE_MODE,
    DEFAULT_THREADS,
    DESCRIPTION,
    DNS_SERVERS,
    DOMAIN_AGE_THRESHOLDS,
    EPP_STATUS_MAP,
    EXPIRY_WARNING_DAYS,
    FAVICON_HASHES,
    HEADERS,
    PORT_SCAN_TIMEOUT,
    PROVIDER_MAP,
    RECORD_TYPES,
    REQUEST_TIMEOUT,
    SITEMAP_CMS_PATTERNS,
    SSL_EXPIRY_WARNING_DAYS,
    VERSION,
    WHOIS_PRIVACY_INDICATORS,
    WHOIS_TIMEOUT,
)


class TestVersion:
    def test_version_string(self):
        assert isinstance(VERSION, str)
        assert len(VERSION) > 0

    def test_app_name(self):
        assert isinstance(APP_NAME, str)
        assert APP_NAME == "DOMAIN SPYDER"

    def test_description(self):
        assert isinstance(DESCRIPTION, str)


class TestDNSConfig:
    def test_dns_servers(self):
        assert isinstance(DNS_SERVERS, list)
        assert len(DNS_SERVERS) > 0
        for server in DNS_SERVERS:
            assert isinstance(server, str)
            assert "." in server

    def test_record_types(self):
        assert "A" in RECORD_TYPES
        assert "MX" in RECORD_TYPES
        assert "TXT" in RECORD_TYPES
        assert "NS" in RECORD_TYPES
        assert "CNAME" in RECORD_TYPES
        assert "AAAA" in RECORD_TYPES


class TestBruteConfig:
    def test_brute_config_keys(self):
        for mode in ("fast", "balanced", "stealth"):
            assert mode in BRUTE_CONFIG
            assert "delay" in BRUTE_CONFIG[mode]
            assert "threads" in BRUTE_CONFIG[mode]

    def test_default_brute_mode(self):
        assert DEFAULT_BRUTE_MODE in BRUTE_CONFIG

    def test_default_threads(self):
        assert isinstance(DEFAULT_THREADS, int)
        assert DEFAULT_THREADS > 0


class TestHTTPConfig:
    def test_headers(self):
        assert "User-Agent" in HEADERS
        assert "DomainSpyder" in HEADERS["User-Agent"]

    def test_timeouts(self):
        assert isinstance(REQUEST_TIMEOUT, (int, float))
        assert REQUEST_TIMEOUT > 0
        assert isinstance(WHOIS_TIMEOUT, (int, float))
        assert WHOIS_TIMEOUT > 0
        assert isinstance(PORT_SCAN_TIMEOUT, (int, float))
        assert PORT_SCAN_TIMEOUT > 0


class TestProviders:
    def test_provider_map(self):
        assert isinstance(PROVIDER_MAP, dict)
        for key in ("google", "zoho", "microsoft", "amazon"):
            assert key in PROVIDER_MAP

    def test_whois_privacy_indicators(self):
        assert isinstance(WHOIS_PRIVACY_INDICATORS, list)
        assert len(WHOIS_PRIVACY_INDICATORS) > 0
        for indicator in WHOIS_PRIVACY_INDICATORS:
            assert isinstance(indicator, str)


class TestEPPStatus:
    def test_epp_status_map(self):
        assert isinstance(EPP_STATUS_MAP, dict)
        assert "ok" in EPP_STATUS_MAP
        assert "clientHold" in EPP_STATUS_MAP
        assert "redemptionPeriod" in EPP_STATUS_MAP


class TestThresholds:
    def test_domain_age_thresholds(self):
        assert "new" in DOMAIN_AGE_THRESHOLDS
        assert "established" in DOMAIN_AGE_THRESHOLDS
        assert "mature" in DOMAIN_AGE_THRESHOLDS
        assert "veteran" in DOMAIN_AGE_THRESHOLDS

    def test_expiry_warnings(self):
        assert isinstance(EXPIRY_WARNING_DAYS, int)
        assert EXPIRY_WARNING_DAYS > 0
        assert isinstance(SSL_EXPIRY_WARNING_DAYS, int)
        assert SSL_EXPIRY_WARNING_DAYS > 0


class TestFaviconHashes:
    def test_hashes_dict(self):
        assert isinstance(FAVICON_HASHES, dict)
        assert len(FAVICON_HASHES) > 0
        for hash_val, info in FAVICON_HASHES.items():
            assert isinstance(hash_val, str)
            assert "name" in info
            assert "category" in info

    def test_known_platforms(self):
        names = {info["name"] for info in FAVICON_HASHES.values()}
        assert "Jira" in names
        assert "Grafana" in names
        assert "GitLab" in names


class TestCookieTechMap:
    def test_cookie_map(self):
        assert isinstance(COOKIE_TECH_MAP, dict)
        assert len(COOKIE_TECH_MAP) > 0
        assert "_ga" in COOKIE_TECH_MAP
        assert "__cfduid" in COOKIE_TECH_MAP

    def test_values(self):
        for key, value in COOKIE_TECH_MAP.items():
            assert isinstance(key, str)
            assert isinstance(value, str)
            assert len(key) > 0
            assert len(value) > 0


class TestSitemapPatterns:
    def test_sitemap_patterns(self):
        assert isinstance(SITEMAP_CMS_PATTERNS, dict)
        assert "wp-content" in SITEMAP_CMS_PATTERNS
        assert SITEMAP_CMS_PATTERNS["wp-content"] == "WordPress"
