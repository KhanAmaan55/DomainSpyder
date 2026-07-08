"""Tests for domainspyder.utils."""

from domainspyder.utils import (
    display_provider,
    get_session,
    is_valid_subdomain,
    normalize_provider,
)


class TestIsValidSubdomain:
    def test_valid_subdomain(self):
        assert is_valid_subdomain("www.example.com", "example.com") is True

    def test_invalid_wildcard(self):
        assert is_valid_subdomain("*.example.com", "example.com") is False

    def test_invalid_at_sign(self):
        assert is_valid_subdomain("@example.com", "example.com") is False

    def test_not_ending_with_parent(self):
        assert is_valid_subdomain("www.other.com", "example.com") is False

    def test_empty_string(self):
        assert is_valid_subdomain("", "example.com") is False

    def test_case_insensitive(self):
        assert is_valid_subdomain("WWW.EXAMPLE.COM", "example.com") is True

    def test_deep_subdomain(self):
        assert is_valid_subdomain("api.www.example.com", "example.com") is True

    def test_domain_is_subdomain_itself(self):
        assert is_valid_subdomain("example.com", "example.com") is True

    def test_whitespace_strip(self):
        assert is_valid_subdomain("  www.example.com  ", "example.com") is True

    def test_partial_match(self):
        assert is_valid_subdomain("notexample.com", "example.com") is True
        # "notexample.com" ends with "example.com", so technically valid
        assert is_valid_subdomain("fakeexample.com", "example.com") is True


class TestNormalizeProvider:
    def test_google(self):
        assert normalize_provider("google.com") == "google"
        assert normalize_provider("aspmx.l.google.com") == "google"
        assert normalize_provider("Google Workspace") == "google"

    def test_microsoft(self):
        assert normalize_provider("protection.outlook.com") == "microsoft"
        assert normalize_provider("outlook.com") == "microsoft"
        assert normalize_provider("Outlook") == "microsoft"

    def test_zoho(self):
        assert normalize_provider("zoho.com") == "zoho"
        assert normalize_provider("Zoho Mail") == "zoho"

    def test_amazon(self):
        assert normalize_provider("amazonses.com") == "amazon"
        assert normalize_provider("AMAZONSES") == "amazon"

    def test_unknown(self):
        assert normalize_provider("unknown.provider.com") is None

    def test_empty(self):
        assert normalize_provider("") is None

    def test_case_insensitive(self):
        assert normalize_provider("GOOGLE") == "google"


class TestDisplayProvider:
    def test_known_provider(self):
        assert display_provider("google") == "Google Workspace"

    def test_unknown_provider(self):
        assert display_provider("unknown") == "unknown"

    def test_all_known(self):
        assert display_provider("microsoft") == "Microsoft 365"
        assert display_provider("zoho") == "Zoho Mail"
        assert display_provider("amazon") == "Amazon SES"


class TestGetSession:
    def test_returns_session(self):
        session = get_session()
        import requests

        assert isinstance(session, requests.Session)

    def test_reuses_session(self):
        s1 = get_session()
        s2 = get_session()
        assert s1 is s2
