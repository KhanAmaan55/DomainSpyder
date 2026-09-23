"""Tests for domainspyder.utils."""

import pytest

from domainspyder.utils import (
    display_provider,
    get_session,
    is_valid_subdomain,
    normalize_domain,
    normalize_host,
    normalize_provider,
    normalize_url_target,
    parse_ports,
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
        # Suffix matches must respect the dot boundary.
        assert is_valid_subdomain("notexample.com", "example.com") is False
        assert is_valid_subdomain("fakeexample.com", "example.com") is False


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


class TestNormalizeDomain:
    @pytest.mark.parametrize(
        "value",
        [
            "example.com",
            "Example.COM",
            "example.com.",
            "  example.com  ",
            "example.com:8443",
            "https://example.com",
            "http://example.com/some/path?q=1",
        ],
    )
    def test_reduces_to_bare_domain(self, value):
        assert normalize_domain(value) == "example.com"

    def test_keeps_subdomains(self):
        assert normalize_domain("https://api.dev.example.co.uk/") == "api.dev.example.co.uk"

    def test_converts_idn_to_punycode(self):
        assert normalize_domain("bücher.de") == "xn--bcher-kva.de"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "not a domain!!",
            "localhost",
            "example..com",
            "-bad.example.com",
            "bad-.example.com",
            "ftp://example.com",
            "https://",
            "a" * 64 + ".com",
            ".".join(["abcdefghi"] * 26) + ".com",
        ],
    )
    def test_rejects_invalid(self, value):
        with pytest.raises(ValueError):
            normalize_domain(value)

    def test_rejects_ip_address(self):
        with pytest.raises(ValueError, match="IP address"):
            normalize_domain("93.184.216.34")


class TestNormalizeHost:
    def test_accepts_domain(self):
        assert normalize_host("https://Example.com:8080/x") == "example.com"

    def test_accepts_ipv4(self):
        assert normalize_host("93.184.216.34") == "93.184.216.34"

    def test_accepts_single_label(self):
        assert normalize_host("localhost") == "localhost"

    def test_rejects_ipv6(self):
        with pytest.raises(ValueError, match="IPv6"):
            normalize_host("[2606:2800:220:1::1]")

    def test_rejects_garbage(self):
        with pytest.raises(ValueError):
            normalize_host("not a host")


class TestNormalizeUrlTarget:
    def test_bare_host_is_normalised(self):
        assert normalize_url_target("Example.com") == "example.com"

    def test_url_is_preserved(self):
        assert normalize_url_target("https://example.com/blog") == "https://example.com/blog"

    def test_invalid_url_host_rejected(self):
        with pytest.raises(ValueError):
            normalize_url_target("https://exa mple.com/")


class TestParsePorts:
    def test_parses_list(self):
        assert parse_ports("22, 80,443") == [22, 80, 443]

    @pytest.mark.parametrize("spec", ["abc", "80,,443", "0", "65536", "99999,-1", "80-90", ""])
    def test_rejects_invalid(self, spec):
        with pytest.raises(ValueError, match="invalid port"):
            parse_ports(spec)
