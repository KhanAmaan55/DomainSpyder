"""Tests for domain info sources (WHOIS, RDAP, SSL, DNS SOA)."""

from unittest.mock import MagicMock, Mock, patch

import httpx
import pytest

from domainspyder.sources.info.dns_soa_source import DnsSoaSource
from domainspyder.sources.info.rdap_source import RdapSource
from domainspyder.sources.info.ssl_source import SslSource
from domainspyder.sources.info.whois_source import WhoisSource


class TestWhoisSource:
    def test_fetch_parses_whois(self, mock_whois, sample_whois_result):
        mock_whois.return_value = sample_whois_result

        source = WhoisSource()
        result = source.fetch("example.com")

        assert result["domain_name"] == "example.com"
        assert result["registrar"] == "Example Registrar Inc"
        assert result["creation_date"] == "2000-01-15"
        assert result["expiration_date"] == "2030-01-15"
        assert "ns1.example.com" in result["name_servers"]
        assert len(result["status"]) == 2
        assert result["registrant"]["org"] == "Example Org"
        assert result["dnssec"] == "unsigned"

    def test_fetch_empty_response(self, mock_whois):
        mock_whois.return_value = None
        source = WhoisSource()
        assert source.fetch("example.com") == {}

    def test_fetch_no_domain_name(self, mock_whois):
        result = Mock()
        result.domain_name = None
        mock_whois.return_value = result
        source = WhoisSource()
        assert source.fetch("example.com") == {}

    def test_safe_fetch_catches_exceptions(self, mock_whois):
        mock_whois.side_effect = Exception("WHOIS server error")
        source = WhoisSource()
        result = source.safe_fetch("example.com")
        assert result == {}

    def test_handles_list_dates(self, mock_whois):
        from datetime import datetime

        result = Mock()
        result.domain_name = "example.com"
        result.creation_date = [datetime(2000, 1, 15)]
        result.expiration_date = [datetime(2030, 1, 15)]
        result.updated_date = [datetime(2024, 6, 1)]
        result.name_servers = None
        result.status = None
        result.org = None
        result.name = None
        result.country = None
        result.state = None
        result.dnssec = None
        result.registrar = None
        mock_whois.return_value = result

        source = WhoisSource()
        data = source.fetch("example.com")
        assert data["creation_date"] == "2000-01-15"
        assert data["expiration_date"] == "2030-01-15"

    def test_handles_string_name_servers(self, mock_whois):
        result = Mock()
        result.domain_name = "example.com"
        result.name_servers = "ns1.example.com"
        result.creation_date = None
        result.expiration_date = None
        result.updated_date = None
        result.status = None
        result.org = None
        result.name = None
        result.country = None
        result.state = None
        result.dnssec = None
        result.registrar = None
        mock_whois.return_value = result

        source = WhoisSource()
        data = source.fetch("example.com")
        assert "ns1.example.com" in data["name_servers"]


class TestRdapSource:
    def test_fetch_parses_rdap(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ldhName": "EXAMPLE.COM",
            "status": ["client delete prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2000-01-15T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-15T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc"]]],
                },
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]],
                },
            ],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "NS2.EXAMPLE.COM"}],
            "secureDNS": {"delegationSigned": False},
        }
        mock_httpx_client.get.return_value = mock_response

        source = RdapSource()
        result = source.fetch("example.com")

        assert result["domain_name"] == "example.com"
        assert result["registrar"] == "Example Registrar Inc"
        assert result["creation_date"] == "2000-01-15"
        assert result["expiration_date"] == "2030-01-15"
        assert "ns1.example.com" in result["name_servers"]
        assert result.get("registrant", {}).get("org") == "Example Org"
        assert result["dnssec"] == "unsigned"

    def test_404_returns_empty(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_httpx_client.get.return_value = mock_response

        source = RdapSource()
        assert source.fetch("example.com") == {}

    def test_429_returns_empty(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 429
        mock_httpx_client.get.return_value = mock_response

        source = RdapSource()
        assert source.fetch("example.com") == {}

    def test_http_error_returns_empty(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.RequestError("Timeout")
        source = RdapSource()
        assert source.fetch("example.com") == {}

    def test_invalid_json_returns_empty(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_httpx_client.get.return_value = mock_response

        source = RdapSource()
        assert source.fetch("example.com") == {}


class TestSslSource:
    @patch("domainspyder.sources.info.ssl_source.socket.create_connection")
    def test_fetch_ssl_certificate(self, mock_create_connection):
        from domainspyder.sources.info.ssl_source import SslSource

        # Mock the socket and SSL context
        mock_sock = MagicMock()
        mock_ssock = MagicMock()

        mock_create_connection.return_value.__enter__.return_value = mock_sock
        mock_ssock.getpeercert.return_value = {
            "subject": (
                (("commonName", "*.example.com"),),
                (("organizationName", "Example Inc"),),
            ),
            "issuer": (
                (("countryName", "US"),),
                (("organizationName", "Example CA"),),
                (("commonName", "Example CA R1"),),
            ),
            "notBefore": "Jan 15 00:00:00 2024 GMT",
            "notAfter": "Jan 15 00:00:00 2026 GMT",
            "subjectAltName": (
                ("DNS", "*.example.com"),
                ("DNS", "example.com"),
            ),
            "serialNumber": "ABCDEF123456",
        }

        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx_instance = MagicMock()
            mock_ctx.return_value = mock_ctx_instance
            mock_ctx_instance.wrap_socket.return_value.__enter__.return_value = mock_ssock

            source = SslSource()
            result = source.fetch("example.com")

        assert result["ssl_issuer"] == "Example CA R1"
        assert result["ssl_subject"] == "*.example.com"
        assert result["ssl_valid_from"] == "2024-01-15"
        assert result["ssl_valid_until"] == "2026-01-15"
        assert "*.example.com" in result["ssl_san"]
        assert result["ssl_serial"] == "ABCDEF123456"

    @patch("domainspyder.sources.info.ssl_source.socket.create_connection")
    def test_connection_failure(self, mock_create_connection):
        mock_create_connection.side_effect = Exception("Connection refused")
        source = SslSource()
        result = source.fetch("example.com")
        assert result == {}

    def test_safe_fetch_catches_exceptions(self):
        source = SslSource()
        with patch.object(source, "fetch", side_effect=Exception("SSL error")):
            result = source.safe_fetch("example.com")
            assert result == {}


class TestDnsSoaSource:
    def test_fetch_soa_record(self, mock_dns_resolver):
        mock_rdata = MagicMock()
        mock_rdata.mname = "ns1.example.com."
        mock_rdata.rname = "admin.example.com."
        mock_rdata.serial = 2024060101
        mock_rdata.refresh = 900
        mock_rdata.retry = 900
        mock_rdata.expire = 1800
        mock_rdata.minimum = 60
        mock_dns_resolver.return_value = [mock_rdata]

        source = DnsSoaSource()
        result = source.fetch("example.com")

        assert result["soa_primary_ns"] == "ns1.example.com"
        assert result["soa_admin"] == "admin@example.com"
        assert result["soa_serial"] == 2024060101
        assert result["soa_refresh"] == 900
        assert result["soa_retry"] == 900
        assert result["soa_expire"] == 1800
        assert result["soa_min_ttl"] == 60

    def test_nxdomain_returns_empty(self, mock_dns_resolver):
        import dns.resolver

        mock_dns_resolver.side_effect = dns.resolver.NXDOMAIN
        source = DnsSoaSource()
        assert source.fetch("example.com") == {}

    def test_no_answer_returns_empty(self, mock_dns_resolver):
        import dns.resolver

        mock_dns_resolver.side_effect = dns.resolver.NoAnswer
        source = DnsSoaSource()
        assert source.fetch("example.com") == {}

    def test_no_nameservers_returns_empty(self, mock_dns_resolver):
        import dns.resolver

        mock_dns_resolver.side_effect = dns.resolver.NoNameservers
        source = DnsSoaSource()
        assert source.fetch("example.com") == {}

    def test_rname_to_email(self):
        source = DnsSoaSource()
        assert source._rname_to_email("admin.example.com") == "admin@example.com"
        assert source._rname_to_email("single") == "single"
        assert source._rname_to_email("a.b.c") == "a@b.c"
