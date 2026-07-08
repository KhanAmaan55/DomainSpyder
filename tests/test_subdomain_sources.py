"""Tests for passive subdomain enumeration sources."""

import json
from unittest.mock import Mock, patch

import pytest

from domainspyder.sources.subdomains.bruteforce import BruteForceSource
from domainspyder.sources.subdomains.crtsh import CrtShSource
from domainspyder.sources.subdomains.hackertarget import HackerTargetSource
from domainspyder.sources.subdomains.otx import OTXSource
from domainspyder.sources.subdomains.rapiddns import RapidDNSSource
from domainspyder.sources.subdomains.wayback import WaybackSource


class TestCrtShSource:
    def test_fetch_parses_results(self, mock_requests, mock_dns_resolver):
        mock_dns_resolver.return_value = []  # prevent any DNS calls
        mock_requests.add(
            mock_requests.GET,
            "https://crt.sh/?q=%25.example.com&output=json",
            json=[
                {"name_value": "www.example.com\nmail.example.com"},
                {"name_value": "api.example.com"},
            ],
            status=200,
        )
        source = CrtShSource()
        results = source.fetch("example.com")
        assert "www.example.com" in results
        assert "mail.example.com" in results
        assert "api.example.com" in results

    def test_non_200_returns_empty(self, mock_requests):
        mock_requests.add(
            mock_requests.GET,
            "https://crt.sh/?q=%25.example.com&output=json",
            status=500,
        )
        source = CrtShSource()
        assert source.fetch("example.com") == []

    def test_invalid_json(self, mock_requests):
        mock_requests.add(
            mock_requests.GET,
            "https://crt.sh/?q=%25.example.com&output=json",
            body="not json",
            status=200,
        )
        source = CrtShSource()
        assert source.fetch("example.com") == []

    def test_filters_wildcards(self, mock_requests):
        mock_requests.add(
            mock_requests.GET,
            "https://crt.sh/?q=%25.example.com&output=json",
            json=[{"name_value": "*.example.com\nwww.example.com"}],
            status=200,
        )
        source = CrtShSource()
        results = source.fetch("example.com")
        assert "*.example.com" not in results
        assert "www.example.com" in results


class TestHackerTargetSource:
    def test_fetch_parses_csv(self, mock_requests):
        mock_requests.add(
            mock_requests.GET,
            "https://api.hackertarget.com/hostsearch/?q=example.com",
            body="www.example.com,93.184.216.34\nmail.example.com,93.184.216.35",
            status=200,
        )
        source = HackerTargetSource()
        results = source.fetch("example.com")
        assert "www.example.com" in results
        assert "mail.example.com" in results


class TestOTXSource:
    def test_fetch_parses_json(self, mock_requests):
        mock_requests.add(
            mock_requests.GET,
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns",
            json={"passive_dns": [{"hostname": "www.example.com"}, {"hostname": "mail.example.com"}]},
            status=200,
        )
        source = OTXSource()
        results = source.fetch("example.com")
        assert "www.example.com" in results
        assert "mail.example.com" in results

    def test_empty_response(self, mock_requests):
        mock_requests.add(
            mock_requests.GET,
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns",
            json={},
            status=200,
        )
        source = OTXSource()
        assert source.fetch("example.com") == []


class TestRapidDNSSource:
    def test_fetch_parses_html(self, mock_requests):
        mock_requests.add(
            mock_requests.GET,
            "https://rapiddns.io/subdomain/example.com?full=1",
            body="<html><body>www.example.com<br>mail.example.com</body></html>",
            status=200,
        )
        source = RapidDNSSource()
        results = source.fetch("example.com")
        assert "www.example.com" in results
        assert "mail.example.com" in results


class TestWaybackSource:
    def test_fetch_parses_cdx(self, mock_requests):
        mock_requests.add(
            mock_requests.GET,
            "https://web.archive.org/cdx/search/cdx?url=*.example.com&output=json",
            json=[
                ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
                ["com,example,www)/", "20240101000000", "https://www.example.com/", "text/html", "200", "hash", "1234"],
                ["com,example,mail)/", "20240101000000", "https://mail.example.com/", "text/html", "200", "hash", "5678"],
            ],
            status=200,
        )
        source = WaybackSource()
        results = source.fetch("example.com")
        assert "www.example.com" in results
        assert "mail.example.com" in results


class TestBruteForceSource:
    def test_fetch_resolves_subdomains(self, mock_dns_resolver, mock_wordlist):
        import dns.resolver

        def resolve_side(subdomain, record_type):
            if subdomain == "www.example.com":
                return [MagicMock()]
            raise dns.resolver.NXDOMAIN

        mock_dns_resolver.side_effect = resolve_side

        source = BruteForceSource(wordlist_path=mock_wordlist, threads=2, delay=0)
        results = source.fetch("example.com")
        assert "www.example.com" in results

    def test_fetch_handles_exceptions(self, mock_wordlist):
        source = BruteForceSource(wordlist_path=mock_wordlist, threads=2, delay=0)
        # Should not raise even with resolver failures
        with patch("dns.resolver.Resolver") as mock_resolver_cls:
            mock_resolver = Mock()
            mock_resolver_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = Exception("DNS error")
            results = source.fetch("example.com")
        assert results == []

    def test_safe_fetch_returns_empty_on_error(self, mock_wordlist):
        source = BruteForceSource(wordlist_path="/nonexistent/wordlist.txt", threads=2, delay=0)
        result = source.safe_fetch("example.com")
        assert result == []



