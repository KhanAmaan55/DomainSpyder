"""Tests for SubdomainScanner."""

from unittest.mock import MagicMock, Mock, patch

import pytest

from domainspyder.scanners.subdomain_scanner import SubdomainScanner
from domainspyder.sources.subdomains.bruteforce import BruteForceSource


class TestSubdomainScanner:
    def test_scan_returns_structured_result(self):
        scanner = SubdomainScanner()
        with (
            patch.object(scanner, "_run_combined", return_value=([], ["www.example.com", "mail.example.com"])),
        ):
            result = scanner.scan("example.com", wordlist="dummy.txt", threads=5)
        assert result["command"] == "subdomains"
        assert result["target"] == "example.com"
        assert len(result["subdomains"]) == 2
        assert "timestamp" in result

    def test_scan_deduplicates(self):
        scanner = SubdomainScanner()
        with (
            patch.object(scanner, "_run_combined", return_value=(["www.example.com"], ["www.example.com", "mail.example.com"])),
        ):
            result = scanner.scan("example.com", wordlist="dummy.txt", threads=5)
        assert result["count"] == 2
        assert result["subdomains"] == ["mail.example.com", "www.example.com"]

    def test_scan_filters_invalid(self):
        scanner = SubdomainScanner()
        with (
            patch.object(scanner, "_run_combined", return_value=(["*.example.com", "@.example.com", "www.example.com"], [])),
        ):
            result = scanner.scan("example.com", wordlist="dummy.txt", threads=5)
        assert "*.example.com" not in result["subdomains"]
        assert "www.example.com" in result["subdomains"]

    def test_scan_brute_only(self):
        scanner = SubdomainScanner()
        with (
            patch.object(scanner, "_run_bruteforce", return_value=["www.example.com", "mail.example.com"]),
        ):
            result = scanner.scan(
                "example.com", wordlist="dummy.txt", threads=5, brute_only=True,
            )
        assert result["count"] == 2

    def test_scan_alive_probing(self):
        scanner = SubdomainScanner()
        with (
            patch.object(scanner, "_run_combined", return_value=([], ["www.example.com"])),
            patch.object(scanner, "_check_alive", return_value=[{"subdomain": "www.example.com", "status": 200, "server": "nginx", "title": "Test"}]),
        ):
            result = scanner.scan("example.com", wordlist="dummy.txt", threads=5, alive=True)
        assert len(result["alive"]) == 1
        assert result["alive"][0]["subdomain"] == "www.example.com"

    def test_run_bruteforce_uses_config(self):
        scanner = SubdomainScanner()
        with (
            patch.object(BruteForceSource, "safe_fetch", return_value=["www.example.com"]),
        ):
            result = scanner._run_bruteforce("example.com", "wordlist.txt", 50, "fast")
        assert result == ["www.example.com"]

    def test_probe_returns_none_on_failure(self):
        scanner = SubdomainScanner()
        with patch("domainspyder.scanners.subdomain_scanner.get_session") as mock_get_session:
            with patch("time.sleep"):
                mock_session = Mock()
                mock_get_session.return_value = mock_session
                mock_session.get.side_effect = Exception("Connection error")

                result = scanner._probe("www.example.com")
                assert result is None

    def test_probe_returns_info_on_success(self):
        scanner = SubdomainScanner()
        with patch("domainspyder.scanners.subdomain_scanner.get_session") as mock_get_session:
            with patch("time.sleep"):
                mock_session = Mock()
                mock_get_session.return_value = mock_session
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.text = "<html><title>Test Site</title></html>"
                mock_response.headers = {"Server": "nginx"}
                mock_session.get.return_value = mock_response

                result = scanner._probe("www.example.com")
                assert result is not None
                assert result["subdomain"] == "www.example.com"
                assert result["status"] == 200
                assert result["server"] == "nginx"
                assert result["title"] == "Test Site"
