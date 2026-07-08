"""Tests for TechScanner."""

from unittest.mock import Mock, patch

import httpx
import pytest

from domainspyder.scanners.tech_scanner import TechScanner


class TestTechScanner:
    def test_normalize_targets(self):
        assert TechScanner._normalize_targets("example.com") == [
            "https://example.com",
            "http://example.com",
        ]
        assert TechScanner._normalize_targets("https://example.com") == [
            "https://example.com",
        ]
        assert TechScanner._normalize_targets("http://example.com") == [
            "http://example.com",
        ]

    def test_empty_result(self):
        result = TechScanner._empty_result("example.com", "https://example.com")
        assert result["target"] == "example.com"
        assert result["url"] == "https://example.com"
        assert result["categories"] == []
        assert result["other"] == []
        assert "error" not in result

    def test_empty_result_with_error(self):
        result = TechScanner._empty_result(
            "example.com", "https://example.com", error="Something failed",
        )
        assert result["error"] == "Something failed"

    def test_fetch_response_ssl_error_fallback(self, mock_httpx_client):
        tech = TechScanner()

        # SSL error on first attempt, then success without verification
        mock_httpx_client.get.side_effect = [
            httpx.RemoteProtocolError("SSL error"),
            Mock(status_code=200, headers={}, cookies={}, text="<html>", url="https://example.com"),
        ]

        response = tech._fetch_response("example.com", ["https://example.com"])
        assert response is not None
        assert response.status_code == 200

    def test_fetch_response_all_fail(self, mock_httpx_client):
        tech = TechScanner()

        mock_httpx_client.get.side_effect = httpx.RequestError("All failed")

        response = tech._fetch_response("example.com", ["https://example.com"])
        assert response is None

    def test_fetch_response_success(self, mock_httpx_client):
        tech = TechScanner()

        mock_response = Mock(
            status_code=200,
            headers={},
            cookies={},
            text="<html><body>Hello</body></html>",
            url="https://example.com",
        )
        mock_httpx_client.get.return_value = mock_response

        with patch.object(tech, "_check_cancelled", return_value=False):
            response = tech._fetch_response("example.com", ["https://example.com"])
        assert response is not None
        assert response.status_code == 200

    def test_scan_network_error_returns_error_result(self, mock_httpx_client):
        tech = TechScanner()
        mock_httpx_client.get.side_effect = httpx.RequestError("All failed")

        result = tech.scan("example.com")
        assert result["error"] == "All fetch attempts failed"

    def test_scan_cancelled_during_fetch(self, mock_httpx_client):
        tech = TechScanner()
        mock_httpx_client.get.side_effect = KeyboardInterrupt()

        result = tech.scan("example.com")
        assert "error" in result

    def test_boost_or_add_cms_new(self):
        categories = []
        TechScanner._boost_or_add_cms(categories, "WordPress")
        assert len(categories) == 1
        assert categories[0]["name"] == "WordPress"
        assert categories[0]["score"] == 8
        assert categories[0]["category"] == "CMS"

    def test_boost_or_add_cms_existing(self):
        categories = [{"name": "WordPress", "score": 5, "confidence": "Medium", "meter": "█████░░░░░", "category": "CMS"}]
        TechScanner._boost_or_add_cms(categories, "WordPress")
        assert categories[0]["score"] == 7  # 5 + 2
        assert categories[0]["confidence"] == "Medium"
