"""Tests for network probe functions (DNS hints, favicon, robots, sitemap, WP API)."""

from unittest.mock import MagicMock, Mock, patch

import httpx
import pytest

from domainspyder.sources.tech.dns_hints_probe import probe_dns_hints
from domainspyder.sources.tech.favicon_probe import probe_favicon
from domainspyder.sources.tech.robots_probe import probe_robots_txt
from domainspyder.sources.tech.sitemap_probe import probe_sitemap
from domainspyder.sources.tech.wp_api_probe import probe_wp_api


class TestProbeDnsHints:
    def test_google_verification(self, mock_dns_resolver):
        mock_answer = MagicMock()
        mock_answer.strings = [b"google-site-verification=xxx"]
        mock_dns_resolver.return_value = [mock_answer]

        hints = probe_dns_hints("example.com")
        assert "Google Search Console verified" in hints

    def test_spf_detected(self, mock_dns_resolver):
        mock_answer = MagicMock()
        mock_answer.strings = [b"v=spf1 include:_spf.google.com ~all"]
        mock_dns_resolver.return_value = [mock_answer]

        hints = probe_dns_hints("example.com")
        assert "SPF record configured" in hints

    def test_dmarc_detected(self, mock_dns_resolver):
        mock_answer = MagicMock()
        mock_answer.strings = [b"v=DMARC1; p=reject"]
        mock_dns_resolver.return_value = [mock_answer]

        hints = probe_dns_hints("example.com")
        assert "DMARC configured" in hints

    def test_dns_failure(self, mock_dns_resolver):
        mock_dns_resolver.side_effect = Exception("DNS failure")
        hints = probe_dns_hints("example.com")
        assert hints == []

    def test_url_input(self, mock_dns_resolver):
        mock_answer = MagicMock()
        mock_answer.strings = [b"google-site-verification=xxx"]
        mock_dns_resolver.return_value = [mock_answer]

        hints = probe_dns_hints("https://example.com/page")
        assert "Google Search Console verified" in hints


class TestProbeFavicon:
    def test_known_hash(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        mock_httpx_client.get.return_value = mock_response

        results = probe_favicon("https://example.com")
        # Since the hash won't match any known, should return []
        assert results == []

    def test_http_error(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.RequestError("Connection error")
        results = probe_favicon("https://example.com")
        assert results == []

    def test_non_200(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_httpx_client.get.return_value = mock_response

        results = probe_favicon("https://example.com")
        assert results == []

    def test_small_response(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"too small"
        mock_httpx_client.get.return_value = mock_response

        results = probe_favicon("https://example.com")
        assert results == []


class TestProbeRobotsTxt:
    def test_robots_found(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Disallow: /wp-admin/\nDisallow: /administrator/"
        mock_httpx_client.get.return_value = mock_response

        result = probe_robots_txt("https://example.com")
        assert len(result["cms_hints"]) >= 1
        cms_names = [h["name"] for h in result["cms_hints"]]
        assert "WordPress" in cms_names
        assert "Joomla" in cms_names

    def test_no_robots(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.RequestError("404")
        result = probe_robots_txt("https://example.com")
        assert result == {"cms_hints": [], "other_hints": []}

    def test_non_200(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = ""
        mock_httpx_client.get.return_value = mock_response

        result = probe_robots_txt("https://example.com")
        assert result == {"cms_hints": [], "other_hints": []}

    def test_admin_panel_detected(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Disallow: /admin/"
        mock_httpx_client.get.return_value = mock_response

        result = probe_robots_txt("https://example.com")
        assert "Admin Panel" in result["other_hints"]


class TestProbeSitemap:
    def test_wordpress_sitemap(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = (
            '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<url><loc>https://example.com/wp-content/page</loc></url></urlset>"
        )
        mock_httpx_client.get.return_value = mock_response

        results = probe_sitemap("https://example.com")
        names = [r["name"] for r in results]
        assert "WordPress" in names

    def test_not_a_sitemap(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Not a sitemap</body></html>"
        mock_httpx_client.get.return_value = mock_response

        results = probe_sitemap("https://example.com")
        assert results == []

    def test_http_error(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.RequestError("Timeout")
        results = probe_sitemap("https://example.com")
        assert results == []

    def test_non_200(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 500
        mock_httpx_client.get.return_value = mock_response

        results = probe_sitemap("https://example.com")
        assert results == []


class TestProbeWpApi:
    def test_wordpress_detected_with_plugins(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "namespaces": ["wp/v2", "yoast/v1", "wc/v3", "jetpack/v4"],
            "name": "Test Site",
        }
        mock_httpx_client.get.return_value = mock_response

        result = probe_wp_api("https://example.com")
        assert result is not None
        assert result["confirmed"] is True
        assert "WordPress REST API" in result["plugins"]
        assert "Yoast SEO" in result["plugins"]
        assert "WooCommerce" in result["plugins"]
        assert "Jetpack" in result["plugins"]
        assert result["site_name"] == "Test Site"

    def test_non_wp_response(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"some": "data"}
        mock_httpx_client.get.return_value = mock_response

        result = probe_wp_api("https://example.com")
        assert result is None

    def test_http_error(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.RequestError("Timeout")
        result = probe_wp_api("https://example.com")
        assert result is None

    def test_non_200(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_httpx_client.get.return_value = mock_response

        result = probe_wp_api("https://example.com")
        assert result is None

    def test_invalid_json(self, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_httpx_client.get.return_value = mock_response

        result = probe_wp_api("https://example.com")
        assert result is None
