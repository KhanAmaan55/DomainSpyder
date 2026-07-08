"""Tests for asset analysis, cookie detection, security analysis, and version extraction."""

from domainspyder.sources.tech.asset_analysis import (
    detect_from_meta_tags,
    detect_from_script_sources,
    detect_from_stylesheets,
    detect_other,
)
from domainspyder.sources.tech.cookie_detector import detect_from_cookies
from domainspyder.sources.tech.security_analysis import detect_security_headers
from domainspyder.sources.tech.version_extractor import extract_versions


class TestDetectFromMetaTags:
    def test_wordpress_generator(self):
        html = '<meta name="generator" content="WordPress 6.5.3">'
        raw, cms = detect_from_meta_tags(html)
        assert raw == "WordPress 6.5.3"
        assert cms == "WordPress"

    def test_drupal_generator(self):
        html = '<meta name="generator" content="Drupal 10 (https://www.drupal.org)">'
        raw, cms = detect_from_meta_tags(html)
        assert cms == "Drupal"

    def test_reversed_attribute_order(self):
        html = '<meta content="WordPress" name="generator">'
        raw, cms = detect_from_meta_tags(html)
        assert raw == "WordPress"
        assert cms == "WordPress"

    def test_no_generator(self):
        html = "<html><head></head><body></body></html>"
        raw, cms = detect_from_meta_tags(html)
        assert raw is None
        assert cms is None

    def test_unknown_generator(self):
        html = '<meta name="generator" content="SomeRandomCMS 1.0">'
        raw, cms = detect_from_meta_tags(html)
        assert raw == "SomeRandomCMS 1.0"
        assert cms is None


class TestDetectFromScriptSources:
    def test_webpack(self):
        assert "Webpack" in detect_from_script_sources(["/dist/webpack/main.js"])

    def test_jquery(self):
        assert "Lodash" in detect_from_script_sources(["/js/lodash.min.js"])

    def test_react(self):
        assert "cdnjs" in detect_from_script_sources(["https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/react.min.js"])

    def test_empty_list(self):
        assert detect_from_script_sources([]) == []

    def test_no_match(self):
        assert detect_from_script_sources(["/js/custom.js"]) == []


class TestDetectFromStylesheets:
    def test_bootstrap(self):
        assert "Bootstrap" in detect_from_stylesheets(["/css/bootstrap.min.css"])

    def test_tailwind(self):
        assert "Tailwind CSS" in detect_from_stylesheets(["/css/tailwind.css"])

    def test_font_awesome(self):
        assert "Font Awesome" in detect_from_stylesheets(["font-awesome/css/all.css"])
        assert "Font Awesome" in detect_from_stylesheets(["fontawesome/css/all.css"])

    def test_google_fonts(self):
        assert "Google Fonts" in detect_from_stylesheets(["https://fonts.googleapis.com/css2?family=Roboto"])

    def test_empty_list(self):
        assert detect_from_stylesheets([]) == []

    def test_no_duplicates(self):
        result = detect_from_stylesheets(["/css/bootstrap.css", "/css/bootstrap-grid.css"])
        assert result.count("Bootstrap") == 1


class TestDetectFromCookies:
    def test_google_analytics(self):
        result = detect_from_cookies({"_ga": "GA1.2.abc123", "_gid": "GA1.2.def456"})
        assert "Google Analytics" in result

    def test_cloudflare(self):
        result = detect_from_cookies({"__cfduid": "abc123"})
        assert "Cloudflare" in result

    def test_shopify(self):
        result = detect_from_cookies({"_shopify": "abc"})
        assert "Shopify" in result

    def test_empty(self):
        assert detect_from_cookies({}) == []

    def test_no_match(self):
        assert detect_from_cookies({"custom_cookie": "value"}) == []

    def test_no_duplicates(self):
        result = detect_from_cookies({"_ga": "x", "_gid": "y", "_gat": "z"})
        assert result.count("Google Analytics") == 1


class TestDetectSecurityHeaders:
    def test_all_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
        }
        result = detect_security_headers(headers)
        assert result["hsts"]["present"] is True
        assert result["csp"]["present"] is True
        assert result["x_frame_options"]["present"] is True
        assert result["x_content_type_options"]["present"] is True
        assert result["referrer_policy"]["present"] is True
        assert result["permissions_policy"]["present"] is True

    def test_none_present(self):
        result = detect_security_headers({})
        assert result["hsts"]["present"] is False
        assert result["csp"]["present"] is False
        assert result["x_frame_options"]["present"] is False
        assert result["x_content_type_options"]["present"] is False
        assert result["referrer_policy"]["present"] is False
        assert result["permissions_policy"]["present"] is False

    def test_partial(self):
        result = detect_security_headers({"Strict-Transport-Security": "max-age=31536000"})
        assert result["hsts"]["present"] is True
        assert result["csp"]["present"] is False

    def test_case_insensitive(self):
        result = detect_security_headers({"x-frame-options": "SAMEORIGIN"})
        assert result["x_frame_options"]["present"] is True
        assert result["x_frame_options"]["value"] == "SAMEORIGIN"


class TestDetectOther:
    def test_nextjs(self):
        body = "__next_data__"
        assert "Next.js" in detect_other({}, body)

    def test_google_analytics(self):
        body = "google-analytics.com/ga.js"
        assert "Google Analytics" in detect_other({}, body)

    def test_jquery(self):
        body = "jquery.min.js"
        assert "jQuery" in detect_other({}, body)

    def test_intercom(self):
        body = "intercom.io"
        assert "Intercom" in detect_other({}, body)

    def test_stripe(self):
        body = "js.stripe.com"
        assert "Stripe" in detect_other({}, body)

    def test_x_powered_by(self):
        headers = {"x-powered-by": "Express"}
        body = ""
        result = detect_other(headers, body)
        assert "X-Powered-By: Express" not in result  # Express is excluded

    def test_x_powered_by_custom(self):
        headers = {"x-powered-by": "CoffeeScript"}
        body = ""
        result = detect_other(headers, body)
        assert "X-Powered-By: CoffeeScript" in result

    def test_empty(self):
        assert detect_other({}, "") == []


class TestExtractVersions:
    def test_from_generator(self):
        headers = {}
        body = ""
        scripts = []
        versions = extract_versions(headers, body, scripts, "WordPress 6.5.3")
        assert versions.get("WordPress") == "6.5.3"

    def test_from_server_header(self):
        headers = {"server": "nginx/1.24.0"}
        versions = extract_versions(headers, "", [], None)
        assert versions.get("nginx") == "1.24.0"

    def test_from_x_powered_by(self):
        headers = {"x-powered-by": "PHP/8.2.0"}
        versions = extract_versions(headers, "", [], None)
        assert versions.get("PHP") == "8.2.0"

    def test_from_scripts(self):
        headers = {}
        body = ""
        scripts = ["https://code.jquery.com/jquery-3.7.1.min.js"]
        versions = extract_versions(headers, body, scripts, None)
        assert versions.get("jQuery") == "3.7.1"

    def test_from_body(self):
        headers = {}
        body = 'ng-version="15.0.0"'
        versions = extract_versions(headers, body, [], None)
        assert versions.get("Angular") == "15.0.0"

    def test_no_versions(self):
        assert extract_versions({}, "", [], None) == {}

    def test_multiple_versions(self):
        headers = {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2.0"}
        versions = extract_versions(headers, "", [], "WordPress 6.5.3")
        assert versions.get("nginx") == "1.24.0"
        assert versions.get("PHP") == "8.2.0"
        assert versions.get("WordPress") == "6.5.3"
