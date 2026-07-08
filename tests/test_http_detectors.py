"""Tests for HTTP header-based technology detectors."""

from domainspyder.sources.tech.http_detectors import (
    detect_backend,
    detect_cdn,
    detect_server,
)


class TestDetectServer:
    def test_nginx(self):
        result = detect_server({"Server": "nginx/1.24.0"})
        names = [r["name"] for r in result]
        assert "nginx" in names

    def test_apache(self):
        result = detect_server({"Server": "Apache/2.4.57"})
        names = [r["name"] for r in result]
        assert "Apache" in names

    def test_iis(self):
        result = detect_server({"Server": "Microsoft-IIS/10.0"})
        names = [r["name"] for r in result]
        assert "IIS" in names

    def test_no_match(self):
        result = detect_server({"Server": "Custom/1.0"})
        assert result == []

    def test_empty_headers(self):
        assert detect_server({}) == []


class TestDetectBackend:
    def test_php(self):
        result = detect_backend({"X-Powered-By": "PHP/8.2.0"}, {})
        names = [r["name"] for r in result]
        assert "PHP" in names

    def test_python_django(self):
        result = detect_backend({"Server": "WSGIServer/0.2"}, {"csrftoken": "abc"})
        names = [r["name"] for r in result]
        assert "Python" in names

    def test_java(self):
        result = detect_backend({"Server": "Java"}, {"JSESSIONID": "abc"})
        names = [r["name"] for r in result]
        assert "Java" in names

    def test_nodejs(self):
        result = detect_backend({"X-Powered-By": "Express"}, {"connect.sid": "abc"})
        names = [r["name"] for r in result]
        assert "Node.js" in names

    def test_ruby(self):
        result = detect_backend({"Server": "Phusion Passenger"}, {"_session_id": "abc"})
        names = [r["name"] for r in result]
        assert "Ruby" in names

    def test_aspnet(self):
        result = detect_backend(
            {"X-Powered-By": "ASP.NET", "X-AspNet-Version": "4.0"}, {}
        )
        names = [r["name"] for r in result]
        assert "ASP.NET" in names

    def test_empty_headers(self):
        assert detect_backend({}, {}) == []


class TestDetectCDN:
    def test_cloudflare(self):
        result = detect_cdn({"cf-ray": "abc123"})
        names = [r["name"] for r in result]
        assert "Cloudflare" in names

    def test_cloudfront(self):
        result = detect_cdn({"X-Amz-Cf-Id": "abc123", "Via": "CloudFront"})
        names = [r["name"] for r in result]
        assert "AWS CloudFront" in names

    def test_fastly(self):
        result = detect_cdn({"X-Fastly-Request-Id": "abc"})
        names = [r["name"] for r in result]
        assert "Fastly" in names

    def test_akamai(self):
        result = detect_cdn({"X-Check-Cacheable": "yes", "Via": "AkamaiEdge"})
        names = [r["name"] for r in result]
        assert "Akamai" in names

    def test_vercel(self):
        result = detect_cdn({"X-Vercel-Id": "abc123"})
        names = [r["name"] for r in result]
        assert "Vercel" in names

    def test_netlify(self):
        result = detect_cdn({"X-NF-Request-Id": "abc"})
        names = [r["name"] for r in result]
        assert "Netlify" in names

    def test_empty_headers(self):
        assert detect_cdn({}) == []
