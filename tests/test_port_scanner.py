"""Tests for PortScanner."""

from unittest.mock import Mock, patch

import pytest

from domainspyder.scanners.port_scanner import PortScanner


class TestPortScanner:
    def test_resolve_target_success(self):
        scanner = PortScanner()
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            ip = scanner._resolve_target("example.com")
        assert ip == "93.184.216.34"

    def test_resolve_target_failure(self):
        scanner = PortScanner()
        with patch("socket.gethostbyname", side_effect=Exception("DNS failure")):
            ip = scanner._resolve_target("example.com")
        assert ip is None

    def test_reverse_dns_success(self):
        scanner = PortScanner()
        with patch("socket.gethostbyaddr", return_value=("example.com", [], ["93.184.216.34"])):
            rdns = scanner._reverse_dns("93.184.216.34")
        assert rdns == "example.com"

    def test_reverse_dns_failure(self):
        scanner = PortScanner()
        with patch("socket.gethostbyaddr", side_effect=Exception("No reverse")):
            rdns = scanner._reverse_dns("93.184.216.34")
        assert rdns == "-"

    def test_scan_port_open(self):
        scanner = PortScanner()
        with patch("socket.socket") as mock_socket:
            sock_instance = Mock()
            mock_socket.return_value.__enter__.return_value = sock_instance
            sock_instance.connect_ex.return_value = 0  # open

            result = scanner._scan_port("93.184.216.34", 80, 1.0, False)
        assert result is not None
        assert result["port"] == 80
        assert result["state"] == "open"
        assert result["service"] == "http"

    def test_scan_port_closed(self):
        scanner = PortScanner()
        with patch("socket.socket") as mock_socket:
            sock_instance = Mock()
            mock_socket.return_value.__enter__.return_value = sock_instance
            sock_instance.connect_ex.return_value = 1  # closed

            result = scanner._scan_port("93.184.216.34", 80, 1.0, False)
        assert result is None

    def test_scan_port_error(self):
        scanner = PortScanner()
        with patch("socket.socket") as mock_socket:
            sock_instance = Mock()
            mock_socket.return_value.__enter__.return_value = sock_instance
            sock_instance.connect_ex.side_effect = Exception("Socket error")

            result = scanner._scan_port("93.184.216.34", 80, 1.0, False)
        assert result is None

    def test_identify_service(self):
        assert PortScanner._identify_service(80) == "http"
        assert PortScanner._identify_service(443) == "https"
        assert PortScanner._identify_service(22) == "ssh"
        assert PortScanner._identify_service(3306) == "mysql"
        assert PortScanner._identify_service(9999) == "unknown"

    def test_normalize_ports(self):
        scanner = PortScanner()
        result = scanner._normalize_ports([80, 443, 0, 65536, 22, 80])
        assert result == [22, 80, 443]

    def test_normalize_ports_invalid(self):
        scanner = PortScanner()
        result = scanner._normalize_ports([-1, 0, "abc", 80])  # type: ignore[list-item]
        assert result == [80]

    def test_detect_provider_cloudflare(self):
        scanner = PortScanner()
        assert scanner._detect_provider("104.16.0.1") == "Cloudflare CDN"
        assert scanner._detect_provider("162.158.0.1") == "Cloudflare CDN"

    def test_detect_provider_aws(self):
        scanner = PortScanner()
        result = scanner._detect_provider("13.0.0.1", "ec2.compute.amazonaws.com")
        assert "AWS" in result

    def test_detect_provider_reverse_dns(self):
        scanner = PortScanner()
        result = scanner._detect_provider("1.2.3.4", "server.cloudfront.net")
        assert "CloudFront" in result

    def test_detect_provider_unknown(self):
        scanner = PortScanner()
        result = scanner._detect_provider("10.0.0.1", "")
        assert result == "Unknown"

    def test_analyze_no_ports(self):
        scanner = PortScanner()
        insights = scanner.analyze({"open_ports": []})
        assert "[INFO] No open ports detected" in insights

    def test_analyze_critical_mysql(self):
        scanner = PortScanner()
        insights = scanner.analyze({"open_ports": [{"port": 3306}]})
        assert any("[CRITICAL]" in i for i in insights)

    def test_analyze_warning_ssh(self):
        scanner = PortScanner()
        insights = scanner.analyze({"open_ports": [{"port": 22}]})
        assert any("[WARNING]" in i for i in insights)

    def test_analyze_web_only(self):
        scanner = PortScanner()
        insights = scanner.analyze({"open_ports": [{"port": 80}, {"port": 443}]})
        assert any("[INFO] Only web ports" in i for i in insights)

    def test_grab_banner_http(self):
        scanner = PortScanner()
        with patch("socket.socket") as mock_socket:
            sock_instance = Mock()
            mock_socket.return_value.__enter__.return_value = sock_instance
            sock_instance.recv.return_value = b"HTTP/1.1 200 OK\r\n"

            banner = scanner._grab_banner("93.184.216.34", 80, 1.0)
        assert "HTTP/1.1" in banner

    def test_grab_banner_tls(self):
        scanner = PortScanner()
        with patch("socket.socket") as mock_s:
            sock = Mock()
            mock_s.return_value.__enter__.return_value = sock
            banner = scanner._grab_banner("93.184.216.34", 443, 1.0)
        assert banner == "TLS (banner skipped)"

    def test_grab_banner_error(self):
        scanner = PortScanner()
        with patch("socket.socket") as mock_socket:
            sock_instance = Mock()
            mock_socket.return_value.__enter__.return_value = sock_instance
            sock_instance.recv.side_effect = Exception("Timeout")

            banner = scanner._grab_banner("93.184.216.34", 80, 1.0)
        assert banner == "-"

    def test_scan_resolution_failure(self):
        scanner = PortScanner()
        with patch.object(scanner, "_resolve_target", return_value=None):
            result = scanner.scan("invalid.example.com")
        assert "error" in result
        assert "Could not resolve" in result["error"]

    def test_scan_success(self):
        scanner = PortScanner()
        with (
            patch.object(scanner, "_resolve_target", return_value="93.184.216.34"),
            patch.object(scanner, "_reverse_dns", return_value="example.com"),
            patch.object(scanner, "_detect_provider", return_value="Unknown"),
            patch.object(scanner, "_scan_port", return_value=None),
        ):
            result = scanner.scan("example.com")
        assert result["target"] == "example.com"
        assert result["ip"] == "93.184.216.34"
        assert "open_ports" in result
        assert "insights" in result
