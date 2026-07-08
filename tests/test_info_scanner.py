"""Tests for InfoScanner."""

from unittest.mock import Mock, patch

import pytest

from domainspyder.scanners.info_scanner import InfoScanner


class TestInfoScanner:
    def test_scan_all_sources_fail(self):
        scanner = InfoScanner()
        with patch.object(scanner, "_run_sources", return_value={}):
            result = scanner.scan("example.com")
        assert "error" in result
        assert result["error"] == "All sources failed"

    def test_scan_merges_results(self):
        scanner = InfoScanner()
        source_data = {
            "whois": {
                "domain_name": "example.com",
                "registrar": "Test Registrar",
                "creation_date": "2000-01-15",
                "expiration_date": "2030-01-15",
                "name_servers": ["ns1.example.com"],
                "status": ["ok"],
                "registrant": {"org": "Test Org"},
                "dnssec": "unsigned",
            },
        }

        with (
            patch.object(scanner, "_run_sources", return_value=source_data),
            patch.object(scanner, "_enrich_data"),
        ):
            result = scanner.scan("example.com")

        assert result["domain"] == "example.com"
        assert result["registrar"] == "Test Registrar"
        assert "sources_used" in result
        assert "sources_failed" in result
        assert "duration" in result
        assert "insights" in result

    def test_analyze_critical_expiry(self):
        scanner = InfoScanner()
        data = {
            "expiry": {"days_remaining": 7, "alert": "CRITICAL"},
        }
        insights = scanner.analyze(data)
        assert any("[CRITICAL]" in i for i in insights)

    def test_analyze_critical_ssl(self):
        scanner = InfoScanner()
        data = {
            "ssl_days_remaining": 3,
        }
        insights = scanner.analyze(data)
        assert any("[CRITICAL]" in i for i in insights)

    def test_analyze_warning_expiry(self):
        scanner = InfoScanner()
        data = {
            "expiry": {"days_remaining": 60, "alert": "WARNING"},
        }
        insights = scanner.analyze(data)
        assert any("[WARNING]" in i for i in insights)

    def test_analyze_dnssec_unsigned(self):
        scanner = InfoScanner()
        data = {"dnssec": "unsigned"}
        insights = scanner.analyze(data)
        assert any("[WARNING] DNSSEC is not enabled" in i for i in insights)

    def test_analyze_dnssec_signed(self):
        scanner = InfoScanner()
        data = {"dnssec": "signedDelegation"}
        insights = scanner.analyze(data)
        assert any("[INFO] DNSSEC is enabled" in i for i in insights)

    def test_analyze_domain_age_veteran(self):
        scanner = InfoScanner()
        data = {"age": {"label": "Veteran", "human": "25 years"}}
        insights = scanner.analyze(data)
        assert any("well-established" in i for i in insights)

    def test_analyze_domain_age_new(self):
        scanner = InfoScanner()
        data = {"age": {"label": "New", "human": "3 months"}}
        insights = scanner.analyze(data)
        assert any("[WARNING]" in i and "new" in i for i in insights)

    def test_analyze_hold_status(self):
        scanner = InfoScanner()
        data = {"status": ["clientHold"]}
        insights = scanner.analyze(data)
        assert any("[CRITICAL]" in i for i in insights)

    def test_analyze_privacy_protection(self):
        scanner = InfoScanner()
        data = {"registrant": {"is_private": True}}
        insights = scanner.analyze(data)
        assert any("[INFO] WHOIS privacy" in i for i in insights)

    def test_compute_age(self):
        scanner = InfoScanner()
        age = scanner._compute_age("2000-01-15")
        assert age["label"] in ("Veteran", "Mature", "Established")
        assert age["years"] >= 24
        assert "human" in age
        assert "days" in age

    def test_compute_age_invalid_date(self):
        scanner = InfoScanner()
        age = scanner._compute_age("not-a-date")
        assert age == {}

    def test_check_expiry(self):
        scanner = InfoScanner()
        from datetime import datetime, timedelta

        future = (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%d")
        expiry = scanner._check_expiry(future)
        assert expiry["days_remaining"] > 0
        assert expiry["alert"] is None

    def test_check_expiry_critical(self):
        scanner = InfoScanner()
        from datetime import datetime, timedelta

        near = (datetime.utcnow() + timedelta(days=15)).strftime("%Y-%m-%d")
        expiry = scanner._check_expiry(near)
        assert expiry["alert"] == "CRITICAL"

    def test_check_expiry_invalid(self):
        scanner = InfoScanner()
        expiry = scanner._check_expiry("not-a-date")
        assert expiry == {}

    def test_detect_privacy(self):
        scanner = InfoScanner()
        assert scanner._detect_privacy({"org": "WhoisGuard Protected"}) is True
        assert scanner._detect_privacy({"org": "Real Company Inc"}) is False
        assert scanner._detect_privacy({}) is False

    def test_explain_status(self):
        scanner = InfoScanner()
        explained = scanner._explain_status(["ok", "clientHold"])
        codes = [e["code"] for e in explained]
        assert "ok" in codes
        assert "clientHold" in codes
        assert explained[0]["meaning"] != "Unknown status code"

    def test_get_source_names(self):
        names = InfoScanner._get_source_names(skip_ssl=False, skip_whois=False)
        assert "whois" in names
        assert "ssl" in names
        assert "rdap" in names
        assert "dns_soa" in names

    def test_get_source_names_skip_ssl(self):
        names = InfoScanner._get_source_names(skip_ssl=True, skip_whois=False)
        assert "ssl" not in names

    def test_get_source_names_skip_whois(self):
        names = InfoScanner._get_source_names(skip_ssl=False, skip_whois=True)
        assert "whois" not in names
