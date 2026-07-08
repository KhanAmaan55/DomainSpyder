"""Tests for DNSScanner."""

from unittest.mock import MagicMock, Mock, patch

import pytest

from domainspyder.scanners.dns_scanner import DNSScanner
from tests.conftest import (
    SAMPLE_A_RECORDS,
    SAMPLE_CNAME_RECORDS,
    SAMPLE_DMARC_RECORD,
    SAMPLE_DNS_RECORDS,
    SAMPLE_MX_RECORDS,
    SAMPLE_NS_RECORDS,
    SAMPLE_TXT_RECORDS,
)


class TestDNSScanner:
    def make_resolver_mock(self, record_type, records):
        """Create a mock resolver response."""
        mocks = []
        for val in records:
            rdata = Mock()
            if record_type == "MX":
                # MX records are tuples of (preference, exchange)
                rdata.preference = 10
                rdata.exchange = val
            elif record_type == "TXT":
                rdata.strings = [val.encode()]
            else:
                rdata = val
            mocks.append(rdata)
        return mocks

    @patch("dns.resolver.Resolver")
    def test_resolve_records(self, mock_resolver_class):
        scanner = DNSScanner()

        # Configure mock resolver
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        def resolve_side_effect(domain, rtype):
            if rtype == "A":
                return self.make_resolver_mock("A", SAMPLE_A_RECORDS)
            if rtype == "AAAA":
                return self.make_resolver_mock("AAAA", SAMPLE_A_RECORDS[:1])
            if rtype == "MX":
                return self.make_resolver_mock("MX", SAMPLE_MX_RECORDS)
            if rtype == "NS":
                return self.make_resolver_mock("NS", SAMPLE_NS_RECORDS)
            if rtype == "TXT":
                return self.make_resolver_mock("TXT", SAMPLE_TXT_RECORDS)
            if rtype == "CNAME":
                return self.make_resolver_mock("CNAME", SAMPLE_CNAME_RECORDS)
            raise Exception("Unknown type")

        mock_resolver.resolve.side_effect = resolve_side_effect

        records = scanner.resolve_records("example.com")
        assert "A" in records
        assert "MX" in records
        assert "NS" in records
        assert "TXT" in records

    @patch("dns.resolver.Resolver")
    def test_analyze_spf_strict(self, mock_resolver_class):
        records = {
            "A": ["93.184.216.34"],
            "MX": ["aspmx.l.google.com"],
            "NS": ["a.iana-servers.net"],
            "TXT": ["v=spf1 include:_spf.google.com -all"],
        }
        scanner = DNSScanner()

        with patch.object(scanner, "get_dmarc_cached", return_value=(["v=DMARC1; p=reject"], True)):
            insights = scanner.analyze(records, "example.com")

        insight_text = " ".join(insights)
        assert "SPF: Strict" in insight_text
        assert "DMARC: Strict" in insight_text

    @patch("dns.resolver.Resolver")
    def test_analyze_spf_softfail(self, mock_resolver_class):
        records = {
            "A": ["93.184.216.34"],
            "MX": ["aspmx.l.google.com"],
            "NS": [],
            "TXT": ["v=spf1 include:_spf.google.com ~all"],
        }
        scanner = DNSScanner()
        with patch.object(scanner, "get_dmarc_cached", return_value=(["v=DMARC1; p=none"], True)):
            insights = scanner.analyze(records, "example.com")
        insight_text = " ".join(insights)
        assert "Soft fail" in insight_text

    @patch("dns.resolver.Resolver")
    def test_analyze_no_spf(self, mock_resolver_class):
        records = {
            "A": ["93.184.216.34"],
            "MX": ["mail.example.com"],
            "NS": [],
            "TXT": ["google-site-verification=xxx"],
        }
        scanner = DNSScanner()
        with patch.object(scanner, "get_dmarc_cached", return_value=([], True)):
            insights = scanner.analyze(records, "example.com")
        insight_text = " ".join(insights)
        assert "SPF: Not configured" in insight_text

    @patch("dns.resolver.Resolver")
    def test_analyze_dmarc_not_configured(self, mock_resolver_class):
        records = {
            "A": ["93.184.216.34"],
            "MX": ["aspmx.l.google.com"],
            "NS": [],
            "TXT": ["v=spf1 include:_spf.google.com -all"],
        }
        scanner = DNSScanner()
        with patch.object(scanner, "get_dmarc_cached", return_value=([], True)):
            insights = scanner.analyze(records, "example.com")
        insight_text = " ".join(insights)
        assert "DMARC: Not configured" in insight_text

    @patch("dns.resolver.Resolver")
    def test_calculate_security_perfect(self, mock_resolver_class):
        records = {
            "MX": ["aspmx.l.google.com"],
            "TXT": ["v=spf1 include:_spf.google.com -all"],
        }
        scanner = DNSScanner()
        with patch.object(scanner, "get_dmarc_cached", return_value=(["v=DMARC1; p=reject"], True)):
            security = scanner.calculate_security(records, "example.com")
        assert security["score"] >= 8
        assert security["risk"] == "Low Risk"

    @patch("dns.resolver.Resolver")
    def test_calculate_security_no_spf(self, mock_resolver_class):
        records = {
            "MX": ["mail.example.com"],
            "TXT": [],
        }
        scanner = DNSScanner()
        with patch.object(scanner, "get_dmarc_cached", return_value=([], True)):
            security = scanner.calculate_security(records, "example.com")
        assert security["score"] < 10
        assert len(security["issues"]) > 0

    def test_security_score_never_negative(self):
        scanner = DNSScanner()
        # All bad: no SPF, DMARC lookup fails, mismatch
        records = {
            "MX": ["mail.example.com"],
            "TXT": [],
        }
        with patch.object(scanner, "get_dmarc_cached", return_value=([], False)):
            security = scanner.calculate_security(records, "example.com")
        assert security["score"] >= 0

    def test_preprocess_extracts_providers(self):
        records = {
            "TXT": ["v=spf1 include:_spf.google.com ~all"],
            "MX": ["aspmx.l.google.com"],
        }
        scanner = DNSScanner()
        data = scanner.preprocess(records)
        assert "google" in data["mx_providers"]
        assert "google" in data["spf_providers"]
        assert len(data["spf_records"]) == 1

    def test_preprocess_no_records(self):
        scanner = DNSScanner()
        data = scanner.preprocess({"TXT": [], "MX": []})
        assert data["mx_providers"] == set()
        assert data["spf_providers"] == set()
        assert data["spf_records"] == []

    @patch("dns.resolver.Resolver")
    def test_get_dmarc_cached(self, mock_resolver_class):
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        mock_rdata = Mock()
        mock_rdata.strings = [b"v=DMARC1; p=reject"]
        mock_resolver.resolve.return_value = [mock_rdata]

        scanner = DNSScanner()
        records, success = scanner.get_dmarc_cached("example.com")
        assert success is True
        assert len(records) > 0

        # Second call should use cache
        records2, success2 = scanner.get_dmarc_cached("example.com")
        assert records2 == records
        assert mock_resolver.resolve.call_count == 1

    def test_scan_returns_structured_result(self):
        scanner = DNSScanner()
        with (
            patch.object(scanner, "resolve_records", return_value=SAMPLE_DNS_RECORDS),
            patch.object(scanner, "get_dmarc_cached", return_value=(SAMPLE_DMARC_RECORD, True)),
        ):
            result = scanner.scan("example.com")

        assert result["command"] == "dns"
        assert result["target"] == "example.com"
        assert "records" in result
        assert "analysis" in result
        assert "security_score" in result
        assert "timestamp" in result
