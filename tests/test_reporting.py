"""Tests for report generation (JSON, HTML, export)."""

import json

import pytest

from domainspyder.reporting import ExportError, save_report
from domainspyder.reporting.exporter import (
    EXPORTERS,
    get_exporter,
    report_metadata,
)
from domainspyder.reporting.html_report import HtmlExporter
from domainspyder.reporting.json_report import JsonExporter


class TestReportMetadata:
    def test_metadata_structure(self):
        meta = report_metadata()
        assert "tool" in meta
        assert "version" in meta
        assert "generated_at" in meta
        assert meta["tool"] == "DomainSpyder"

    def test_generated_at_is_iso(self):
        meta = report_metadata()
        assert "T" in meta["generated_at"]


class TestJsonExporter:
    def test_render_includes_metadata(self):
        exporter = JsonExporter()
        data = {"command": "test", "target": "example.com"}
        output = exporter.render(data)
        payload = json.loads(output)
        assert "tool" in payload
        assert "version" in payload
        assert "generated_at" in payload
        assert payload["data"]["command"] == "test"

    def test_render_preserves_data(self):
        exporter = JsonExporter()
        data = {"command": "dns", "target": "example.com", "records": {"A": ["1.2.3.4"]}}
        output = exporter.render(data)
        payload = json.loads(output)
        assert payload["data"]["records"]["A"] == ["1.2.3.4"]

    def test_render_handles_non_serializable(self):
        exporter = JsonExporter()
        data = {"command": "test", "bytes": b"binary"}
        # Should not raise
        output = exporter.render(data)
        payload = json.loads(output)
        assert "bytes" in payload["data"]


class TestHtmlExporter:
    def test_init_valid_themes(self):
        exporter = HtmlExporter(theme="light")
        assert exporter.theme == "light"
        exporter = HtmlExporter(theme="dark")
        assert exporter.theme == "dark"

    def test_init_invalid_theme(self):
        with pytest.raises(ValueError, match="Unsupported HTML theme"):
            HtmlExporter(theme="green")

    def test_render_basic_html(self):
        exporter = HtmlExporter(theme="light")
        data = {"command": "dns", "target": "example.com", "records": {"A": ["1.2.3.4"]}}
        output = exporter.render(data)
        assert "<!doctype html>" in output
        assert "example.com" in output
        assert "DNS" in output

    def test_render_subdomains_html(self):
        exporter = HtmlExporter(theme="light")
        data = {
            "command": "subdomains",
            "target": "example.com",
            "count": 2,
            "subdomains": ["www.example.com", "mail.example.com"],
            "alive": [],
        }
        output = exporter.render(data)
        assert "www.example.com" in output
        assert "mail.example.com" in output

    def test_render_ports_html(self):
        exporter = HtmlExporter(theme="light")
        data = {
            "command": "ports",
            "target": "example.com",
            "ip": "1.2.3.4",
            "ports_scanned": 2,
            "open_ports": [{"port": 80, "state": "open", "service": "http", "banner": "nginx"}],
            "insights": ["Web server exposed"],
        }
        output = exporter.render(data)
        assert "80" in output
        assert "nginx" in output

    def test_render_tech_html(self):
        exporter = HtmlExporter(theme="light")
        data = {
            "command": "tech",
            "target": "example.com",
            "status": 200,
            "categories": [{"name": "nginx", "category": "Server", "version": "1.24", "confidence": "High"}],
            "other": ["jQuery"],
        }
        output = exporter.render(data)
        assert "nginx" in output
        assert "jQuery" in output

    def test_render_info_html(self):
        exporter = HtmlExporter(theme="light")
        data = {
            "command": "info",
            "target": "example.com",
            "whois": {"registrar": "Test Registrar"},
            "rdap": {},
            "ssl": {},
            "soa": {},
            "insights": ["Domain is well-established"],
        }
        output = exporter.render(data)
        assert "Test Registrar" in output
        assert "well-established" in output

    def test_security_score_section(self):
        exporter = HtmlExporter(theme="light")
        html = exporter._security_score({"score": 8, "risk": "Low Risk", "issues": ["No SPF"], "good": ["DMARC ok"]})
        assert "8/10" in html
        assert "No SPF" in html
        assert "DMARC ok" in html

    def test_security_score_empty(self):
        exporter = HtmlExporter(theme="light")
        assert exporter._security_score({}) == ""
        assert exporter._security_score(None) == ""

    def test_friendly_datetime(self):
        exporter = HtmlExporter(theme="light")
        result = exporter._friendly_datetime("2024-01-15T12:00:00+00:00")
        assert "January" in result
        assert "2024" in result

    def test_friendly_datetime_invalid(self):
        exporter = HtmlExporter(theme="light")
        assert exporter._friendly_datetime("") == "-"
        assert exporter._friendly_datetime("-") == "-"

    def test_humanize_key(self):
        exporter = HtmlExporter(theme="light")
        assert exporter._humanize_key("ssl_subject") == "Ssl Subject"
        assert exporter._humanize_key("domain_name") == "Domain Name"

    def test_score_text(self):
        exporter = HtmlExporter(theme="light")
        assert exporter._score_text({"score": 8}) == "8/10"
        assert exporter._score_text({}) == "-"

    def test_format_value_none(self):
        exporter = HtmlExporter(theme="light")
        result = exporter._format_value(None)
        assert "muted" in result

    def test_format_value_list(self):
        exporter = HtmlExporter(theme="light")
        result = exporter._format_value(["a", "b"])
        assert result.count("br") >= 1

    def test_format_value_dict(self):
        exporter = HtmlExporter(theme="light")
        result = exporter._format_value({"key": "val"})
        assert "key" in result
        assert "val" in result

    def test_table_no_rows(self):
        exporter = HtmlExporter(theme="light")
        html = exporter._table("Test", ["Col1"], [])
        assert "0 rows" in html
        assert "No data found" in html

    def test_list_section(self):
        exporter = HtmlExporter(theme="light")
        html = exporter._list_section("Test", ["item1", "item2"])
        assert "item1" in html
        assert "item2" in html

    def test_list_html_empty(self):
        exporter = HtmlExporter(theme="light")
        html = exporter._list_html([])
        assert "No items found" in html


class TestGetExporter:
    def test_json_exporter(self):
        exporter = get_exporter("report.json")
        assert isinstance(exporter, JsonExporter)

    def test_html_exporter(self):
        exporter = get_exporter("report.html", html_theme="light")
        assert isinstance(exporter, HtmlExporter)

    def test_html_dark_theme(self):
        exporter = get_exporter("report.html", html_theme="dark")
        assert isinstance(exporter, HtmlExporter)
        assert exporter.theme == "dark"

    def test_unsupported_format(self):
        with pytest.raises(ExportError, match="Unsupported report format"):
            get_exporter("report.pdf")

    def test_empty_extension(self):
        with pytest.raises(ExportError, match="Unsupported report format"):
            get_exporter("report")


class TestExporters:
    def test_exporter_registry(self):
        assert ".json" in EXPORTERS
        assert ".html" in EXPORTERS
        assert EXPORTERS[".json"] is JsonExporter
        assert EXPORTERS[".html"] is HtmlExporter


class TestSaveReport:
    def test_save_json(self, tmp_path):
        output = tmp_path / "report.json"
        data = {"command": "test", "target": "example.com"}
        path = save_report(data, str(output))
        assert path.exists()
        content = json.loads(path.read_text())
        assert content["data"]["target"] == "example.com"

    def test_save_html(self, tmp_path):
        output = tmp_path / "report.html"
        data = {"command": "dns", "target": "example.com", "records": {}}
        path = save_report(data, str(output), html_theme="light")
        assert path.exists()
        content = path.read_text()
        assert "<!doctype html>" in content

    def test_save_creates_parent_dirs(self, tmp_path):
        output = tmp_path / "nested" / "subdir" / "report.json"
        data = {"command": "test", "target": "example.com"}
        path = save_report(data, str(output))
        assert path.exists()

    def test_unsupported_format(self, tmp_path):
        data = {"command": "test"}
        with pytest.raises(ExportError, match="Unsupported report format"):
            save_report(data, str(tmp_path / "report.pdf"))
