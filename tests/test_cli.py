"""Tests for CLI argument parsing and command routing."""

from __future__ import annotations

from argparse import ArgumentTypeError
from unittest.mock import Mock, patch

import pytest

from domainspyder.cli import _build_parser, _handle_dns, _handle_info, _handle_ports, _handle_subdomains, _handle_tech, main


class TestBuildParser:
    """Tests for CLI argument parsing."""

    def test_subdomains_parser(self):
        parser = _build_parser()
        args = parser.parse_args(["subdomains", "example.com"])
        assert args.command == "subdomains"
        assert args.domain == "example.com"

    def test_dns_parser(self):
        parser = _build_parser()
        args = parser.parse_args(["dns", "example.com"])
        assert args.command == "dns"
        assert args.domain == "example.com"

    def test_ports_parser(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com"])
        assert args.command == "ports"
        assert args.target == "example.com"

    def test_tech_parser(self):
        parser = _build_parser()
        args = parser.parse_args(["tech", "example.com"])
        assert args.command == "tech"
        assert args.target == "example.com"

    def test_info_parser(self):
        parser = _build_parser()
        args = parser.parse_args(["info", "example.com"])
        assert args.command == "info"
        assert args.domain == "example.com"

    def test_debug_flag(self):
        parser = _build_parser()
        args = parser.parse_args(["--debug", "dns", "example.com"])
        assert args.debug is True

    def test_no_debug(self):
        parser = _build_parser()
        args = parser.parse_args(["dns", "example.com"])
        assert args.debug is False

    def test_subdomains_output(self):
        parser = _build_parser()
        args = parser.parse_args(["subdomains", "example.com", "--output", "report.json"])
        assert args.output == "report.json"

    def test_subdomains_alive(self):
        parser = _build_parser()
        args = parser.parse_args(["subdomains", "example.com", "--alive"])
        assert args.alive is True

    def test_subdomains_brute_only(self):
        parser = _build_parser()
        args = parser.parse_args(["subdomains", "example.com", "--brute-only"])
        assert args.brute_only is True

    def test_subdomains_brutemode(self):
        parser = _build_parser()
        args = parser.parse_args(["subdomains", "example.com", "--brute-only", "--brutemode", "fast"])
        assert args.brutemode == "fast"

    def test_subdomains_save(self):
        parser = _build_parser()
        args = parser.parse_args(["subdomains", "example.com", "--save", "results.txt"])
        assert args.save == "results.txt"

    def test_dns_raw_only(self):
        parser = _build_parser()
        args = parser.parse_args(["dns", "example.com", "--raw-only"])
        assert args.raw_only is True

    def test_ports_top_100(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com", "--top-100"])
        assert args.top_100 is True

    def test_ports_top_1000(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com", "--top-1000"])
        assert args.top_1000 is True

    def test_ports_full(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com", "--full"])
        assert args.full is True

    def test_ports_custom_ports(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com", "--ports", "80,443,8080"])
        assert args.ports == "80,443,8080"

    def test_ports_fast(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com", "--fast"])
        assert args.fast is True

    def test_ports_deep(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com", "--deep"])
        assert args.deep is True

    def test_ports_threads(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com", "--threads", "100"])
        assert args.threads == 100

    def test_info_brief(self):
        parser = _build_parser()
        args = parser.parse_args(["info", "example.com", "--brief"])
        assert args.brief is True

    def test_info_no_ssl(self):
        parser = _build_parser()
        args = parser.parse_args(["info", "example.com", "--no-ssl"])
        assert args.no_ssl is True

    def test_info_no_whois(self):
        parser = _build_parser()
        args = parser.parse_args(["info", "example.com", "--no-whois"])
        assert args.no_whois is True

    def test_html_light_default(self):
        parser = _build_parser()
        args = parser.parse_args(["dns", "example.com", "--output", "report.html"])
        assert args.html_theme == "light"

    def test_html_dark(self):
        parser = _build_parser()
        args = parser.parse_args(["dns", "example.com", "--output", "report.html", "--html-dark"])
        assert args.html_theme == "dark"

    def test_requires_command(self):
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_no_positional_args_unless_needed(self):
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["subdomains"])


class TestCommandHandlers:
    def test_handle_subdomains(self):
        parser = _build_parser()
        args = parser.parse_args(["subdomains", "example.com"])

        with (
            patch("domainspyder.cli.SubdomainScanner") as mock_scanner_cls,
            patch("domainspyder.cli.print_banner"),
            patch("domainspyder.cli.print_target"),
            patch("domainspyder.cli.print_subdomain_table"),
            patch("domainspyder.cli.print_total"),
        ):
            mock_scanner = Mock()
            mock_scanner_cls.return_value = mock_scanner
            mock_scanner.scan.return_value = {"subdomains": ["www.example.com"], "alive": []}

            _handle_subdomains(args)

        mock_scanner.scan.assert_called_once_with(
            "example.com", "wordlists/default.txt", 50,
            alive=False, brutemode="balanced", brute_only=False,
        )

    def test_handle_dns(self):
        parser = _build_parser()
        args = parser.parse_args(["dns", "example.com"])

        with (
            patch("domainspyder.cli.DNSScanner") as mock_scanner_cls,
            patch("domainspyder.cli.print_banner"),
            patch("domainspyder.cli.print_target"),
            patch("domainspyder.cli.print_dns_records"),
            patch("domainspyder.cli.print_dns_insights"),
            patch("domainspyder.cli.print_security_score"),
        ):
            mock_scanner = Mock()
            mock_scanner_cls.return_value = mock_scanner
            mock_scanner.scan.return_value = {
                "records": {"A": ["1.2.3.4"]},
                "analysis": [],
                "security_score": {"score": 8, "risk": "Low", "issues": [], "good": []},
            }

            _handle_dns(args)

        mock_scanner.scan.assert_called_once_with("example.com")

    def test_handle_ports(self):
        parser = _build_parser()
        args = parser.parse_args(["ports", "example.com"])

        with (
            patch("domainspyder.cli.PortScanner") as mock_scanner_cls,
            patch("domainspyder.cli.print_banner"),
            patch("domainspyder.cli.print_target"),
            patch("domainspyder.cli.print_port_summary"),
            patch("domainspyder.cli.print_port_table"),
        ):
            mock_scanner = Mock()
            mock_scanner_cls.return_value = mock_scanner
            mock_scanner.scan.return_value = {
                "open_ports": [{"port": 80, "state": "open"}],
                "insights": [],
            }

            _handle_ports(args)

    def test_handle_tech(self):
        parser = _build_parser()
        args = parser.parse_args(["tech", "example.com"])

        with (
            patch("domainspyder.cli.TechScanner") as mock_scanner_cls,
            patch("domainspyder.cli.print_banner"),
            patch("domainspyder.cli.print_target"),
            patch("domainspyder.cli.print_tech_summary"),
        ):
            mock_scanner = Mock()
            mock_scanner_cls.return_value = mock_scanner
            mock_scanner.scan.return_value = {
                "categories": [{"name": "nginx"}],
                "other": [],
                "technologies": [],
            }

            _handle_tech(args)

    def test_handle_info(self):
        parser = _build_parser()
        args = parser.parse_args(["info", "example.com"])

        with (
            patch("domainspyder.cli.InfoScanner") as mock_scanner_cls,
            patch("domainspyder.cli.print_banner"),
            patch("domainspyder.cli.print_target"),
            patch("domainspyder.cli.print_info_summary"),
        ):
            mock_scanner = Mock()
            mock_scanner_cls.return_value = mock_scanner
            mock_scanner.scan.return_value = {
                "name_servers": [],
                "status_explained": [],
                "insights": [],
            }

            _handle_info(args)
        mock_scanner.scan.assert_called_once_with(
            "example.com", skip_ssl=False, skip_whois=False, brief=False,
        )


class TestMain:
    def test_main_dispatches(self):
        with (
            patch("sys.argv", ["domainspyder", "dns", "example.com"]),
            patch("domainspyder.cli._handle_dns") as mock_handler,
            patch("domainspyder.cli.warnings"),
            patch("domainspyder.cli.print_banner"),
        ):
            main()
            mock_handler.assert_called_once()

    def test_main_keyboard_interrupt(self):
        with (
            patch("sys.argv", ["domainspyder", "dns", "example.com"]),
            patch("domainspyder.cli._handle_dns", side_effect=KeyboardInterrupt),
            patch("domainspyder.cli.console") as mock_console,
            patch("domainspyder.cli.warnings"),
        ):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 130
