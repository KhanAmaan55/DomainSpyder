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
        assert args.ports == [80, 443, 8080]

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
            "example.com", None, 50,
            alive=False, brutemode="balanced", brute_only=False,
        )

    def test_handle_subdomains_save_failure(self, tmp_path):
        parser = _build_parser()
        args = parser.parse_args(
            ["subdomains", "example.com", "--save", str(tmp_path / "out.txt")]
        )

        with (
            patch("domainspyder.cli.SubdomainScanner") as mock_scanner_cls,
            patch("domainspyder.cli.print_banner"),
            patch("domainspyder.cli.print_target"),
            patch("domainspyder.cli.print_subdomain_table"),
            patch("domainspyder.cli.print_total"),
            patch("domainspyder.cli.print_saved") as mock_saved,
            patch("domainspyder.cli.console") as mock_console,
            patch("builtins.open", side_effect=OSError("disk full")),
        ):
            mock_scanner_cls.return_value.scan.return_value = {
                "subdomains": ["www.example.com"],
                "alive": [],
            }

            _handle_subdomains(args)

        mock_saved.assert_not_called()
        printed = " ".join(str(c.args[0]) for c in mock_console.print.call_args_list)
        assert "Failed to save results" in printed
        assert "disk full" in printed

    def test_handle_subdomains_save_alive(self, tmp_path):
        save_path = tmp_path / "alive.txt"
        parser = _build_parser()
        args = parser.parse_args(
            ["subdomains", "example.com", "--alive", "--save", str(save_path)]
        )

        with (
            patch("domainspyder.cli.SubdomainScanner") as mock_scanner_cls,
            patch("domainspyder.cli.print_banner"),
            patch("domainspyder.cli.print_target"),
            patch("domainspyder.cli.print_subdomain_table"),
            patch("domainspyder.cli.print_total"),
            patch("domainspyder.cli.print_saved") as mock_saved,
        ):
            mock_scanner_cls.return_value.scan.return_value = {
                "subdomains": [],
                "alive": [
                    {
                        "subdomain": "www.example.com",
                        "status": 200,
                        "title": "Example Domain",
                    }
                ],
            }

            _handle_subdomains(args)

        assert save_path.read_text() == "www.example.com 200 Example Domain\n"
        mock_saved.assert_called_once_with(str(save_path))

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

        mock_scanner.scan.assert_called_once_with(
            "example.com", ports=None, threads=args.threads, mode="balanced",
        )

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

        mock_scanner.scan.assert_called_once_with("example.com")

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


class TestArgumentValidation:
    @pytest.mark.parametrize("command", ["subdomains", "dns", "info"])
    def test_domain_is_normalised(self, command):
        args = _build_parser().parse_args([command, "https://Example.COM/path"])
        assert args.domain == "example.com"

    @pytest.mark.parametrize("command", ["subdomains", "dns", "info"])
    @pytest.mark.parametrize("bad", ["not a domain!!", "localhost", "1.2.3.4"])
    def test_invalid_domain_exits_2(self, command, bad, capsys):
        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args([command, bad])
        assert exc.value.code == 2
        assert "argument domain:" in capsys.readouterr().err

    def test_ports_accepts_ipv4(self):
        args = _build_parser().parse_args(["ports", "93.184.216.34"])
        assert args.target == "93.184.216.34"

    def test_tech_preserves_url(self):
        args = _build_parser().parse_args(["tech", "https://example.com/blog"])
        assert args.target == "https://example.com/blog"

    @pytest.mark.parametrize("spec", ["abc", "99999,-1", "80,,443"])
    def test_invalid_ports_exit_2(self, spec, capsys):
        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args(["ports", "example.com", "--ports", spec])
        assert exc.value.code == 2
        assert "invalid port" in capsys.readouterr().err

    @pytest.mark.parametrize("command", ["subdomains", "ports"])
    @pytest.mark.parametrize("threads", ["0", "-5", "many"])
    def test_invalid_threads_exit_2(self, command, threads):
        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args([command, "example.com", "--threads", threads])
        assert exc.value.code == 2

    def test_missing_wordlist_exits_2(self, capsys):
        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args(
                ["subdomains", "example.com", "--wordlist", "/nonexistent/words.txt"]
            )
        assert exc.value.code == 2
        assert "wordlist not found" in capsys.readouterr().err

    def test_existing_wordlist_accepted(self, mock_wordlist):
        args = _build_parser().parse_args(
            ["subdomains", "example.com", "--wordlist", mock_wordlist]
        )
        assert args.wordlist == mock_wordlist

    def test_version_flag(self, capsys):
        from domainspyder import __version__

        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args(["--version"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.strip() == f"domainspyder {__version__}"


class TestExitCodes:
    @pytest.fixture(autouse=True)
    def _quiet(self):
        with (
            patch("domainspyder.cli.print_banner"),
            patch("domainspyder.cli.print_target"),
            patch("domainspyder.cli.console"),
        ):
            yield

    def test_successful_scan_returns_0(self):
        args = _build_parser().parse_args(["dns", "example.com"])
        with (
            patch("domainspyder.cli.DNSScanner") as mock_cls,
            patch("domainspyder.cli.print_dns_records"),
            patch("domainspyder.cli.print_dns_insights"),
            patch("domainspyder.cli.print_security_score"),
        ):
            mock_cls.return_value.scan.return_value = {
                "records": {"A": ["1.2.3.4"]},
                "analysis": [],
                "security_score": {},
            }
            assert _handle_dns(args) == 0

    def test_empty_result_returns_0(self):
        args = _build_parser().parse_args(["dns", "example.com"])
        with patch("domainspyder.cli.DNSScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = {"records": {}}
            assert _handle_dns(args) == 0

    def test_port_resolution_failure_returns_1(self):
        args = _build_parser().parse_args(["ports", "example.com"])
        with (
            patch("domainspyder.cli.PortScanner") as mock_cls,
            patch("domainspyder.cli.print_port_summary") as mock_summary,
        ):
            mock_cls.return_value.scan.return_value = {
                "error": "Could not resolve target: example.com"
            }
            assert _handle_ports(args) == 1
        mock_summary.assert_not_called()

    def test_custom_ports_passed_through(self):
        args = _build_parser().parse_args(["ports", "example.com", "--ports", "22,80"])
        with patch("domainspyder.cli.PortScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = {"open_ports": []}
            assert _handle_ports(args) == 0
        assert mock_cls.return_value.scan.call_args.kwargs["ports"] == [22, 80]

    def test_tech_error_returns_1(self):
        args = _build_parser().parse_args(["tech", "example.com"])
        with patch("domainspyder.cli.TechScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = {"error": "boom"}
            assert _handle_tech(args) == 1

    def test_info_error_returns_1(self):
        args = _build_parser().parse_args(["info", "example.com"])
        with patch("domainspyder.cli.InfoScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = {"error": "boom"}
            assert _handle_info(args) == 1

    def test_export_failure_returns_1(self, tmp_path):
        args = _build_parser().parse_args(
            ["dns", "example.com", "--output", str(tmp_path / "report.txt")]
        )
        with patch("domainspyder.cli.DNSScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = {"records": {}}
            assert _handle_dns(args) == 1

    def test_save_failure_returns_1(self, tmp_path):
        args = _build_parser().parse_args(
            ["subdomains", "example.com", "--save", str(tmp_path / "missing" / "out.txt")]
        )
        with (
            patch("domainspyder.cli.SubdomainScanner") as mock_cls,
            patch("domainspyder.cli.print_subdomain_table"),
            patch("domainspyder.cli.print_total"),
        ):
            mock_cls.return_value.scan.return_value = {
                "subdomains": ["www.example.com"],
                "alive": [],
            }
            assert _handle_subdomains(args) == 1

    def test_wildcard_note_printed(self):
        from domainspyder import cli

        args = _build_parser().parse_args(["subdomains", "example.com"])
        with (
            patch("domainspyder.cli.SubdomainScanner") as mock_cls,
            patch("domainspyder.cli.print_subdomain_table"),
            patch("domainspyder.cli.print_total"),
        ):
            mock_cls.return_value.scan.return_value = {
                "subdomains": [],
                "alive": [],
                "wildcard_ips": ["10.0.0.1"],
            }
            assert _handle_subdomains(args) == 0
        printed = " ".join(str(c.args[0]) for c in cli.console.print.call_args_list)
        assert "Wildcard DNS detected" in printed
        assert "10.0.0.1" in printed

    def test_main_returns_handler_code(self):
        with (
            patch("sys.argv", ["domainspyder", "dns", "example.com"]),
            patch("domainspyder.cli._handle_dns", return_value=1),
        ):
            assert main() == 1
