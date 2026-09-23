"""
DomainSpyder CLI entry point.

Handles argument parsing and dispatches to the appropriate
scanner + formatter.  All presentation logic lives in
``domainspyder.display``.
"""

from __future__ import annotations

import argparse
import logging
import os
import warnings
from collections.abc import Callable
from typing import Any

from rich.progress import Progress, SpinnerColumn, TextColumn

from domainspyder.config import (
    APP_NAME,
    DEFAULT_BRUTE_MODE,
    DEFAULT_THREADS,
    DEFAULT_WORDLIST,
    DESCRIPTION,
    FULL_PORT_RANGE,
    TOP_PORTS_100,
    TOP_PORTS_1000,
    VERSION,
)
from domainspyder.display.banner import print_banner
from domainspyder.display.formatter import (
    console,
    print_dns_insights,
    print_dns_records,
    print_info_insights,
    print_info_nameservers,
    print_info_soa,
    print_info_ssl,
    print_info_status,
    print_info_summary,
    print_port_insights,
    print_port_summary,
    print_port_table,
    print_saved,
    print_security_score,
    print_subdomain_table,
    print_target,
    print_tech_summary,
    print_total,
)
from domainspyder.reporting import ExportError, save_report
from domainspyder.scanners.dns_scanner import DNSScanner
from domainspyder.scanners.info_scanner import InfoScanner
from domainspyder.scanners.port_scanner import PortScanner
from domainspyder.scanners.subdomain_scanner import SubdomainScanner
from domainspyder.scanners.tech_scanner import TechScanner
from domainspyder.utils import (
    normalize_domain,
    normalize_host,
    normalize_url_target,
    parse_ports,
)

warnings.simplefilter("ignore")

# Exit codes: 0 = scan ran (even with no findings), 1 = scan or export
# failed, 2 = invalid arguments (argparse), 130 = interrupted.
EXIT_OK = 0
EXIT_FAILURE = 1


# ------------------------------------------------------------------
# Argument types
# ------------------------------------------------------------------


def _arg_type(func: Callable[[str], Any], name: str) -> Callable[[str], Any]:
    """Adapt a ``ValueError``-raising parser into an argparse type."""

    def convert(value: str) -> Any:
        try:
            return func(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from None

    convert.__name__ = name
    return convert


def _positive_int(value: str) -> int:
    if not value.strip().isdigit() or int(value) < 1:
        raise ValueError(f"expected a positive integer, got '{value}'")
    return int(value)


def _existing_file(value: str) -> str:
    if not os.path.isfile(value):
        raise ValueError(f"wordlist not found: '{value}'")
    return value


_domain_arg = _arg_type(normalize_domain, "domain")
_host_arg = _arg_type(normalize_host, "host")
_url_target_arg = _arg_type(normalize_url_target, "target")
_ports_arg = _arg_type(parse_ports, "port list")
_threads_arg = _arg_type(_positive_int, "thread count")
_wordlist_arg = _arg_type(_existing_file, "wordlist")


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="domainspyder",
        description=f"{APP_NAME} v{VERSION} - {DESCRIPTION}",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging globally",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_output_argument(command_parser: argparse.ArgumentParser) -> None:
        """Add the shared structured report output option."""
        command_parser.add_argument(
            "--output",
            help="Write a structured report to a file (.json, .html)",
        )
        html_theme = command_parser.add_mutually_exclusive_group()
        html_theme.add_argument(
            "--html-light",
            action="store_const",
            const="light",
            dest="html_theme",
            default="light",
            help="Use the light theme for HTML reports (default)",
        )
        html_theme.add_argument(
            "--html-dark",
            action="store_const",
            const="dark",
            dest="html_theme",
            help="Use the dark theme for HTML reports",
        )

    # ---- subdomains command ------------------------------------------
    sub = subparsers.add_parser("subdomains", help="Subdomain enumeration")
    sub.add_argument("domain", type=_domain_arg, help="Target domain")
    add_output_argument(sub)
    sub.add_argument(
        "--wordlist",
        type=_wordlist_arg,
        default=None,
        help=f"Path to wordlist (default: bundled {os.path.basename(DEFAULT_WORDLIST)})",
    )
    sub.add_argument("--save", help="Save results to file")
    sub.add_argument(
        "--threads",
        type=_threads_arg,
        default=DEFAULT_THREADS,
        help=f"Number of threads (default: {DEFAULT_THREADS})",
    )
    sub.add_argument(
        "--alive",
        action="store_true",
        help="Show only alive subdomains with HTTP info",
    )
    sub.add_argument(
        "--brute-only",
        action="store_true",
        help="Run only brute-force enumeration",
    )
    sub.add_argument(
        "--brutemode",
        choices=["fast", "balanced", "stealth"],
        default=DEFAULT_BRUTE_MODE,
        help=f"Brute-force mode (default: {DEFAULT_BRUTE_MODE})",
    )

    # ---- dns command -------------------------------------------------
    dns_cmd = subparsers.add_parser("dns", help="DNS record enumeration")
    dns_cmd.add_argument("domain", type=_domain_arg, help="Target domain")
    add_output_argument(dns_cmd)
    dns_cmd.add_argument(
        "--raw-only",
        action="store_true",
        help="Show raw DNS records without analysis",
    )

    # ---- ports command -------------------------------------------------
    ports_cmd = subparsers.add_parser("ports", help="Port scanning")
    ports_cmd.add_argument(
        "target", type=_host_arg, help="Target domain or IPv4 address"
    )
    add_output_argument(ports_cmd)
    ports_cmd.add_argument(
        "--ports",
        type=_ports_arg,
        help="Custom ports (comma-separated, e.g. 22,80,443)",
    )
    ports_cmd.add_argument("--top-100", action="store_true")
    ports_cmd.add_argument("--top-1000", action="store_true")
    ports_cmd.add_argument("--full", action="store_true")
    ports_cmd.add_argument("--fast", action="store_true", help="Fast scan mode")
    ports_cmd.add_argument("--deep", action="store_true", help="Deep scan mode")
    ports_cmd.add_argument(
        "--threads",
        type=_threads_arg,
        default=50,
        help="Number of threads (default: 50)",
    )

    # ---- tech command --------------------------------------------------
    tech_cmd = subparsers.add_parser("tech", help="Technology detection")
    tech_cmd.add_argument("target", type=_url_target_arg, help="Target domain or URL")
    add_output_argument(tech_cmd)

    # ---- info command --------------------------------------------------
    info_cmd = subparsers.add_parser("info", help="WHOIS + domain info")
    info_cmd.add_argument("domain", type=_domain_arg, help="Target domain")
    add_output_argument(info_cmd)
    info_cmd.add_argument(
        "--brief",
        action="store_true",
        help="Show only key registration fields (skip SSL, SOA, status)",
    )
    info_cmd.add_argument(
        "--no-ssl",
        action="store_true",
        help="Skip SSL certificate analysis",
    )
    info_cmd.add_argument(
        "--no-whois",
        action="store_true",
        help="Skip WHOIS lookup (use RDAP + SSL + DNS only)",
    )

    return parser


# ------------------------------------------------------------------
# Command handlers
# ------------------------------------------------------------------


def _maybe_save_report(
    data: dict[str, Any],
    output_path: str | None,
    html_theme: str = "light",
) -> bool:
    """Save a structured report if requested; return ``False`` on failure."""
    if not output_path:
        return True

    try:
        saved_path = save_report(data, output_path, html_theme=html_theme)
    except ExportError as exc:
        console.print(f"  [red]Report export failed:[/red] {exc}\n")
        return False

    console.print(f"  [green]✓[/green] Report saved: {saved_path}\n")
    return True


def _report_exit(
    data: dict[str, Any],
    output_path: str | None,
    html_theme: str,
    *,
    failed: bool = False,
) -> int:
    """Save the report (if requested) and pick the exit code."""
    saved = _maybe_save_report(data, output_path, html_theme)
    return EXIT_FAILURE if failed or not saved else EXIT_OK


def _handle_subdomains(args: argparse.Namespace) -> int:
    """Run subdomain enumeration and display results."""
    print_banner()
    print_target(args.domain, mode="subdomains")

    if not args.brute_only and args.brutemode != DEFAULT_BRUTE_MODE:
        console.print(
            "  [yellow]Note: --brutemode is ignored without --brute-only[/yellow]\n"
        )
    if args.brute_only:
        console.print(f"  [dim]Brute mode:[/dim] {args.brutemode}\n")

    scanner = SubdomainScanner(debug=args.debug)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("[cyan]Enumerating subdomains...", total=None)

        data = scanner.scan(
            args.domain,
            args.wordlist,
            args.threads,
            alive=args.alive,
            brutemode=args.brutemode,
            brute_only=args.brute_only,
        )

    results = data["alive"] if args.alive else data["subdomains"]

    wildcard_ips = data.get("wildcard_ips") or []
    if wildcard_ips:
        console.print(
            f"  [yellow]Wildcard DNS detected[/yellow] (*.{args.domain} -> "
            f"{', '.join(wildcard_ips)}); brute-force hits matching it were "
            "discarded.\n"
        )

    print_subdomain_table(results, alive=args.alive)
    print_total(len(results))

    exit_code = EXIT_OK

    if args.save:
        try:
            with open(args.save, "w") as fh:
                if args.alive:
                    fh.writelines(
                        f"{item['subdomain']} {item['status']} {item['title']}\n"
                        for item in results
                    )
                else:
                    fh.write("\n".join(results))
        except OSError as exc:
            console.print(f"  [red]Failed to save results:[/red] {exc}\n")
            exit_code = EXIT_FAILURE
        else:
            print_saved(args.save)

    return _report_exit(data, args.output, args.html_theme, failed=exit_code != EXIT_OK)


def _handle_dns(args: argparse.Namespace) -> int:
    """Run DNS enumeration and display results."""
    print_banner()
    print_target(args.domain, mode="dns")

    scanner = DNSScanner(debug=args.debug)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("[cyan]Resolving DNS records...", total=None)
        data = scanner.scan(args.domain)

    records = data["records"]

    if not records:
        console.print("  [red]No DNS records found.[/red]\n")
        return _report_exit(data, args.output, args.html_theme)

    print_dns_records(records)
    if not args.raw_only:
        print_dns_insights(data["analysis"])
        print_security_score(data["security_score"])

    return _report_exit(data, args.output, args.html_theme)


def _handle_ports(args: argparse.Namespace) -> int:
    """Run port scanning and display results."""
    print_banner()
    print_target(args.target, mode="ports")

    ports = None

    if args.top_100:
        ports = TOP_PORTS_100
    elif args.top_1000:
        ports = TOP_PORTS_1000
    elif args.full:
        ports = FULL_PORT_RANGE
    elif args.ports:
        ports = args.ports

    mode = "balanced"

    if args.fast:
        mode = "fast"
    elif args.deep:
        mode = "deep"

    scanner = PortScanner(debug=args.debug)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("[cyan]Scanning ports...", total=None)

        data = scanner.scan(
            args.target,
            ports=ports,
            threads=args.threads,
            mode=mode,
        )

    if data.get("error"):
        console.print(f"  [red]Port scan failed:[/red] {data['error']}\n")
        return _report_exit(data, args.output, args.html_theme, failed=True)

    if not data.get("open_ports"):
        console.print("  [red]No open ports found.[/red]\n")
        return _report_exit(data, args.output, args.html_theme)

    print_port_summary(data)
    print_port_table(data["open_ports"])
    if data.get("insights"):
        print_port_insights(data["insights"])

    return _report_exit(data, args.output, args.html_theme)


def _handle_tech(args: argparse.Namespace) -> int:
    """Run technology detection and display results."""
    print_banner()
    print_target(args.target, mode="tech")

    scanner = TechScanner(debug=args.debug)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("[cyan]Detecting technologies...", total=None)
            data = scanner.scan(args.target)
    except KeyboardInterrupt:
        console.print("\n  [yellow]Scan aborted by user (Ctrl+C).[/yellow]\n")
        return 130

    if data.get("error"):
        console.print(f"  [red]Technology scan failed:[/red] {data['error']}\n")
        return _report_exit(data, args.output, args.html_theme, failed=True)

    print_tech_summary(data)
    return _report_exit(data, args.output, args.html_theme)


def _handle_info(args: argparse.Namespace) -> int:
    """Run domain info lookup and display results."""
    print_banner()
    print_target(args.domain, mode="info")

    scanner = InfoScanner(debug=args.debug)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("[cyan]Gathering domain info...", total=None)

            data = scanner.scan(
                args.domain,
                skip_ssl=args.no_ssl,
                skip_whois=args.no_whois,
                brief=args.brief,
            )
    except KeyboardInterrupt:
        console.print("\n  [yellow]Scan aborted by user (Ctrl+C).[/yellow]\n")
        return 130

    if data.get("error"):
        console.print(f"  [red]Domain info failed:[/red] {data['error']}\n")
        return _report_exit(data, args.output, args.html_theme, failed=True)

    # Always show the main summary
    print_info_summary(data)

    if not args.brief:
        # Name servers
        ns = data.get("name_servers", [])
        if ns:
            print_info_nameservers(ns)

        # Registration status (EPP codes)
        status_explained = data.get("status_explained", [])
        if status_explained:
            print_info_status(status_explained)

        # SSL certificate
        print_info_ssl(data)

        # DNS SOA record
        print_info_soa(data)

    # Insights (always shown)
    if data.get("insights"):
        print_info_insights(data["insights"])

    return _report_exit(data, args.output, args.html_theme)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> int:
    """CLI entry point invoked by the ``domainspyder`` console script."""
    parser = _build_parser()
    args = parser.parse_args()

    # Configure logging
    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        # Suppress noisy library logs in debug mode
        for noisy in ("httpx", "urllib3", "httpcore", "chardet", "whois"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    # Dispatch
    handlers = {
        "subdomains": _handle_subdomains,
        "dns": _handle_dns,
        "ports": _handle_ports,
        "tech": _handle_tech,
        "info": _handle_info,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        console.print("\n  [yellow]Aborted by user.[/yellow]\n")
        raise SystemExit(130) from None


if __name__ == "__main__":
    raise SystemExit(main())
