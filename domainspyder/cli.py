"""
DomainSpyder CLI entry point.

Handles argument parsing and dispatches to the appropriate
scanner + formatter.  All presentation logic lives in
``domainspyder.display``.
"""

from __future__ import annotations

import argparse
import logging
import warnings
from concurrent.futures import ThreadPoolExecutor

from domainspyder.config import (
    APP_NAME,
    DEFAULT_BRUTE_MODE,
    DEFAULT_THREADS,
    DEFAULT_WORDLIST,
    DESCRIPTION,
    VERSION,
    TOP_PORTS_100,
    TOP_PORTS_1000,
    FULL_PORT_RANGE
)
from domainspyder.display.banner import print_banner
from domainspyder.display.formatter import (
    console,
    print_dns_insights,
    print_dns_records,
    print_saved,
    print_security_score,
    print_subdomain_table,
    print_target,
    print_total,
    print_port_table,
    print_port_summary,
    print_port_insights
)
from domainspyder.scanners.dns_scanner import DNSScanner
from domainspyder.scanners.subdomain_scanner import SubdomainScanner
from domainspyder.scanners.port_scanner import PortScanner

from rich.progress import Progress, SpinnerColumn, TextColumn

warnings.simplefilter("ignore")


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
        "--debug",
        action="store_true",
        help="Enable debug logging globally",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- subdomains command ------------------------------------------
    sub = subparsers.add_parser("subdomains", help="Subdomain enumeration")
    sub.add_argument("domain", help="Target domain")
    sub.add_argument(
        "--wordlist",
        default=DEFAULT_WORDLIST,
        help=f"Path to wordlist (default: {DEFAULT_WORDLIST})",
    )
    sub.add_argument("--save", help="Save results to file")
    sub.add_argument(
        "--threads",
        type=int,
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
    dns_cmd.add_argument("domain", help="Target domain")
    dns_cmd.add_argument(
        "--raw-only",
        action="store_true",
        help="Show raw DNS records without analysis",
    )

    # ---- ports command -------------------------------------------------
    ports_cmd = subparsers.add_parser("ports", help="Port scanning")
    ports_cmd.add_argument("target", help="Target domain")
    ports_cmd.add_argument("--ports", help="Custom ports (comma-separated)")
    ports_cmd.add_argument("--top-100", action="store_true")
    ports_cmd.add_argument("--top-1000", action="store_true")
    ports_cmd.add_argument("--full", action="store_true")
    ports_cmd.add_argument("--fast", action="store_true", help="Fast scan mode")
    ports_cmd.add_argument("--deep", action="store_true", help="Deep scan mode")
    ports_cmd.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of threads (default: 50)",
    )

    return parser


# ------------------------------------------------------------------
# Command handlers
# ------------------------------------------------------------------


def _handle_subdomains(args: argparse.Namespace) -> None:
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

        results = scanner.scan(
            args.domain,
            args.wordlist,
            args.threads,
            alive=args.alive,
            brutemode=args.brutemode,
            brute_only=args.brute_only,
        )

    print_subdomain_table(results, alive=args.alive)
    print_total(len(results))

    if args.save:
        with open(args.save, "w") as fh:
            if args.alive:
                for item in results:
                    fh.write(
                        f"{item['subdomain']} {item['status']} {item['title']}\n"
                    )
            else:
                fh.write("\n".join(results))
        print_saved(args.save)


def _handle_dns(args: argparse.Namespace) -> None:
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
        records = scanner.scan(args.domain)
        with ThreadPoolExecutor() as executor:
            data = scanner.preprocess(records)
        
            f1 = executor.submit(scanner.analyze, records, args.domain, data)
            f2 = executor.submit(scanner.calculate_security, records, args.domain, data)
        
            if not args.raw_only:
                insights = f1.result()
                security = f2.result()
            

    if not records:
        console.print("  [red]No DNS records found.[/red]\n")
        return

    print_dns_records(records)
    if not args.raw_only:
        print_dns_insights(insights)
        print_security_score(security)

def _handle_ports(args: argparse.Namespace) -> None:
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
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            console.print("[red]Invalid port list format.[/red]")
            return
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

    if not data or not data.get("open_ports"):
        console.print("  [red]No open ports found.[/red]\n")
        return

    insights = scanner.analyze(data)
    
    print_port_summary(data)
    print_port_table(data["open_ports"])
    if insights:
        print_port_insights(insights)

# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """CLI entry point invoked by the ``domainspyder`` console script."""
    parser = _build_parser()
    args = parser.parse_args()

    # Configure logging
    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(levelname)s] %(name)s: %(message)s",
        )
    else:
        logging.basicConfig(level=logging.CRITICAL)

    # Dispatch
    handlers = {
        "subdomains": _handle_subdomains,
        "dns": _handle_dns,
        "ports": _handle_ports,
    }
    handler = handlers.get(args.command)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()