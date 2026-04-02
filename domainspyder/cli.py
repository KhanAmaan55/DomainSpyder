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
)
from domainspyder.scanners.dns_scanner import DNSScanner
from domainspyder.scanners.subdomain_scanner import SubdomainScanner

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
    }
    handler = handlers.get(args.command)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()