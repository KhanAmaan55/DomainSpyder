import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
import warnings
import logging
from .core.subdomain import enumerate_domain

console = Console()
warnings.simplefilter("ignore")

def banner():
    console.print("""
[bold cyan]
╔══════════════════════════════════════╗
║       🕷️ DomainSpyder v1.0            ║
║     Domain Intelligence Framework    ║
╚══════════════════════════════════════╝
[/bold cyan]
""")

def handle_subdomains(args):
    banner()
    console.print(f"[green][+][/green] Target: [cyan]{args.domain}[/cyan]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:

        task = progress.add_task("[yellow]Enumerating subdomains...", total=None)

        subs = enumerate_domain(
            args.domain,
            args.wordlist,
            args.threads,
            debug=args.debug,
            alive=args.alive
        )

        progress.update(task, completed=1)

    table = Table(title="Discovered Subdomains", box=box.DOUBLE)
    table.add_column("#", style="dim")
    table.add_column("Subdomain", style="cyan")

    for i, sub in enumerate(subs, 1):
        table.add_row(str(i), sub)

    console.print(table)
    console.print(f"\n[bold green]Total Found:[/bold green] {len(subs)}\n")

    if args.save:
        with open(args.save, "w") as f:
            f.write("\n".join(subs))
        console.print(f"[blue]Saved to {args.save}[/blue]")


def main():
    parser = argparse.ArgumentParser(
        description="🕷️ DomainSpyder - Domain Intelligence Framework"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging globally"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    sub_parser = subparsers.add_parser(
        "subdomains",
        help="Subdomain enumeration"
    )
    sub_parser.add_argument("domain", help="Target domain")
    sub_parser.add_argument(
        "--wordlist",
        default="wordlists/default.txt",
        help="Path to wordlist"
    )
    sub_parser.add_argument(
        "--save",
        help="Save results to file"
    )
    sub_parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of threads (default: 50)"
    )
    sub_parser.add_argument(
        "--alive",
        action="store_true",
        help="Show only alive subdomains"
    )

    args = parser.parse_args()
    
    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(levelname)s] %(message)s"
        )
    else:
        logging.basicConfig(level=logging.CRITICAL)
        
    if args.command == "subdomains":
        handle_subdomains(args)


if __name__ == "__main__":
    main()