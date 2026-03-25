import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
import warnings
from .core import enumerate_domain

console = Console()
warnings.simplefilter("ignore")

def banner():
    console.print("""
[bold cyan]
╔══════════════════════════════════════╗
║      🕷️ DomainSpyder v1.0           ║
║   Subdomain Enumeration Toolkit     ║
╚══════════════════════════════════════╝
[/bold cyan]
""")

def main():
    parser = argparse.ArgumentParser(
        description="🕷️ DomainSpyder - Subdomain Enumeration Tool"
    )

    parser.add_argument("domain", help="Target domain")
    parser.add_argument(
        "--wordlist",
        default="wordlists/default.txt",
        help="Path to wordlist"
    )
    parser.add_argument(
        "--save",
        help="Save results to file"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Number of threads (default: 20)"
    )

    args = parser.parse_args()

    banner()
    console.print(f"[green][+][/green] Target: [cyan]{args.domain}[/cyan]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:

        task = progress.add_task("[yellow]Enumerating subdomains...", total=None)
        subs = enumerate_domain(args.domain, args.wordlist, args.threads)
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