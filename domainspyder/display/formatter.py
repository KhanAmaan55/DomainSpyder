"""
DomainSpyder output formatter.

All Rich-based terminal rendering lives here so that scanners
and the CLI stay free of presentation logic.
"""

from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from domainspyder.display import themes


# ---------------------------------------------------------------------------
# Shared console instance
# ---------------------------------------------------------------------------

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section_header(title: str, *, style: str = themes.SUBHEADING) -> None:
    """Print a styled section header with box-drawing separators."""
    width = 60
    border = Text(f"  {'─' * width}", style=themes.SEPARATOR)
    heading = Text(f"  {title}", style=style)
    console.print()
    console.print(border, highlight=False)
    console.print(heading, highlight=False)
    console.print(border, highlight=False)
    console.print()


def color_status(status_code: int) -> str:
    """Return a Rich-markup-wrapped HTTP status code."""
    if 200 <= status_code < 300:
        return f"[green]{status_code}[/green]"
    if 300 <= status_code < 400:
        return f"[cyan]{status_code}[/cyan]"
    if 400 <= status_code < 500:
        return f"[yellow]{status_code}[/yellow]"
    return f"[red]{status_code}[/red]"


# ---------------------------------------------------------------------------
# Target info
# ---------------------------------------------------------------------------

def print_target(domain: str, mode: str = "") -> None:
    """Print the target domain line."""
    line = Text()
    line.append("  TARGET ", style="bold white on cyan")
    line.append(f"  {domain}", style="bold cyan")
    if mode:
        line.append(f"  ({mode})", style="dim")
    console.print(line, highlight=False)
    console.print()


# ---------------------------------------------------------------------------
# Subdomain output
# ---------------------------------------------------------------------------

def print_subdomain_table(
    results: list[Any],
    *,
    alive: bool = False,
) -> None:
    """Render discovered subdomains as a Rich table."""
    if alive:
        table = Table(
            title="Alive Subdomains",
            box=box.ROUNDED,
            border_style=themes.TABLE_BORDER,
            title_style=themes.HEADING,
            header_style=themes.TABLE_HEADER,
            pad_edge=True,
            expand=False,
        )
        table.add_column("#", style=themes.MUTED, justify="right", width=5)
        table.add_column("Subdomain", style=themes.ACCENT_DIM, min_width=30)
        table.add_column("Status", justify="center", width=8)
        table.add_column("Server", style="magenta", min_width=15)
        table.add_column("Title", style=themes.WARNING_DIM, max_width=50)

        for idx, item in enumerate(results, 1):
            table.add_row(
                str(idx),
                item["subdomain"],
                color_status(item["status"]),
                item["server"],
                item["title"],
            )
    else:
        table = Table(
            title="Discovered Subdomains",
            box=box.ROUNDED,
            border_style=themes.TABLE_BORDER,
            title_style=themes.HEADING,
            header_style=themes.TABLE_HEADER,
            pad_edge=True,
            expand=False,
        )
        table.add_column("#", style=themes.MUTED, justify="right", width=5)
        table.add_column("Subdomain", style=themes.ACCENT_DIM, min_width=40)

        for idx, sub in enumerate(results, 1):
            table.add_row(str(idx), sub)

    console.print()
    console.print(table)
    console.print()


def print_total(count: int) -> None:
    """Print the total results count."""
    line = Text()
    line.append("  TOTAL ", style="bold white on green")
    line.append(f"  {count} result(s) found", style="bold green")
    console.print(line, highlight=False)
    console.print()


# ---------------------------------------------------------------------------
# DNS output
# ---------------------------------------------------------------------------

def print_security_score(security: dict) -> None:
    """Render the DNS security score panel."""
    _section_header("SECURITY SUMMARY")

    score = security["score"]
    color = themes.score_color(score)

    # Score bar
    filled = score
    empty = 10 - score
    bar = Text()
    bar.append("  Score: ", style="bold white")
    bar.append("[" + "█" * filled, style=f"bold {color}")
    bar.append("░" * empty + "]", style="dim")
    bar.append(f"  {score}/10", style=f"bold {color}")
    bar.append(f"  {security['risk']}", style=f"{color}")
    console.print(bar, highlight=False)
    console.print()

    if security["issues"]:
        console.print("  [bold red]Issues:[/bold red]")
        for issue in security["issues"]:
            console.print(f"    [red]x[/red]  {issue}")
        console.print()

    if security["good"]:
        console.print("  [bold green]Passed:[/bold green]")
        for item in security["good"]:
            console.print(f"    [green]+[/green]  {item}")
        console.print()


def print_dns_insights(insights: list[str]) -> None:
    """Render DNS analysis insights."""
    _section_header("DNS INSIGHTS")

    for insight in insights:
        # Determine severity by tags embedded in the insight string
        if "[WARNING]" in insight:
            clean = insight.replace("[WARNING] ", "")
            console.print(f"    [red]![/red]  [red]{clean}[/red]")
        elif "[INFO]" in insight:
            clean = insight.replace("[INFO] ", "")
            console.print(f"    [yellow]~[/yellow]  [yellow]{clean}[/yellow]")
        else:
            console.print(f"    [green]+[/green]  [green]{insight}[/green]")

    console.print()


def print_dns_records(records: dict[str, list[str]]) -> None:
    """Render raw DNS records grouped by type."""
    _section_header("RAW DNS RECORDS")

    for record_type, values in records.items():
        console.print(f"  [bold cyan][{record_type}][/bold cyan]")

        for val in sorted(values):
            # Skip noisy verification TXT records
            if record_type == "TXT" and any(
                tag in val
                for tag in [
                    "google-site-verification",
                    "ms=",
                    "facebook-domain-verification",
                ]
            ):
                continue

            label = ""
            if record_type == "MX" and "google" in val.lower():
                label = "  (Google Workspace)"

            console.print(f"    {val}[dim]{label}[/dim]")

        console.print()


# ---------------------------------------------------------------------------
# File save confirmation
# ---------------------------------------------------------------------------

def print_saved(filepath: str) -> None:
    """Print a confirmation that results were saved."""
    line = Text()
    line.append("  SAVED ", style="bold white on magenta")
    line.append(f"  {filepath}", style="magenta")
    console.print(line, highlight=False)
    console.print()
