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
# Port output
# ---------------------------------------------------------------------------
def print_port_summary(data: dict) -> None:
    _section_header("PORT SCAN SUMMARY")

    console.print(f"  Target: [cyan]{data['target']}[/cyan] ({data['ip']})")
    if data.get("provider"):
        console.print(f"  Provider: [yellow]{data['provider']}[/yellow]")

    if data.get("reverse_dns") and data["reverse_dns"] != "-":
        console.print(f"  Reverse DNS: [magenta]{data['reverse_dns']}[/magenta]")

    console.print(f"  Ports Scanned: {data['ports_scanned']}")
    console.print(f"  Open Ports: [green]{data['open_count']}[/green]")
    console.print(f"  Closed: [dim]{data['closed_count']}[/dim]")
    console.print(f"  Duration: {data['duration']}s\n")

def print_port_table(results: list[dict[str, Any]]) -> None:
    """Render open ports as a Rich table."""
    if not results:
        console.print("  [red]No open ports found.[/red]\n")
        return

    table = Table(
        title="Open Ports",
        box=box.ROUNDED,
        border_style=themes.TABLE_BORDER,
        title_style=themes.HEADING,
        header_style=themes.TABLE_HEADER,
    )

    table.add_column("#", style=themes.MUTED, justify="right", width=5)
    table.add_column("Port", style="cyan", justify="right", width=8)
    table.add_column("State", justify="center", width=10)
    table.add_column("Service", style="magenta", min_width=12)
    table.add_column("Banner", style=themes.WARNING_DIM, max_width=50)

    for idx, item in enumerate(results, 1):
        table.add_row(
            str(idx),
            str(item.get("port", "-")),
            _color_port_state(item.get("state", "unknown")),
            item.get("service", "-"),
            item.get("banner", "-"),
        )

    console.print()
    console.print(table)
    console.print()

def print_port_insights(insights: list[str]) -> None:
    _section_header("PORT INSIGHTS")

    if not insights:
        console.print("    [dim]- No notable exposure detected[/dim]\n")
        return

    for insight in insights:
        if "[CRITICAL]" in insight:
            clean = insight.replace("[CRITICAL] ", "")
            console.print(f"    [bold red]![/bold red]  [red]{clean}[/red]")

        elif "[WARNING]" in insight:
            clean = insight.replace("[WARNING] ", "")
            console.print(f"    [yellow]![/yellow]  [yellow]{clean}[/yellow]")

        elif "[INFO]" in insight:
            clean = insight.replace("[INFO] ", "")
            console.print(f"    [green]+[/green]  [green]{clean}[/green]")

        else:
            console.print(f"    [dim]-[/dim]  {insight}")

    console.print()

def _color_port_state(state: str) -> str:
    """Colorize port state."""
    if state == "open":
        return "[green]open[/green]"
    return "[red]closed[/red]"

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
