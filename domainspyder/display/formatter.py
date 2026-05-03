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
# Technology output
# ---------------------------------------------------------------------------

def print_tech_summary(data: dict[str, Any]) -> None:
    """Render technology detection results."""
    _section_header("TECHNOLOGY DETECTION")

    console.print(f"  Target: [cyan]{data['target']}[/cyan]")
    if data.get("url"):
        console.print(f"  URL: [magenta]{data['url']}[/magenta]")
    if data.get("status") is not None:
        console.print(f"  Status: {color_status(data['status'])}")
    console.print()

    categories = data.get("categories", [])
    if not categories:
        console.print("  [yellow]No technologies confidently detected.[/yellow]\n")
        return

    category_width = max(len(item["category"]) for item in categories) + 2
    name_strs = []
    for item in categories:
        ver = item.get("version", "")
        name_strs.append(f"{item['name']} {ver}" if ver else item["name"])
    name_width = max(len(s) for s in name_strs) + 2

    for item, name_str in zip(categories, name_strs):
        color = themes.score_color(item["score"])
        console.print(
            "  "
            f"[bold white][{item['category']:<{category_width}}][/bold white] "
            f"[cyan]{name_str:<{name_width}}[/cyan] "
            f"[{color}]{item['meter']}[/{color}] "
            f"([{color}]{item['confidence']}[/{color}])"
        )

    other = data.get("other", [])
    if other:
        console.print()
        console.print("  [bold white]Other Technologies:[/bold white]")
        for item in other:
            console.print(f"    [magenta]+[/magenta] {item}")

    console.print()

# ---------------------------------------------------------------------------
# Domain info output
# ---------------------------------------------------------------------------

def print_info_summary(data: dict[str, Any]) -> None:
    """Render the main domain registration information panel."""
    _section_header("DOMAIN INFORMATION")

    domain = data.get("domain", "-")
    console.print(f"  Domain:       [cyan]{domain}[/cyan]")

    registrar = data.get("registrar")
    if registrar:
        console.print(f"  Registrar:    [yellow]{registrar}[/yellow]")

    # Creation date + age
    creation = data.get("creation_date")
    age = data.get("age", {})
    if creation:
        age_suffix = ""
        if age:
            age_suffix = (
                f"  [dim]({age.get('human', '')} — "
                f"{age.get('label', '')})[/dim]"
            )
        console.print(f"  Created:      [green]{creation}[/green]{age_suffix}")

    # Expiration date + days remaining
    expiration = data.get("expiration_date")
    expiry = data.get("expiry", {})
    if expiration:
        days_left = expiry.get("days_remaining")
        alert = expiry.get("alert")

        if alert == "CRITICAL":
            color = "red"
        elif alert == "WARNING":
            color = "yellow"
        else:
            color = "green"

        expiry_suffix = ""
        if days_left is not None:
            expiry_suffix = f"  [dim]({days_left} days remaining)[/dim]"

        console.print(
            f"  Expires:      [{color}]{expiration}[/{color}]{expiry_suffix}",
        )

    # Updated date
    updated = data.get("updated_date")
    if updated:
        console.print(f"  Updated:      [dim]{updated}[/dim]")

    # Organization / registrant
    registrant = data.get("registrant", {})
    if registrant:
        org = registrant.get("org", "")
        name = registrant.get("name", "")
        is_private = registrant.get("is_private", False)

        display_val = org or name or "-"
        privacy_tag = "  [dim][private][/dim]" if is_private else ""
        console.print(
            f"  Organization: [magenta]{display_val}[/magenta]{privacy_tag}",
        )

        country = registrant.get("country")
        if country:
            console.print(f"  Country:      [dim]{country}[/dim]")

    # DNSSEC
    dnssec = data.get("dnssec")
    if dnssec:
        dnssec_lower = dnssec.lower()
        if "signed" in dnssec_lower and "unsigned" not in dnssec_lower:
            console.print(f"  DNSSEC:       [green]{dnssec}[/green]")
        else:
            console.print(f"  DNSSEC:       [yellow]{dnssec}[/yellow]")

    # Sources metadata
    sources_used = data.get("sources_used", [])
    sources_failed = data.get("sources_failed", [])
    duration = data.get("duration")

    console.print()
    if sources_used:
        console.print(
            f"  Sources:      [dim]{', '.join(sources_used)}[/dim]",
        )
    if sources_failed:
        console.print(
            f"  Failed:       [red]{', '.join(sources_failed)}[/red]",
        )
    if duration is not None:
        console.print(f"  Duration:     [dim]{duration}s[/dim]")

    console.print()


def print_info_ssl(data: dict[str, Any]) -> None:
    """Render SSL certificate information section."""
    # Only render if SSL data is present
    has_ssl = any(k.startswith("ssl_") for k in data)
    if not has_ssl:
        return

    _section_header("SSL CERTIFICATE")

    issuer = data.get("ssl_issuer", "-")
    issuer_org = data.get("ssl_issuer_org")
    if issuer_org and issuer_org != issuer:
        console.print(
            f"  Issuer:       [cyan]{issuer}[/cyan]"
            f"  [dim]({issuer_org})[/dim]",
        )
    else:
        console.print(f"  Issuer:       [cyan]{issuer}[/cyan]")

    subject = data.get("ssl_subject")
    if subject:
        console.print(f"  Subject:      [dim]{subject}[/dim]")

    valid_from = data.get("ssl_valid_from")
    if valid_from:
        console.print(f"  Valid From:   [green]{valid_from}[/green]")

    valid_until = data.get("ssl_valid_until")
    ssl_days = data.get("ssl_days_remaining")
    if valid_until:
        if ssl_days is not None:
            if ssl_days <= 7:
                color = "red"
            elif ssl_days <= 30:
                color = "yellow"
            else:
                color = "green"
            console.print(
                f"  Valid Until:  [{color}]{valid_until}[/{color}]"
                f"  [dim]({ssl_days} days remaining)[/dim]",
            )
        else:
            console.print(f"  Valid Until:  {valid_until}")

    san_list = data.get("ssl_san", [])
    if san_list:
        # Show first few SANs inline, rest as count
        display_sans = san_list[:5]
        console.print(
            f"  SANs:         [dim]{', '.join(display_sans)}[/dim]",
        )
        if len(san_list) > 5:
            console.print(
                f"                [dim]... and {len(san_list) - 5} more[/dim]",
            )

    console.print()


def print_info_soa(data: dict[str, Any]) -> None:
    """Render DNS SOA record section."""
    # Only render if SOA data is present
    has_soa = any(k.startswith("soa_") for k in data)
    if not has_soa:
        return

    _section_header("DNS SOA RECORD")

    primary_ns = data.get("soa_primary_ns")
    if primary_ns:
        console.print(f"  Primary NS:   [cyan]{primary_ns}[/cyan]")

    admin = data.get("soa_admin")
    if admin:
        console.print(f"  Admin:        [dim]{admin}[/dim]")

    serial = data.get("soa_serial")
    if serial is not None:
        console.print(f"  Serial:       [dim]{serial}[/dim]")

    refresh = data.get("soa_refresh")
    if refresh is not None:
        console.print(
            f"  Refresh:      [dim]{refresh}s"
            f" ({_seconds_to_human(refresh)})[/dim]",
        )

    retry = data.get("soa_retry")
    if retry is not None:
        console.print(
            f"  Retry:        [dim]{retry}s"
            f" ({_seconds_to_human(retry)})[/dim]",
        )

    expire = data.get("soa_expire")
    if expire is not None:
        console.print(
            f"  Expire:       [dim]{expire}s"
            f" ({_seconds_to_human(expire)})[/dim]",
        )

    min_ttl = data.get("soa_min_ttl")
    if min_ttl is not None:
        console.print(
            f"  Min TTL:      [dim]{min_ttl}s"
            f" ({_seconds_to_human(min_ttl)})[/dim]",
        )

    console.print()


def print_info_nameservers(name_servers: list[str]) -> None:
    """Render name server list."""
    if not name_servers:
        return

    _section_header("NAME SERVERS")

    for ns in name_servers:
        console.print(f"    [cyan]+[/cyan]  [cyan]{ns}[/cyan]")

    console.print()


def print_info_status(status_explained: list[dict[str, str]]) -> None:
    """Render EPP status codes with human-readable meanings."""
    if not status_explained:
        return

    _section_header("REGISTRATION STATUS")

    for item in status_explained:
        code = item.get("code", "-")
        meaning = item.get("meaning", "-")

        # Color based on severity
        code_lower = code.lower()
        if "hold" in code_lower or "pending" in code_lower:
            console.print(
                f"    [red]![/red]  [red]{code}[/red]"
                f"  [dim]— {meaning}[/dim]",
            )
        elif "prohibited" in code_lower:
            console.print(
                f"    [yellow]~[/yellow]  [yellow]{code}[/yellow]"
                f"  [dim]— {meaning}[/dim]",
            )
        else:
            console.print(
                f"    [green]+[/green]  [green]{code}[/green]"
                f"  [dim]— {meaning}[/dim]",
            )

    console.print()


def print_info_insights(insights: list[str]) -> None:
    """Render domain analysis insights."""
    _section_header("DOMAIN INSIGHTS")

    if not insights:
        console.print("    [dim]- No notable findings[/dim]\n")
        return

    for insight in insights:
        if "[CRITICAL]" in insight:
            clean = insight.replace("[CRITICAL] ", "")
            console.print(f"    [bold red]![/bold red]  [red]{clean}[/red]")

        elif "[WARNING]" in insight:
            clean = insight.replace("[WARNING] ", "")
            console.print(
                f"    [yellow]![/yellow]  [yellow]{clean}[/yellow]",
            )

        elif "[INFO]" in insight:
            clean = insight.replace("[INFO] ", "")
            console.print(f"    [green]+[/green]  [green]{clean}[/green]")

        else:
            console.print(f"    [dim]-[/dim]  {insight}")

    console.print()


def _seconds_to_human(seconds: int) -> str:
    """Convert seconds to a compact human-readable string."""
    if seconds >= 86400:
        days = seconds // 86400
        return f"{days}d"
    if seconds >= 3600:
        hours = seconds // 3600
        return f"{hours}h"
    if seconds >= 60:
        minutes = seconds // 60
        return f"{minutes}m"
    return f"{seconds}s"


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

