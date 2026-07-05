"""Standalone HTML report exporter."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any


HTML_THEMES = ("light", "dark")


class HtmlExporter:
    """Render structured scan results as a branded, self-contained HTML document."""

    _logo_data_uri: str | None = None
    _logo_loaded = False

    def __init__(self, theme: str = "light") -> None:
        normalized_theme = theme.strip().lower()
        if normalized_theme not in HTML_THEMES:
            supported = ", ".join(HTML_THEMES)
            raise ValueError(
                f"Unsupported HTML theme '{theme}'. Supported themes: {supported}"
            )
        self.theme = normalized_theme

    def render(self, data: dict[str, Any]) -> str:
        """Return a responsive standalone HTML report for *data*."""
        from domainspyder.reporting.exporter import report_metadata

        metadata = report_metadata()
        command = str(data.get("command", "scan")).title()
        target = str(data.get("target") or data.get("domain") or "-")
        generated_at = metadata["generated_at"]
        generated_at_display = self._friendly_datetime(generated_at)
        theme_label = f"{self.theme.title()} mode"

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DomainSpyder {escape(command)} Report - {escape(target)}</title>
  <style>
    :root {{
      color-scheme: light;
      --palette-purple: #5c39a2;
      --palette-cloud: #f4f3f8;
      --palette-ink: #0c182d;
      --palette-lavender: #a190cb;
      --palette-slate: #686f80;
      --palette-midnight: #242054;
      --palette-mist: #c9bfe1;
      --palette-violet: #4123a2;

      --page-bg: var(--palette-cloud);
      --surface: #ffffff;
      --surface-soft: rgba(244, 243, 248, 0.78);
      --text: var(--palette-ink);
      --muted: var(--palette-slate);
      --line: rgba(201, 191, 225, 0.78);
      --brand: var(--palette-purple);
      --brand-strong: var(--palette-violet);
      --brand-deep: var(--palette-midnight);
      --accent: var(--palette-lavender);
      --hero-text: #ffffff;
      --hero-muted: rgba(244, 243, 248, 0.82);
      --table-head: rgba(244, 243, 248, 0.92);
      --table-hover: rgba(201, 191, 225, 0.18);
      --shadow: 0 18px 45px rgba(12, 24, 45, 0.09);
      --panel-shadow: 0 1px 2px rgba(12, 24, 45, 0.08);
    }}

    body.theme-dark {{
      color-scheme: dark;
      --page-bg: var(--palette-ink);
      --surface: #151a33;
      --surface-soft: rgba(36, 32, 84, 0.68);
      --text: var(--palette-cloud);
      --muted: var(--palette-mist);
      --line: rgba(201, 191, 225, 0.24);
      --brand: var(--palette-lavender);
      --brand-strong: var(--palette-purple);
      --brand-deep: var(--palette-midnight);
      --accent: var(--palette-mist);
      --hero-text: var(--palette-cloud);
      --hero-muted: rgba(244, 243, 248, 0.72);
      --table-head: rgba(36, 32, 84, 0.78);
      --table-hover: rgba(161, 144, 203, 0.12);
      --shadow: 0 20px 50px rgba(0, 0, 0, 0.34);
      --panel-shadow: 0 1px 2px rgba(0, 0, 0, 0.28);
    }}

    * {{ box-sizing: border-box; }}

    html {{ scroll-behavior: smooth; }}

    body {{
      margin: 0;
      background:
        linear-gradient(180deg, rgba(201, 191, 225, 0.22), rgba(244, 243, 248, 0) 320px),
        var(--page-bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system,
        BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}

    body.theme-dark {{
      background:
        linear-gradient(180deg, rgba(92, 57, 162, 0.28), rgba(12, 24, 45, 0) 340px),
        var(--page-bg);
    }}

    .report-shell {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
    }}

    .report-header {{
      background:
        linear-gradient(
          135deg,
          rgba(12, 24, 45, 0.98),
          rgba(36, 32, 84, 0.96) 56%,
          rgba(92, 57, 162, 0.96)
        );
      color: var(--hero-text);
      border-bottom: 1px solid rgba(201, 191, 225, 0.26);
      box-shadow: var(--shadow);
    }}

    .topbar {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      padding: 22px 0 10px;
    }}

    .brand-lockup {{
      display: inline-flex;
      align-items: center;
      min-width: 0;
      padding: 8px 16px;
      border-radius: 10px;
      background: #ffffff;
      box-shadow: 0 6px 18px rgba(12, 24, 45, 0.18);
    }}

    /* The logo has a transparent background, so a light chip lets the dark
       "DOMAIN" wordmark read while the purple glow keeps its color. The asset
       is a ~5:1 banner with transparent padding, so cover-crop the content
       band (vertically centred at ~48%) rather than letterboxing it. */
    .brand-logo {{
      display: block;
      width: min(232px, 52vw);
      height: 46px;
      object-fit: cover;
      object-position: center 48%;
    }}

    .brand-wordmark {{
      display: inline-flex;
      align-items: center;
      min-height: 48px;
      color: var(--hero-text);
      font-size: 22px;
      font-weight: 800;
    }}

    .theme-chip {{
      flex: 0 0 auto;
      border: 1px solid rgba(244, 243, 248, 0.36);
      background: rgba(244, 243, 248, 0.11);
      color: var(--hero-text);
      border-radius: 999px;
      padding: 7px 12px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0;
    }}

    .hero-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(280px, 420px);
      gap: 28px;
      align-items: end;
      padding: 18px 0 34px;
    }}

    .eyebrow {{
      margin: 0 0 8px;
      color: var(--hero-muted);
      font-size: 13px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
    }}

    h1 {{
      margin: 0;
      font-size: clamp(34px, 5vw, 58px);
      line-height: 1.02;
      letter-spacing: 0;
    }}

    .target-line {{
      margin: 14px 0 0;
      color: var(--hero-muted);
      font-size: clamp(16px, 2vw, 20px);
      overflow-wrap: anywhere;
    }}

    .metadata {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 1px;
      margin: 0;
      overflow: hidden;
      border: 1px solid rgba(244, 243, 248, 0.22);
      border-radius: 8px;
      background: rgba(244, 243, 248, 0.16);
    }}

    .metadata div {{
      display: grid;
      grid-template-columns: 112px minmax(0, 1fr);
      gap: 12px;
      padding: 12px 14px;
      background: rgba(12, 24, 45, 0.18);
    }}

    .metadata dt {{
      color: var(--hero-muted);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
    }}

    .metadata dd {{
      margin: 0;
      color: var(--hero-text);
      font-size: 13px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }}

    main.report-shell {{
      padding: 24px 0 48px;
    }}

    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(178px, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }}

    .summary-card {{
      min-height: 104px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--panel-shadow);
    }}

    .summary-label {{
      margin: 0 0 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
    }}

    .summary-value {{
      margin: 0;
      color: var(--text);
      font-size: 24px;
      font-weight: 800;
      line-height: 1.18;
      overflow-wrap: anywhere;
    }}

    .report-section {{
      margin-top: 16px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--panel-shadow);
    }}

    .section-heading {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 14px;
    }}

    h2 {{
      margin: 0;
      color: var(--text);
      font-size: 20px;
      line-height: 1.2;
      letter-spacing: 0;
    }}

    h3 {{
      margin: 18px 0 8px;
      color: var(--text);
      font-size: 15px;
      line-height: 1.3;
      letter-spacing: 0;
    }}

    .section-count {{
      flex: 0 0 auto;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--surface-soft);
      color: var(--brand);
      padding: 4px 10px;
      font-size: 12px;
      font-weight: 800;
    }}

    .table-scroll {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }}

    table {{
      width: 100%;
      min-width: 620px;
      border-collapse: collapse;
    }}

    th, td {{
      padding: 11px 13px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}

    th {{
      color: var(--muted);
      background: var(--table-head);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
    }}

    tbody tr:hover {{
      background: var(--table-hover);
    }}

    tbody tr:last-child td {{
      border-bottom: 0;
    }}

    td:first-child {{
      color: var(--brand);
      font-weight: 800;
    }}

    code, pre {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }}

    pre {{
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      color: var(--text);
      background: var(--surface-soft);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 13px;
      font-size: 13px;
      line-height: 1.55;
    }}

    .inline-pre {{
      max-height: 260px;
      overflow: auto;
    }}

    .clean-list {{
      display: grid;
      gap: 8px;
      margin: 0;
      padding-left: 19px;
    }}

    .clean-list li {{
      padding-left: 3px;
    }}

    .muted {{
      color: var(--muted);
    }}

    .pill {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--surface-soft);
      color: var(--brand);
      padding: 2px 9px;
      font-size: 12px;
      font-weight: 800;
    }}

    .score-layout {{
      display: grid;
      grid-template-columns: minmax(220px, 380px) minmax(0, 1fr);
      gap: 22px;
      align-items: start;
    }}

    .score-value {{
      display: flex;
      align-items: baseline;
      gap: 8px;
      margin-bottom: 12px;
    }}

    .score-value strong {{
      color: var(--brand);
      font-size: 32px;
      line-height: 1;
    }}

    .score-bar {{
      height: 16px;
      overflow: hidden;
      border-radius: 999px;
      background: var(--surface-soft);
      border: 1px solid var(--line);
    }}

    .score-fill {{
      height: 100%;
      width: var(--score-width);
      background: var(--score-color);
    }}

    .score-notes {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }}

    details {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface-soft);
      overflow: hidden;
    }}

    summary {{
      cursor: pointer;
      padding: 12px 14px;
      color: var(--brand);
      font-weight: 800;
    }}

    details pre {{
      border: 0;
      border-top: 1px solid var(--line);
      border-radius: 0;
      background: transparent;
    }}

    @media (max-width: 820px) {{
      .hero-grid,
      .score-layout,
      .score-notes {{
        grid-template-columns: 1fr;
      }}

      .metadata {{
        max-width: none;
      }}
    }}

    @media (max-width: 640px) {{
      .report-shell {{
        width: calc(100% - 24px);
      }}

      .topbar {{
        align-items: stretch;
        flex-direction: column;
        gap: 10px;
        padding-top: 16px;
      }}

      .brand-logo {{
        width: min(196px, 66vw);
        height: 40px;
      }}

      .theme-chip {{
        width: fit-content;
      }}

      .hero-grid {{
        gap: 18px;
        padding: 8px 0 24px;
      }}

      .metadata div {{
        grid-template-columns: 1fr;
        gap: 3px;
      }}

      main.report-shell {{
        padding-top: 16px;
      }}

      .summary-grid {{
        grid-template-columns: 1fr;
      }}

      .summary-card,
      .report-section {{
        padding: 14px;
      }}

      .section-heading {{
        align-items: flex-start;
        flex-direction: column;
        gap: 8px;
      }}

      .summary-value {{
        font-size: 21px;
      }}
    }}
  </style>
</head>
<body class="theme-{escape(self.theme)}">
  <header class="report-header">
    <div class="report-shell">
      <div class="topbar">
        <div class="brand-lockup">{self._logo_markup()}</div>
        <div class="theme-chip">{escape(theme_label)}</div>
      </div>
      <div class="hero-grid">
        <div>
          <p class="eyebrow">Structured scan export</p>
          <h1>{escape(command)} Report</h1>
          <p class="target-line">{escape(target)}</p>
        </div>
        <dl class="metadata">
          <div>
            <dt>Generated</dt>
            <dd title="{escape(generated_at)}">{escape(generated_at_display)}</dd>
          </div>
          <div><dt>Tool</dt><dd>DomainSpyder {escape(metadata["version"])}</dd></div>
          <div><dt>Command</dt><dd>{escape(str(data.get("command", "-")))}</dd></div>
        </dl>
      </div>
    </div>
  </header>
  <main class="report-shell">
    {self._summary_cards(data)}
    {self._command_sections(data)}
    {self._raw_data(data)}
  </main>
</body>
</html>
"""

    def _summary_cards(self, data: dict[str, Any]) -> str:
        cards = [
            ("Command", str(data.get("command", "-"))),
            ("Target", str(data.get("target") or data.get("domain") or "-")),
            ("Scan Timestamp", self._friendly_datetime(str(data.get("timestamp", "-")))),
        ]
        command = data.get("command")
        if command == "subdomains":
            cards.append(("Subdomains", str(data.get("count", 0))))
            cards.append(("Alive", str(len(data.get("alive", [])))))
        elif command == "dns":
            records = data.get("records", {})
            cards.append(("Record Types", str(len(records))))
            cards.append(("Security Score", self._score_text(data.get("security_score", {}))))
        elif command == "ports":
            cards.append(("Ports Scanned", str(data.get("ports_scanned", 0))))
            open_count = data.get("open_count", len(data.get("open_ports", [])))
            cards.append(("Open Ports", str(open_count)))
        elif command == "tech":
            tech_count = len(data.get("technologies", data.get("categories", [])))
            cards.append(("Technologies", str(tech_count)))
            cards.append(("HTTP Status", str(data.get("status", "-"))))
        elif command == "info":
            cards.append(("Registrar", str(data.get("registrar", "-"))))
            cards.append(("Sources Used", str(len(data.get("sources_used", [])))))

        items = "\n".join(
            f'<article class="summary-card"><p class="summary-label">{escape(label)}</p>'
            f'<p class="summary-value">{escape(value)}</p></article>'
            for label, value in cards
        )
        return f'<section class="summary-grid" aria-label="Report summary">{items}</section>'

    def _command_sections(self, data: dict[str, Any]) -> str:
        command = data.get("command")
        if command == "dns":
            return self._dns_sections(data)
        if command == "ports":
            return self._ports_sections(data)
        if command == "tech":
            return self._tech_sections(data)
        if command == "info":
            return self._info_sections(data)
        if command == "subdomains":
            return self._subdomain_sections(data)
        return ""

    def _dns_sections(self, data: dict[str, Any]) -> str:
        rows = []
        for record_type, values in data.get("records", {}).items():
            rows.append((record_type, "<br>".join(escape(str(v)) for v in values)))
        sections = [
            self._table("DNS Records", ["Type", "Values"], rows),
            self._list_section("DNS Insights", data.get("analysis", [])),
            self._security_score(data.get("security_score", {})),
        ]
        return "".join(sections)

    def _ports_sections(self, data: dict[str, Any]) -> str:
        rows = [
            (
                str(item.get("port", "-")),
                str(item.get("state", "-")),
                str(item.get("service", "-")),
                str(item.get("banner", "-")),
            )
            for item in data.get("open_ports", [])
        ]
        details = [
            ("IP", data.get("ip", "-")),
            ("Provider", data.get("provider", "-")),
            ("Reverse DNS", data.get("reverse_dns", "-")),
            ("Duration", f"{data.get('duration', '-')}s"),
        ]
        return (
            self._table("Port Scan Details", ["Field", "Value"], details)
            + self._table("Open Ports", ["Port", "State", "Service", "Banner"], rows)
            + self._list_section("Port Insights", data.get("insights", []))
        )

    def _tech_sections(self, data: dict[str, Any]) -> str:
        techs = data.get("technologies", data.get("categories", []))
        rows = [
            (
                str(item.get("category", "-")),
                str(item.get("name", "-")),
                str(item.get("version", "-")),
                str(item.get("confidence", "-")),
            )
            for item in techs
        ]
        return (
            self._table(
                "Detected Technologies",
                ["Category", "Name", "Version", "Confidence"],
                rows,
            )
            + self._table_from_mapping("Security Headers", data.get("security_headers", {}))
            + self._list_section("Other Technologies", data.get("other", []))
        )

    def _info_sections(self, data: dict[str, Any]) -> str:
        whois = data.get("whois", {})
        rdap = data.get("rdap", {})
        ssl = data.get("ssl", {})
        soa = data.get("soa", {})
        return (
            self._table_from_mapping("WHOIS Summary", whois)
            + self._table_from_mapping("RDAP Summary", rdap)
            + self._table_from_mapping("SSL Certificate", ssl)
            + self._table_from_mapping("SOA Record", soa)
            + self._list_section("Domain Insights", data.get("insights", []))
        )

    def _subdomain_sections(self, data: dict[str, Any]) -> str:
        sub_rows = [(str(idx), sub) for idx, sub in enumerate(data.get("subdomains", []), 1)]
        alive_rows = [
            (
                str(idx),
                str(item.get("subdomain", "-")),
                str(item.get("status", "-")),
                str(item.get("server", "-")),
                str(item.get("title", "-")),
            )
            for idx, item in enumerate(data.get("alive", []), 1)
        ]
        return (
            self._table("Discovered Subdomains", ["#", "Subdomain"], sub_rows)
            + self._table(
                "Alive Subdomains",
                ["#", "Subdomain", "Status", "Server", "Title"],
                alive_rows,
            )
        )

    def _security_score(self, security: dict[str, Any]) -> str:
        if not security:
            return ""
        try:
            score = int(security.get("score", 0))
        except (TypeError, ValueError):
            score = 0
        score = max(0, min(10, score))
        color = "#5c39a2" if score >= 8 else "#a190cb" if score >= 5 else "#4123a2"
        issues = self._list_html(security.get("issues", []))
        good = self._list_html(security.get("good", []))
        risk = escape(str(security.get("risk", "")))
        return f"""<section class="report-section">
  <div class="section-heading">
    <h2>Security Score</h2>
    <span class="section-count">{score}/10</span>
  </div>
  <div class="score-layout">
    <div>
      <div class="score-value"><strong>{score}/10</strong><span class="muted">{risk}</span></div>
      <div class="score-bar">
        <div class="score-fill" style="--score-width: {score * 10}%; --score-color: {color};"></div>
      </div>
    </div>
    <div class="score-notes">
      <div><h3>Issues</h3>{issues}</div>
      <div><h3>Passed</h3>{good}</div>
    </div>
  </div>
</section>"""

    def _raw_data(self, data: dict[str, Any]) -> str:
        payload = escape(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        return f"""<section class="report-section raw-section">
  <div class="section-heading">
    <h2>Raw Structured Data</h2>
    <span class="section-count">JSON</span>
  </div>
  <details>
    <summary>View payload</summary>
    <pre>{payload}</pre>
  </details>
</section>"""

    def _table(
        self,
        title: str,
        headers: list[str],
        rows: list[tuple[Any, ...]],
    ) -> str:
        if not rows:
            return (
                f'<section class="report-section"><div class="section-heading">'
                f"<h2>{escape(title)}</h2><span class=\"section-count\">0 rows</span></div>"
                '<p class="muted">No data found.</p></section>'
            )

        head = "".join(f"<th>{escape(header)}</th>" for header in headers)
        body = "".join(
            "<tr>"
            + "".join(f"<td>{self._cell_html(cell)}</td>" for cell in row)
            + "</tr>"
            for row in rows
        )
        return f"""<section class="report-section">
  <div class="section-heading">
    <h2>{escape(title)}</h2>
    <span class="section-count">{len(rows)} rows</span>
  </div>
  <div class="table-scroll">
    <table>
      <thead><tr>{head}</tr></thead>
      <tbody>{body}</tbody>
    </table>
  </div>
</section>"""

    def _table_from_mapping(self, title: str, data: dict[str, Any]) -> str:
        rows = [
            (self._humanize_key(key), self._format_value(value))
            for key, value in data.items()
        ]
        return self._table(title, ["Field", "Value"], rows)

    def _list_section(self, title: str, values: list[Any]) -> str:
        count = len(values) if values else 0
        return f"""<section class="report-section">
  <div class="section-heading">
    <h2>{escape(title)}</h2>
    <span class="section-count">{count} items</span>
  </div>
  {self._list_html(values)}
</section>"""

    def _list_html(self, values: list[Any]) -> str:
        if not values:
            return '<p class="muted">No items found.</p>'
        items = "".join(f"<li>{escape(str(item))}</li>" for item in values)
        return f'<ul class="clean-list">{items}</ul>'

    def _cell_html(self, value: Any) -> str:
        if self._is_html_cell(value):
            return str(value)
        return escape(str(value))

    @classmethod
    def _logo_markup(cls) -> str:
        data_uri = cls._logo_uri()
        if data_uri:
            return f'<img class="brand-logo" src="{data_uri}" alt="DomainSpyder logo">'
        return '<span class="brand-wordmark">DomainSpyder</span>'

    @classmethod
    def _logo_uri(cls) -> str | None:
        if cls._logo_loaded:
            return cls._logo_data_uri

        project_root = Path(__file__).resolve().parents[2]
        candidates = [
            project_root / "assests" / "img" / "logo_no_bg_2.png",
            project_root / "assets" / "img" / "logo_no_bg_2.png",
            project_root / "assests" / "img" / "logo_no_bg_1.png",
            project_root / "assets" / "img" / "logo_no_bg_1.png",
            project_root / "assests" / "img" / "logo_2.png",
            project_root / "assets" / "img" / "logo_2.png",
            Path.cwd() / "assests" / "img" / "logo_no_bg_2.png",
            Path.cwd() / "assets" / "img" / "logo_no_bg_2.png",
            Path.cwd() / "assests" / "img" / "logo_no_bg_1.png",
            Path.cwd() / "assets" / "img" / "logo_no_bg_1.png",
            Path.cwd() / "assests" / "img" / "logo_2.png",
            Path.cwd() / "assets" / "img" / "logo_2.png",
        ]
        for path in candidates:
            try:
                image = path.read_bytes()
            except OSError:
                continue
            cls._logo_data_uri = (
                "data:image/png;base64,"
                + base64.b64encode(image).decode("ascii")
            )
            break

        cls._logo_loaded = True
        return cls._logo_data_uri

    @staticmethod
    def _format_value(value: Any) -> str:
        if value is None:
            return '<span class="muted">-</span>'
        if isinstance(value, (list, tuple, set)):
            if not value:
                return '<span class="muted">-</span>'
            return "<br>".join(escape(str(item)) for item in value)
        if isinstance(value, dict):
            payload = escape(json.dumps(value, indent=2, ensure_ascii=False, default=str))
            return f'<pre class="inline-pre">{payload}</pre>'
        return escape(str(value))

    @staticmethod
    def _friendly_datetime(value: str) -> str:
        if not value or value == "-":
            return "-"

        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value

        # Render UTC timestamps in the reader's local time so "when was this
        # generated" is immediately obvious without doing timezone math.
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone()

        hour = parsed.hour % 12 or 12
        meridiem = "AM" if parsed.hour < 12 else "PM"
        date_part = f"{parsed.strftime('%A')}, {parsed.strftime('%B')} {parsed.day}, {parsed.year}"
        time_part = f"{hour}:{parsed.minute:02d} {meridiem}"

        zone_name = parsed.tzname() if parsed.tzinfo is not None else ""
        if zone_name:
            return f"{date_part} at {time_part} {zone_name}"
        return f"{date_part} at {time_part}"

    @staticmethod
    def _humanize_key(key: str) -> str:
        return key.replace("_", " ").title()

    @staticmethod
    def _score_text(security: dict[str, Any]) -> str:
        if not security:
            return "-"
        return f"{security.get('score', '-')}/10"

    @staticmethod
    def _is_html_cell(value: Any) -> bool:
        return isinstance(value, str) and (
            "<br>" in value
            or value.startswith("<pre")
            or value.startswith("<span")
        )
