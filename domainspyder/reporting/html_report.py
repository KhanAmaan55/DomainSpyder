"""Standalone HTML report exporter."""

from __future__ import annotations

from html import escape
from typing import Any


class HtmlExporter:
    """Render structured scan results as a self-contained HTML document."""

    def render(self, data: dict[str, Any]) -> str:
        """Return a responsive standalone HTML report for *data*."""
        from domainspyder.reporting.exporter import report_metadata

        metadata = report_metadata()
        command = str(data.get("command", "scan")).title()
        target = str(data.get("target") or data.get("domain") or "-")
        generated_at = metadata["generated_at"]

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DomainSpyder {escape(command)} Report - {escape(target)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --line: #d8dee8;
      --brand: #075e73;
      --brand-strong: #0a4455;
      --accent: #2f7d68;
      --warn: #a15c00;
      --danger: #b42318;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    header {{
      background: linear-gradient(135deg, var(--brand-strong), var(--brand));
      color: #fff;
      padding: 32px 24px;
    }}
    main {{
      width: min(1180px, calc(100% - 32px));
      margin: 24px auto 48px;
    }}
    .header-inner {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
    }}
    .brand {{
      margin: 0 0 8px;
      font-size: clamp(28px, 5vw, 44px);
      line-height: 1.05;
      letter-spacing: 0;
    }}
    .subtitle, .meta {{
      margin: 0;
      color: rgba(255, 255, 255, 0.84);
    }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 22px;
    }}
    .card, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(23, 32, 51, 0.04);
    }}
    .card {{
      padding: 16px;
      min-height: 92px;
    }}
    .label {{
      margin: 0 0 6px;
      color: var(--muted);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    .value {{
      margin: 0;
      font-size: 24px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }}
    section {{
      padding: 18px;
      margin-top: 16px;
      overflow-x: auto;
    }}
    h2 {{
      margin: 0 0 14px;
      font-size: 20px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 520px;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
      background: #f9fafc;
    }}
    code, pre {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #f9fafc;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      font-size: 13px;
    }}
    ul {{
      margin: 0;
      padding-left: 20px;
    }}
    .score-wrap {{
      display: grid;
      gap: 10px;
      max-width: 420px;
    }}
    .score-bar {{
      height: 14px;
      background: #e9eef5;
      border-radius: 999px;
      overflow: hidden;
    }}
    .score-fill {{
      height: 100%;
      width: var(--score-width);
      background: var(--score-color);
    }}
    .pill {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      background: #eef6f3;
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
    }}
    .muted {{ color: var(--muted); }}
    .danger {{ color: var(--danger); }}
    .warn {{ color: var(--warn); }}
    @media (max-width: 640px) {{
      header {{ padding: 24px 16px; }}
      main, .header-inner {{ width: calc(100% - 24px); }}
      section {{ padding: 14px; }}
      .value {{ font-size: 20px; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <h1 class="brand">DomainSpyder</h1>
      <p class="subtitle">{escape(command)} report for {escape(target)}</p>
      <p class="meta">Generated {escape(generated_at)} with DomainSpyder {escape(metadata["version"])}</p>
    </div>
  </header>
  <main>
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
            ("Scan Timestamp", str(data.get("timestamp", "-"))),
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
            cards.append(("Open Ports", str(data.get("open_count", len(data.get("open_ports", []))))))
        elif command == "tech":
            cards.append(("Technologies", str(len(data.get("technologies", data.get("categories", []))))))
            cards.append(("HTTP Status", str(data.get("status", "-"))))
        elif command == "info":
            cards.append(("Registrar", str(data.get("registrar", "-"))))
            cards.append(("Sources Used", str(len(data.get("sources_used", [])))))

        items = "\n".join(
            f'<article class="card"><p class="label">{escape(label)}</p>'
            f'<p class="value">{escape(value)}</p></article>'
            for label, value in cards
        )
        return f'<div class="summary">{items}</div>'

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
            self._table("Detected Technologies", ["Category", "Name", "Version", "Confidence"], rows)
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
            + self._table("Alive Subdomains", ["#", "Subdomain", "Status", "Server", "Title"], alive_rows)
        )

    def _security_score(self, security: dict[str, Any]) -> str:
        if not security:
            return ""
        score = int(security.get("score", 0))
        score = max(0, min(10, score))
        color = "#2f7d68" if score >= 8 else "#a15c00" if score >= 5 else "#b42318"
        issues = self._list_html(security.get("issues", []))
        good = self._list_html(security.get("good", []))
        return f"""<section>
  <h2>Security Score</h2>
  <div class="score-wrap">
    <strong>{score}/10 <span class="muted">{escape(str(security.get("risk", "")))}</span></strong>
    <div class="score-bar"><div class="score-fill" style="--score-width: {score * 10}%; --score-color: {color};"></div></div>
  </div>
  <h3>Issues</h3>{issues}
  <h3>Passed</h3>{good}
</section>"""

    def _raw_data(self, data: dict[str, Any]) -> str:
        import json

        return (
            "<section><h2>Raw Structured Data</h2><pre>"
            + escape(json.dumps(data, indent=2, ensure_ascii=False))
            + "</pre></section>"
        )

    def _table(
        self,
        title: str,
        headers: list[str],
        rows: list[tuple[Any, ...]],
    ) -> str:
        if not rows:
            return f"<section><h2>{escape(title)}</h2><p class=\"muted\">No data found.</p></section>"
        head = "".join(f"<th>{escape(header)}</th>" for header in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{cell if self._is_html_cell(cell) else escape(str(cell))}</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return f"<section><h2>{escape(title)}</h2><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></section>"

    def _table_from_mapping(self, title: str, data: dict[str, Any]) -> str:
        rows = [(self._humanize_key(key), self._format_value(value)) for key, value in data.items()]
        return self._table(title, ["Field", "Value"], rows)

    def _list_section(self, title: str, values: list[Any]) -> str:
        return f"<section><h2>{escape(title)}</h2>{self._list_html(values)}</section>"

    def _list_html(self, values: list[Any]) -> str:
        if not values:
            return '<p class="muted">No items found.</p>'
        items = "".join(f"<li>{escape(str(item))}</li>" for item in values)
        return f"<ul>{items}</ul>"

    @staticmethod
    def _format_value(value: Any) -> str:
        if isinstance(value, (list, tuple, set)):
            return "<br>".join(escape(str(item)) for item in value)
        if isinstance(value, dict):
            return "<pre>" + escape(str(value)) + "</pre>"
        return escape(str(value))

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
        return isinstance(value, str) and ("<br>" in value or value.startswith("<pre>"))
