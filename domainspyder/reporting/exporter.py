"""Exporter registry and report saving helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from domainspyder.config import VERSION
from domainspyder.reporting.html_report import HtmlExporter
from domainspyder.reporting.json_report import JsonExporter


class ExportError(RuntimeError):
    """Raised when report export cannot be completed."""


class ReportExporter(Protocol):
    """Protocol implemented by all report exporters."""

    def render(self, data: dict[str, Any]) -> str:
        """Return a serialized report for *data*."""


EXPORTERS: dict[str, type[ReportExporter]] = {
    ".json": JsonExporter,
    ".html": HtmlExporter,
}


def get_exporter(path: str | Path) -> ReportExporter:
    """Return an exporter instance selected by the output file extension."""
    suffix = Path(path).suffix.lower()
    exporter_cls = EXPORTERS.get(suffix)
    if exporter_cls is None:
        supported = ", ".join(sorted(EXPORTERS))
        raise ExportError(
            f"Unsupported report format '{suffix or '<none>'}'. "
            f"Supported formats: {supported}"
        )
    return exporter_cls()


def save_report(data: dict[str, Any], output_path: str | Path) -> Path:
    """Render *data* with the matching exporter and write it to *output_path*."""
    path = Path(output_path).expanduser()
    exporter = get_exporter(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(exporter.render(data), encoding="utf-8")
    except OSError as exc:
        raise ExportError(f"Could not write report to {path}: {exc}") from exc
    return path


def report_metadata() -> dict[str, str]:
    """Return standard metadata used by exporters."""
    from datetime import datetime, timezone

    return {
        "tool": "DomainSpyder",
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
