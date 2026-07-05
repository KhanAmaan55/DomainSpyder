"""JSON report exporter."""

from __future__ import annotations

import json
from typing import Any


class JsonExporter:
    """Serialize structured scan results as pretty-printed JSON."""

    def render(self, data: dict[str, Any]) -> str:
        """Return a JSON report that preserves the complete scan result."""
        from domainspyder.reporting.exporter import report_metadata

        payload = {
            **report_metadata(),
            "data": data,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"
