"""Security header audit for technology detection."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def detect_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Audit security-related response headers."""
    findings: dict[str, Any] = {}
    normalized = {k.lower(): v for k, v in headers.items()}

    hsts = normalized.get("strict-transport-security")
    findings["hsts"] = {"present": bool(hsts), "value": hsts or ""}

    csp = normalized.get("content-security-policy")
    findings["csp"] = {"present": bool(csp), "length": len(csp) if csp else 0}

    xfo = normalized.get("x-frame-options")
    findings["x_frame_options"] = {"present": bool(xfo), "value": xfo or ""}

    xcto = normalized.get("x-content-type-options")
    findings["x_content_type_options"] = {"present": bool(xcto), "value": xcto or ""}

    rp = normalized.get("referrer-policy")
    findings["referrer_policy"] = {"present": bool(rp), "value": rp or ""}

    pp = normalized.get("permissions-policy")
    findings["permissions_policy"] = {"present": bool(pp)}

    present_count = sum(1 for v in findings.values() if v.get("present"))
    logger.debug("Security headers: %d/%d present", present_count, len(findings))

    return findings
