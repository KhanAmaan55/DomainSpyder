"""Security header audit for technology detection."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def detect_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    """
    Analyze a mapping of HTTP response headers and report presence and selected properties of common security headers.
    
    Parameters:
        headers (dict[str, str]): Mapping of response header names to their string values.
    
    Returns:
        dict[str, Any]: A dictionary with these keys:
            - "hsts": {"present": bool, "value": str}
            - "csp": {"present": bool, "length": int}
            - "x_frame_options": {"present": bool, "value": str}
            - "x_content_type_options": {"present": bool, "value": str}
            - "referrer_policy": {"present": bool, "value": str}
            - "permissions_policy": {"present": bool}
        Each entry indicates whether the header was present and includes the header value or its length where applicable.
    """
    findings: dict[str, Any] = {}

    hsts = headers.get("strict-transport-security")
    findings["hsts"] = {"present": bool(hsts), "value": hsts or ""}

    csp = headers.get("content-security-policy")
    findings["csp"] = {"present": bool(csp), "length": len(csp) if csp else 0}

    xfo = headers.get("x-frame-options")
    findings["x_frame_options"] = {"present": bool(xfo), "value": xfo or ""}

    xcto = headers.get("x-content-type-options")
    findings["x_content_type_options"] = {"present": bool(xcto), "value": xcto or ""}

    rp = headers.get("referrer-policy")
    findings["referrer_policy"] = {"present": bool(rp), "value": rp or ""}

    pp = headers.get("permissions-policy")
    findings["permissions_policy"] = {"present": bool(pp)}

    present_count = sum(1 for v in findings.values() if v.get("present"))
    logger.debug("Security headers: %d/%d present", present_count, len(findings))

    return findings
