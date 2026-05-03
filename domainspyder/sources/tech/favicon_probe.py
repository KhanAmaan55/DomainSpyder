"""
Favicon hash fingerprinting probe.

Fetches /favicon.ico, computes its MD5 hash, and matches against
a curated database of known platform favicon hashes. This is
the same technique used by Shodan for platform identification.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from domainspyder.config import FAVICON_HASHES, HEADERS, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)


def probe_favicon(base_url: str) -> list[dict[str, Any]]:
    """
    Fetch /favicon.ico and match its hash against known platforms.

    Returns a list of category dicts for matched platforms.
    """
    parsed = urlparse(base_url)
    favicon_url = urlunparse((parsed.scheme, parsed.netloc, "/favicon.ico", "", "", ""))
    logger.debug("Favicon probe: fetching %s", favicon_url)

    try:
        with httpx.Client(
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = client.get(favicon_url)
    except Exception as exc:
        logger.debug("Favicon probe: fetch failed: %s", exc)
        return []

    if resp.status_code != 200:
        logger.debug("Favicon probe: got %d, skipping", resp.status_code)
        return []

    content = resp.content
    if not content or len(content) < 100:
        logger.debug("Favicon probe: response too small (%d bytes)", len(content))
        return []

    favicon_hash = hashlib.md5(content).hexdigest()
    logger.debug("Favicon probe: hash = %s (%d bytes)", favicon_hash, len(content))

    match = FAVICON_HASHES.get(favicon_hash)
    if not match:
        logger.debug("Favicon probe: no hash match")
        return []

    name = match["name"]
    category = match.get("category", "Server")

    logger.debug("Favicon probe: matched → %s (%s)", name, category)
    return [{
        "name": name,
        "score": 7,
        "confidence": "High",
        "meter": "███████░░░",
        "category": category,
    }]
