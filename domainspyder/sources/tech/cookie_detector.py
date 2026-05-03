"""
Cookie-based technology detection (enhanced).

Maps cookie names and patterns to the technologies that set them,
providing additional signals beyond header/body analysis.
"""

from __future__ import annotations

import logging

from domainspyder.config import COOKIE_TECH_MAP

logger = logging.getLogger(__name__)


def detect_from_cookies(cookies: dict[str, str]) -> list[str]:
    """
    Detect technologies from cookie names.

    Checks each cookie against ``COOKIE_TECH_MAP`` patterns.
    Returns a list of detected technology names.
    """
    if not cookies:
        return []

    found: list[str] = []
    cookie_keys = " ".join(cookies.keys()).lower()

    for pattern, label in COOKIE_TECH_MAP.items():
        if pattern in cookie_keys and label not in found:
            found.append(label)
            logger.debug("Cookie detector: %s → %s", pattern, label)

    logger.debug("Cookie detector: found %d technologies", len(found))
    return found
