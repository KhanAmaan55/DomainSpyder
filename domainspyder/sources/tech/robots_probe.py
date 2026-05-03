"""robots.txt probe for CMS and admin panel detection."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from domainspyder.config import HEADERS, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

_ROBOTS_HINTS: list[tuple[str, str, str]] = [
    ("wp-admin", "WordPress", "CMS"),
    ("wp-includes", "WordPress", "CMS"),
    ("/administrator/", "Joomla", "CMS"),
    ("/components/com_", "Joomla", "CMS"),
    ("/sites/default/", "Drupal", "CMS"),
    ("/core/", "Drupal", "CMS"),
    ("/admin/", "Admin Panel", ""),
    ("/phpmyadmin", "phpMyAdmin", ""),
    ("/magento", "Magento", "CMS"),
    ("/skin/frontend/", "Magento", "CMS"),
]


def probe_robots_txt(
    base_url: str,
) -> dict[str, list[dict[str, Any]]]:
    """
    Fetch /robots.txt and return CMS/tool hints.

    Returns ``{"cms_hints": [...], "other_hints": [...]}``.
    """
    parsed = urlparse(base_url)
    robots_url = urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
    logger.debug("robots.txt probe: fetching %s", robots_url)

    try:
        with httpx.Client(
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = client.get(robots_url)
    except Exception as exc:
        logger.debug("robots.txt probe: fetch failed: %s", exc)
        return {"cms_hints": [], "other_hints": []}

    if resp.status_code != 200:
        logger.debug("robots.txt probe: got %d, skipping", resp.status_code)
        return {"cms_hints": [], "other_hints": []}

    text = resp.text.lower()
    logger.debug("robots.txt probe: got %d bytes", len(text))

    cms_hints: list[dict[str, Any]] = []
    other_hints: list[str] = []
    seen_names: set[str] = set()

    for pattern, name, cat in _ROBOTS_HINTS:
        if pattern in text and name not in seen_names:
            if cat:
                cms_hints.append({
                    "name": name,
                    "score": 5,
                    "confidence": "Medium",
                    "meter": "█████░░░░░",
                    "category": cat,
                })
            else:
                other_hints.append(name)
            seen_names.add(name)

    logger.debug(
        "robots.txt probe: %d CMS hints, %d other hints",
        len(cms_hints), len(other_hints),
    )
    return {"cms_hints": cms_hints, "other_hints": other_hints}
