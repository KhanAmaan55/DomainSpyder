"""
Sitemap.xml probe for CMS cross-validation.

Fetches /sitemap.xml and looks for CMS-specific URL patterns
and XML namespaces that reveal the underlying platform.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from domainspyder.config import HEADERS, REQUEST_TIMEOUT, SITEMAP_CMS_PATTERNS

logger = logging.getLogger(__name__)


def probe_sitemap(base_url: str) -> list[dict[str, Any]]:
    """
    Probe a site's /sitemap.xml for known CMS indicator patterns.
    
    Builds a sitemap URL from base_url, fetches the sitemap XML, and scans its content for configured CMS indicator patterns. For each unique CMS matched, returns a category dictionary describing the detection.
    
    Parameters:
        base_url (str): The target site's base URL used to construct the sitemap URL (scheme and netloc are preserved).
    
    Returns:
        list[dict[str, Any]]: A list of matched CMS category dictionaries. Each dictionary contains the keys:
            - `name`: CMS name matched
            - `score`: numeric score (int)
            - `confidence`: textual confidence level
            - `meter`: visual meter string
            - `category`: fixed value `"CMS"`
    """
    parsed = urlparse(base_url)
    sitemap_url = urlunparse((parsed.scheme, parsed.netloc, "/sitemap.xml", "", "", ""))
    logger.debug("Sitemap probe: fetching %s", sitemap_url)

    try:
        with httpx.Client(
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = client.get(sitemap_url)
    except httpx.RequestError as exc:
        logger.debug("Sitemap probe: fetch failed: %s", exc)
        return []

    if resp.status_code != 200:
        logger.debug("Sitemap probe: got %d, skipping", resp.status_code)
        return []

    text = resp.text.lower()
    if not text or ("<urlset" not in text and "<sitemapindex" not in text):
        logger.debug("Sitemap probe: not a valid sitemap XML")
        return []

    logger.debug("Sitemap probe: got %d chars of sitemap", len(text))

    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    for pattern, name in SITEMAP_CMS_PATTERNS.items():
        if pattern in text and name not in seen:
            results.append({
                "name": name,
                "score": 4,
                "confidence": "Medium",
                "meter": "████░░░░░░",
                "category": "CMS",
            })
            seen.add(name)
            logger.debug("Sitemap probe: matched %s → %s", pattern, name)

    logger.debug("Sitemap probe: %d CMS patterns matched", len(results))
    return results
