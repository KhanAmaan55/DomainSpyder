"""
WordPress /wp-json/ API probe.

When WordPress signals are detected, probes the REST API
to confirm WordPress and enumerate plugins/themes via
namespace discovery.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from domainspyder.config import HEADERS, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

# Maps WP REST API namespace prefixes → plugin names
_NAMESPACE_MAP: dict[str, str] = {
    "wp/v2": "WordPress REST API",
    "yoast": "Yoast SEO",
    "wc/": "WooCommerce",
    "jetpack": "Jetpack",
    "acf/": "Advanced Custom Fields",
    "wp-site-health": "Site Health",
    "contact-form-7": "Contact Form 7",
    "wordfence": "Wordfence Security",
    "rankmath": "Rank Math SEO",
    "elementor": "Elementor",
    "wpml": "WPML",
    "gravityforms": "Gravity Forms",
    "bbpress": "bbPress",
    "buddypress": "BuddyPress",
}


def probe_wp_api(base_url: str) -> dict[str, Any] | None:
    """
    Probe the target's /wp-json/ REST endpoint to confirm a WordPress site and identify likely plugins.
    
    Parameters:
        base_url (str): The target site's base URL (scheme and host are used to construct the /wp-json/ endpoint).
    
    Returns:
        result (dict[str, Any] | None): If WordPress is detected, a dictionary containing:
            - "confirmed": True
            - "plugins": a list of detected plugin/component names (may be empty)
            - "site_name": the site name from the REST API or an empty string.
        Returns None if the endpoint is unavailable, not a valid JSON REST response, or does not contain WP namespaces.
    """
    parsed = urlparse(base_url)
    wp_url = urlunparse((parsed.scheme, parsed.netloc, "/wp-json/", "", "", ""))
    logger.debug("WP API probe: fetching %s", wp_url)

    try:
        with httpx.Client(
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = client.get(wp_url)
    except httpx.RequestError as exc:
        logger.debug("WP API probe: fetch failed: %s", exc)
        return None

    if resp.status_code != 200:
        logger.debug("WP API probe: got %d, skipping", resp.status_code)
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.debug("WP API probe: response is not JSON")
        return None

    # Validate it's a real WP REST API response
    if not isinstance(data, dict) or "namespaces" not in data:
        logger.debug("WP API probe: invalid JSON shape or no 'namespaces' key, not WP")
        return None

    namespaces = data.get("namespaces", [])
    logger.debug("WP API probe: found %d namespaces", len(namespaces))

    plugins: list[str] = []
    ns_blob = " ".join(str(ns).lower() for ns in namespaces)

    for prefix, plugin_name in _NAMESPACE_MAP.items():
        if prefix in ns_blob and plugin_name not in plugins:
            plugins.append(plugin_name)
            logger.debug("WP API probe: namespace %s → %s", prefix, plugin_name)

    return {
        "confirmed": True,
        "plugins": plugins,
        "site_name": data.get("name", ""),
    }
