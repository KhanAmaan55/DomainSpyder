"""
Page-asset and secondary technology detection.

Analyses meta generator tags, script sources, stylesheet links,
and secondary technologies (analytics, chat, payments, etc.)
from the HTTP response body and headers.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Meta generator tag
# ------------------------------------------------------------------

# Maps generator-tag keywords → canonical CMS names
_GENERATOR_MAP: dict[str, str] = {
    "wordpress": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "ghost": "Ghost",
    "hugo": "Hugo",
    "jekyll": "Jekyll",
    "hexo": "Hexo",
    "pelican": "Pelican",
    "gatsby": "Gatsby",
    "nuxt": "Nuxt.js",
    "next.js": "Next.js",
}


def detect_from_meta_tags(html: str) -> tuple[str | None, str | None]:
    """
    Parse ``<meta name="generator">`` from HTML.

    Returns ``(raw_generator_string, matched_cms_name)`` or
    ``(None, None)`` if no generator tag was found.
    """
    match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        html, re.IGNORECASE,
    )
    if not match:
        match = re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
            html, re.IGNORECASE,
        )
    if not match:
        return None, None

    generator = match.group(1).strip()
    gen_lower = generator.lower()

    for key, name in _GENERATOR_MAP.items():
        if key in gen_lower:
            logger.debug("Meta generator matched: %s → %s", generator, name)
            return generator, name

    logger.debug("Meta generator found but unmatched: %s", generator)
    return generator, None


# ------------------------------------------------------------------
# Script source analysis
# ------------------------------------------------------------------

_SCRIPT_PATTERNS: list[tuple[str, str]] = [
    ("webpack", "Webpack"),
    ("vite", "Vite"),
    ("parcel", "Parcel"),
    ("rollup", "Rollup"),
    ("turbopack", "Turbopack"),
    ("esbuild", "esbuild"),
    ("unpkg.com", "unpkg CDN"),
    ("cdnjs.cloudflare.com", "cdnjs"),
    ("jsdelivr.net", "jsDelivr"),
    ("polyfill.io", "Polyfill.io"),
    ("recaptcha", "Google reCAPTCHA"),
    ("hcaptcha", "hCaptcha"),
    ("turnstile", "Cloudflare Turnstile"),
    ("lazysizes", "LazySizes"),
    ("swiper", "Swiper.js"),
    ("gsap", "GSAP"),
    ("three.js", "Three.js"),
    ("chart.js", "Chart.js"),
    ("d3.js", "D3.js"),
    ("moment.js", "Moment.js"),
    ("lodash", "Lodash"),
    ("axios", "Axios"),
    ("socket.io", "Socket.IO"),
    ("firebase", "Firebase"),
    ("supabase", "Supabase"),
]


def detect_from_script_sources(scripts: list[str]) -> list[str]:
    """Detect bundlers, frameworks, and libraries from script src URLs."""
    if not scripts:
        return []

    blob = " ".join(s.lower() for s in scripts)
    found: list[str] = []

    for pattern, label in _SCRIPT_PATTERNS:
        if pattern in blob:
            found.append(label)

    logger.debug("Script analysis: found %d technologies", len(found))
    return found


# ------------------------------------------------------------------
# Stylesheet analysis
# ------------------------------------------------------------------

_CSS_PATTERNS: list[tuple[str, str]] = [
    ("bootstrap", "Bootstrap"),
    ("tailwind", "Tailwind CSS"),
    ("bulma", "Bulma"),
    ("materialize", "Materialize CSS"),
    ("foundation", "Foundation"),
    ("semantic-ui", "Semantic UI"),
    ("ant-design", "Ant Design"),
    ("chakra-ui", "Chakra UI"),
    ("normalize.css", "Normalize.css"),
    ("animate.css", "Animate.css"),
    ("font-awesome", "Font Awesome"),
    ("fontawesome", "Font Awesome"),
    ("material-icons", "Material Icons"),
    ("google-fonts", "Google Fonts"),
    ("fonts.googleapis.com", "Google Fonts"),
    ("use.typekit.net", "Adobe Fonts"),
]


def detect_from_stylesheets(stylesheets: list[str]) -> list[str]:
    """Detect UI libraries from stylesheet hrefs."""
    if not stylesheets:
        return []

    blob = " ".join(s.lower() for s in stylesheets)
    found: list[str] = []

    for pattern, label in _CSS_PATTERNS:
        if pattern in blob and label not in found:
            found.append(label)

    logger.debug("Stylesheet analysis: found %d technologies", len(found))
    return found


# ------------------------------------------------------------------
# Secondary / "other" technologies
# ------------------------------------------------------------------

def detect_other(headers: dict[str, str], body: str) -> list[str]:
    """Detect secondary tools that don't fit core categories."""
    found: set[str] = set()

    x_powered = headers.get("x-powered-by", "").lower()

    # Meta-frameworks
    if "__next_data__" in body or "_next/static" in body or x_powered == "next.js":
        found.add("Next.js")
    if "nuxt" in body or "__nuxt" in body or "_nuxt/" in body:
        found.add("Nuxt.js")
    if "___gatsby" in body or "gatsby-" in body:
        found.add("Gatsby")
    if "_astro/" in body or "astro-island" in body:
        found.add("Astro")
    if "sveltekit" in body or "_app/immutable" in body:
        found.add("SvelteKit")
    if "remix" in body and "__remixcontext" in body:
        found.add("Remix")

    # Analytics & tag management
    if any(t in body for t in ["googletagmanager.com", "gtag(", "gtm.js"]):
        found.add("Google Tag Manager")
    if any(t in body for t in ["google-analytics.com", "ga.js", "analytics.js", "gtag/js"]):
        found.add("Google Analytics")
    if "plausible.io" in body:
        found.add("Plausible Analytics")
    if "fathom" in body and "usefathom.com" in body:
        found.add("Fathom Analytics")
    if "posthog" in body:
        found.add("PostHog")
    if "mixpanel.com" in body or "mixpanel.init" in body:
        found.add("Mixpanel")
    if "segment.com" in body or "segment.io" in body:
        found.add("Segment")
    if "amplitude.com" in body:
        found.add("Amplitude")

    # Heatmaps / session recording
    if "hotjar" in body:
        found.add("Hotjar")
    if "mouseflow" in body:
        found.add("Mouseflow")
    if "fullstory" in body or "fullstory.com" in body:
        found.add("FullStory")
    if "clarity.ms" in body:
        found.add("Microsoft Clarity")
    if "logrocket" in body:
        found.add("LogRocket")

    # Customer support / chat
    if "intercom.io" in body or "intercomcdn.com" in body:
        found.add("Intercom")
    if "drift.com" in body or "js.driftt.com" in body:
        found.add("Drift")
    if "crisp.chat" in body:
        found.add("Crisp")
    if "tidio" in body:
        found.add("Tidio")
    if "tawk.to" in body:
        found.add("Tawk.to")
    if "zendesk.com" in body:
        found.add("Zendesk")
    if "freshchat" in body or "freshdesk" in body:
        found.add("Freshdesk")

    # Error monitoring / observability
    if "sentry.io" in body or "sentry_key" in body:
        found.add("Sentry")
    if "datadoghq.com" in body or "datadoghq-browser-agent" in body:
        found.add("Datadog RUM")
    if "bugsnag.com" in body:
        found.add("Bugsnag")
    if "rollbar.com" in body:
        found.add("Rollbar")
    if "newrelic" in body or "nr-data.net" in body:
        found.add("New Relic")

    # UI libraries
    jquery_count = sum(
        1 for t in ["jquery.min.js", "jquery.js", "window.jquery", "jquery/jquery"]
        if t in body
    )
    if jquery_count >= 1:
        found.add("jQuery")
    if "bootstrap" in body and re.search(r"bootstrap(\.min)?\.(css|js)", body):
        found.add("Bootstrap")
    if "tailwind" in body and re.search(r"tailwind(\.min)?\.(css|js)|cdn\.tailwindcss\.com", body):
        found.add("Tailwind CSS")
    if "bulma" in body and "bulma.io" in body:
        found.add("Bulma")
    if "materialize" in body:
        found.add("Materialize CSS")
    if "foundation.min" in body or "foundation.css" in body:
        found.add("Foundation")
    if "alpine.js" in body or "x-data=" in body:
        found.add("Alpine.js")
    if "htmx" in body and ("hx-get" in body or "hx-post" in body):
        found.add("HTMX")
    if "lit-element" in body or "lit-html" in body or "lit.dev" in body:
        found.add("Lit")

    # Marketing / CRM
    if "hubspot.com" in body or "_hsq.push" in body:
        found.add("HubSpot")
    if "salesforce.com" in body and "pardot" in body:
        found.add("Salesforce Pardot")
    if "marketo" in body:
        found.add("Marketo")
    if "klaviyo.com" in body:
        found.add("Klaviyo")
    if "mailchimp.com" in body:
        found.add("Mailchimp")

    # Image / media CDNs
    if "cloudinary.com" in body:
        found.add("Cloudinary")
    if "imgix.net" in body:
        found.add("Imgix")
    if "imagekit.io" in body:
        found.add("ImageKit")
    if "fastly.picmonkey.com" in body:
        found.add("Fastly Image Optimizer")

    # Payments
    if "stripe.com" in body or "js.stripe.com" in body:
        found.add("Stripe")
    if "paypal.com" in body and "paypalobjects.com" in body:
        found.add("PayPal")
    if "braintree" in body:
        found.add("Braintree")

    # Maps
    if "maps.googleapis.com" in body:
        found.add("Google Maps")
    if "mapbox.com" in body or "mapboxgl" in body:
        found.add("Mapbox")
    if "leafletjs.com" in body or "leaflet.js" in body:
        found.add("Leaflet")

    # A/B testing / personalisation
    if "optimizely" in body:
        found.add("Optimizely")
    if "abtasty" in body:
        found.add("AB Tasty")
    if "vwo.com" in body or "visualwebsiteoptimizer" in body:
        found.add("VWO")

    # Search
    if "algolia" in body:
        found.add("Algolia")
    if "swiftype" in body:
        found.add("Swiftype")

    # Misc HTTP headers
    if "x-powered-by" in headers:
        powered = headers["x-powered-by"]
        if powered.lower() not in ("", "express", "php", "asp.net"):
            found.add(f"X-Powered-By: {powered}")

    return sorted(found)
