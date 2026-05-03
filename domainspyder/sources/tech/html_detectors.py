"""
HTML body-based technology detectors.

Detects frontend SPA frameworks and CMS / website-builder platforms
by scanning HTML content, inline scripts, and header clues.
"""

from __future__ import annotations

import logging
from typing import Any

from domainspyder.sources.tech.helpers import (
    boost,
    finalize_all,
    header_blob,
    new_candidate,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Frontend detection
# ------------------------------------------------------------------

def detect_frontend(
    body: str,
    script_blob: str = "",
    strong_platforms: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Detect frontend SPA frameworks from HTML content (pre-lowercased)."""
    strong_platforms = strong_platforms or set()

    candidates = {
        name: new_candidate()
        for name in ["React", "Angular", "Vue", "Svelte", "Astro", "Ionic"]
    }

    # React / Next.js
    react_signals = [
        "data-reactroot", "data-reactid", "__next_data__",
        "_next/static", 'id="__next"', "id='__next'",
        "react.development.js", "react.production.min.js",
        "react-dom", "__react_fiber", "_reactrouter",
    ]
    react_count = sum(1 for s in react_signals if s in body)
    if "__next_data__" in body or "_next/static" in body:
        boost(candidates["React"], 2, 8)
    elif react_count >= 2:
        boost(candidates["React"], react_count, min(10, 4 + react_count * 2))
    elif react_count == 1:
        boost(candidates["React"], 1, 2)

    # Angular
    angular_signals = [
        "ng-version", "ng-app", "ng-controller", "ng-model",
        "main-es2015", "runtime-es2015", "polyfills-es2015",
        "[_nghost", "[_ngcontent", "ng-reflect",
    ]
    ang_count = sum(1 for s in angular_signals if s in body)
    if ang_count >= 2:
        boost(candidates["Angular"], ang_count, min(10, 4 + ang_count * 2))
    elif ang_count == 1:
        boost(candidates["Angular"], 1, 3)
    if any(x in body for x in ["main.", "polyfills.", "runtime."]):
        boost(candidates["Angular"], 1, 4)
    if any(x in script_blob for x in ["main.", "polyfills.", "runtime."]):
        boost(candidates["Angular"], 2, 7)
    if "ng-version" in body:
        boost(candidates["Angular"], 2, 8)
    if "zone.js" in body:
        boost(candidates["Angular"], 1, 4)

    # Ionic
    ionic_signals = [
        "ionic", "ion-app", "ion-content", "ion-router", "ion-page",
    ]
    ionic_count = sum(1 for s in ionic_signals if s in body)
    if ionic_count >= 2:
        boost(candidates["Ionic"], ionic_count, min(10, 6 + ionic_count))
    elif ionic_count == 1:
        boost(candidates["Ionic"], 1, 4)

    # Vue
    vue_signals = [
        "data-v-", "__vue__", "vue.js", "vue.min.js",
        "vue-router", "vuex", "__vue_app__", "createapp(",
        "v-cloak", ":class=", "@click=",
    ]
    vue_count = sum(1 for s in vue_signals if s in body)
    if vue_count >= 2:
        boost(candidates["Vue"], vue_count, min(10, 4 + vue_count * 2))
    elif vue_count == 1:
        boost(candidates["Vue"], 1, 3)

    # Svelte / SvelteKit
    svelte_signals = [
        "__svelte", "svelte-", "sveltekit", "_app/immutable",
        "data-svelte-h", "svelte/transition",
    ]
    svel_count = sum(1 for s in svelte_signals if s in body)
    if svel_count >= 2:
        boost(candidates["Svelte"], svel_count, min(10, 5 + svel_count * 2))
    elif svel_count == 1:
        boost(candidates["Svelte"], 1, 4)

    # Astro
    astro_signals = [
        "astro-island", "astro:page-load", "_astro/",
        "data-astro-cid", "astro.config",
    ]
    astro_count = sum(1 for s in astro_signals if s in body)
    if astro_count >= 1:
        boost(candidates["Astro"], astro_count, min(10, 5 + astro_count * 2))

    # Suppress frameworks on strong hosted platforms
    if strong_platforms:
        for name in ("React", "Angular", "Vue", "Svelte", "Astro"):
            candidates[name]["score"] = max(0, candidates[name]["score"] - 3)
            if candidates[name]["score"] < 3:
                candidates[name]["signals"] = 0

    return finalize_all(candidates)


# ------------------------------------------------------------------
# CMS detection
# ------------------------------------------------------------------

def detect_cms(
    html: str,
    headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Detect CMS / website-builder platforms."""
    body = html.lower()
    headers = headers or {}
    hdr_blob = header_blob(*headers.values())

    candidates = {
        name: new_candidate()
        for name in [
            "WordPress", "Joomla", "Drupal", "Wix", "Shopify",
            "Webflow", "Squarespace", "Ghost", "HubSpot",
            "Magento", "PrestaShop", "BigCommerce",
        ]
    }

    # WordPress
    wp_signals = [
        "wp-content", "wp-includes", "wordpress",
        'generator" content="wordpress',
        "/wp-json/", "wp-block-", "wp-emoji",
    ]
    wp_count = sum(1 for s in wp_signals if s in body)
    if wp_count >= 2:
        boost(candidates["WordPress"], wp_count, min(10, 6 + wp_count))
    elif wp_count == 1:
        boost(candidates["WordPress"], 1, 5)

    # Joomla
    joomla_signals = [
        "/media/system/js/", "com_content", "joomla!",
        'generator" content="joomla', "/media/jui/", "joomla.document",
    ]
    joomla_count = sum(1 for s in joomla_signals if s in body)
    if joomla_count >= 1:
        boost(candidates["Joomla"], joomla_count, min(10, 6 + joomla_count))

    # Drupal
    drupal_signals = [
        "/sites/default/", "/misc/drupal.js", "drupal-settings-json",
        'generator" content="drupal', "drupal.js", "drupal.behaviors",
        "/core/themes/", "/modules/contrib/",
    ]
    drupal_count = sum(1 for s in drupal_signals if s in body)
    if drupal_count >= 1:
        boost(candidates["Drupal"], drupal_count, min(10, 6 + drupal_count))
    if "x-drupal-cache" in headers or "x-drupal-dynamic-cache" in headers:
        boost(candidates["Drupal"], 2, 5)

    # Wix
    wix_body_signals = [
        "wix.com", "wixstatic.com", "wix-image",
        "siteassets", "wix-code", "parastorage.com",
        "_wixcms", "wix-bolt", "wixapps.net",
    ]
    wix_count = sum(1 for s in wix_body_signals if s in body)
    wix_header_signals = [
        "x-wix-request-id", "x-wix-renderer-server",
        "x-wix-published-version",
    ]
    wix_header_count = sum(1 for h in wix_header_signals if h in headers)
    total_wix = wix_count + wix_header_count * 2
    if total_wix >= 2:
        boost(candidates["Wix"], 2, min(10, 7 + total_wix))
    elif total_wix == 1:
        boost(candidates["Wix"], 1, 5)

    # Shopify
    shopify_body = [
        "cdn.shopify.com", "shopify.com", "shopify",
        "myshopify.com", "/cart.js", "shopify-section",
        "shopify_analytics",
    ]
    shopify_header_keys = [
        "x-shopid", "x-shardid", "x-sorting-hat-podid",
        "x-shopify-stage",
    ]
    shopify_body_count = sum(1 for s in shopify_body if s in body or s in hdr_blob)
    shopify_hdr_count = sum(1 for h in shopify_header_keys if h in headers)
    total_shopify = shopify_body_count + shopify_hdr_count * 2
    if total_shopify >= 2:
        boost(candidates["Shopify"], 2, min(10, 7 + total_shopify))
    elif total_shopify == 1:
        boost(candidates["Shopify"], 1, 5)

    # Webflow
    webflow_signals = [
        "webflow", "webflow.io", "wf-force-outline-none",
        "data-wf-page", "data-wf-site", "js.webflow.com",
    ]
    wf_count = sum(1 for s in webflow_signals if s in body)
    if wf_count >= 2:
        boost(candidates["Webflow"], 2, min(10, 7 + wf_count))
    elif wf_count == 1:
        boost(candidates["Webflow"], 1, 5)

    # Squarespace
    sqsp_signals = [
        "squarespace.com", "squarespace", "static1.squarespace.com",
        "sqsp-templates", "sqsptheme", "data-layout-label",
        "squarespace-cdn.com",
    ]
    sqsp_count = sum(1 for s in sqsp_signals if s in body)
    if "x-servedby" in headers and "squarespace" in headers.get("x-servedby", "").lower():
        sqsp_count += 2
    if sqsp_count >= 2:
        boost(candidates["Squarespace"], 2, min(10, 7 + sqsp_count))
    elif sqsp_count == 1:
        boost(candidates["Squarespace"], 1, 5)

    # Ghost
    ghost_signals = [
        "ghost.io", "content/themes/", "ghost/", "ghost-url",
        'generator" content="ghost',
    ]
    ghost_count = sum(1 for s in ghost_signals if s in body)
    if ghost_count >= 1:
        boost(candidates["Ghost"], ghost_count, min(10, 6 + ghost_count))

    # HubSpot CMS
    hs_signals = [
        "hs-scripts.com", "hubspot.com", "hscta-", "hs-cta-",
        "_hsp.push", "hubspotutk",
    ]
    hs_count = sum(1 for s in hs_signals if s in body)
    if "x-hs-hub-id" in headers or "hubspotutk" in headers:
        hs_count += 2
    if hs_count >= 2:
        boost(candidates["HubSpot"], 2, min(10, 6 + hs_count))
    elif hs_count == 1:
        boost(candidates["HubSpot"], 1, 4)

    # Magento
    magento_signals = [
        "magento", "mage/", "varien", "skin/frontend/",
        "pub/static/", "requirejs/require.js", "checkout/cart/",
    ]
    mag_count = sum(1 for s in magento_signals if s in body)
    if mag_count >= 2:
        boost(candidates["Magento"], mag_count, min(10, 6 + mag_count))
    elif mag_count == 1:
        boost(candidates["Magento"], 1, 4)

    # PrestaShop
    presta_signals = [
        "prestashop", "presta-shop", "/modules/", "addons.prestashop.com",
        "id_product", "id_category",
    ]
    pre_count = sum(1 for s in presta_signals if s in body)
    if pre_count >= 2:
        boost(candidates["PrestaShop"], pre_count, min(10, 6 + pre_count))

    # BigCommerce
    bc_signals = [
        "bigcommerce", "bigcommerce.com", "cdn11.bigcommerce.com",
        "stencil-utils", "bigpay.site",
    ]
    bc_count = sum(1 for s in bc_signals if s in body)
    if bc_count >= 1:
        boost(candidates["BigCommerce"], bc_count, min(10, 7 + bc_count))

    # Cross-CMS suppression
    strong_hosted = {"Wix", "Shopify", "Webflow", "Squarespace", "BigCommerce"}
    strong_detected = any(
        candidates[name]["score"] >= 8 for name in strong_hosted
        if name in candidates
    )
    if strong_detected:
        for suppress in ("WordPress", "Drupal", "Joomla"):
            candidates[suppress]["score"] = max(0, candidates[suppress]["score"] - 5)
            if candidates[suppress]["score"] < 3:
                candidates[suppress]["signals"] = 0

    return finalize_all(candidates)
