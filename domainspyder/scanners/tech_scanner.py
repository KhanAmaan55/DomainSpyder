"""
DomainSpyder technology scanner.

Multi-method, multi-source technology detection.  Fetches the target
page once, then runs a pipeline of detectors (HTTP, HTML, asset,
cookie, security) on the shared response and concurrent network
probes (DNS hints, robots.txt, favicon, sitemap, WordPress API)
in parallel.

All detection logic lives in ``domainspyder.sources.tech.*``;
this module orchestrates execution, merges results, and applies
cross-source enrichments (meta-tag boosting, version extraction,
WordPress plugin discovery).
"""

from __future__ import annotations

import logging
import re
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import httpx

from domainspyder.config import HEADERS, REQUEST_TIMEOUT

# Detectors (operate on shared HTTP response data)
from domainspyder.sources.tech.asset_analysis import (
    detect_from_meta_tags,
    detect_from_script_sources,
    detect_from_stylesheets,
    detect_other,
)
from domainspyder.sources.tech.cookie_detector import detect_from_cookies
from domainspyder.sources.tech.helpers import (
    confidence_label,
    lower_headers,
)
from domainspyder.sources.tech.html_detectors import detect_cms, detect_frontend
from domainspyder.sources.tech.http_detectors import (
    detect_backend,
    detect_cdn,
    detect_server,
)
from domainspyder.sources.tech.security_analysis import detect_security_headers
from domainspyder.sources.tech.version_extractor import extract_versions

# Probes (make independent network requests)
from domainspyder.sources.tech.dns_hints_probe import probe_dns_hints
from domainspyder.sources.tech.favicon_probe import probe_favicon
from domainspyder.sources.tech.robots_probe import probe_robots_txt
from domainspyder.sources.tech.sitemap_probe import probe_sitemap
from domainspyder.sources.tech.wp_api_probe import probe_wp_api

logger = logging.getLogger(__name__)

_SSL_ERROR_TYPES = (
    ssl.SSLError,
    httpx.ConnectError,
    httpx.RemoteProtocolError,
)


class TechScanner:
    """
    Detect common web technologies via a multi-source pipeline.

    Usage::

        scanner = TechScanner(debug=True)
        results = scanner.scan("example.com")
    """

    def __init__(self, *, debug: bool = False) -> None:
        self._debug = debug
        self._cancelled = False
        self._target: str = ""

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log(self, level: int, phase: str, msg: str, *args: Any) -> None:
        """
        Log a message prefixed with the scanner's target and phase.
        
        Parameters:
            level (int): Logging level as accepted by the module logger (e.g., logging.INFO).
            phase (str): Short identifier for the current phase used in the log prefix.
            msg (str): Message format string.
            *args (Any): Optional format arguments for `msg`.
        """
        prefix = f"[tech:{self._target}] {phase} — "
        logger.log(level, prefix + msg, *args)

    def _check_cancelled(self, phase: str) -> bool:
        """
        Check whether the current scan has been cancelled and log a skipped message for the given phase.
        
        Parameters:
        	phase (str): Phase name used in the log message when the scan is skipped.
        
        Returns:
        	True if the scanner has been cancelled and the phase was skipped, False otherwise.
        """
        if self._cancelled:
            self._log(logging.INFO, phase, "Skipped (scan cancelled)")
            return True
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target: str) -> dict[str, Any]:
        """
        Perform a multi-phase technology scan of the given target and return detected findings.
        
        Parameters:
            target (str): The host or URL to scan. If no scheme is provided, both "https://" and "http://" variants are attempted.
        
        Returns:
            dict[str, Any]: A result dictionary containing:
                - "target": the original target string
                - "url": the final URL used for the scan
                - "status": HTTP status code from the fetch
                - "categories": list of detected technology categories (each a dict with keys such as "name", "score", "confidence", "category", and optionally "version")
                - "other": sorted list of additional detected technology strings
                - optional "meta_generator": raw generator value extracted from meta tags
                - optional "security_headers": detected security-related header details
                - optional "dns_hints": list of DNS-derived hints
                - optional "versions": mapping of technology name to extracted version string
        """
        self._target = target
        self._cancelled = False
        urls = self._normalize_targets(target)

        self._log(logging.INFO, "Start", "Beginning technology scan")

        # ==============================================================
        # Phase 1: HTTP Fetch
        # ==============================================================
        try:
            if self._check_cancelled("HTTP Fetch"):
                return self._empty_result(target, urls[0])
            response = self._fetch_response(target, urls)
        except KeyboardInterrupt:
            self._cancelled = True
            self._log(logging.WARNING, "HTTP Fetch", "Cancelled by user")
            return self._empty_result(target, urls[0], error="Scan cancelled by user")

        if response is None:
            return self._empty_result(target, urls[0], error="All fetch attempts failed")

        # Extract shared fingerprint data
        headers = lower_headers(response.headers)
        cookies = {n.lower(): v for n, v in response.cookies.items()}
        html = response.text or ""
        body = html.lower()
        scripts = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', html)
        script_blob = " ".join(s.lower() for s in scripts)
        stylesheets = re.findall(r'<link[^>]+href=[\'"]([^\'"]+)[\'"]', html)
        base_url = str(response.url)

        self._log(
            logging.INFO, "HTTP Fetch",
            "Got %d status, %d headers, %d cookies, %d scripts, %d stylesheets",
            response.status_code, len(headers), len(cookies),
            len(scripts), len(stylesheets),
        )

        # ==============================================================
        # Phase 2: Core detectors (shared response data)
        # ==============================================================
        categories: list[dict[str, Any]] = []
        other: list[str] = []
        meta_generator: str | None = None
        security_headers: dict[str, Any] = {}

        try:
            if not self._check_cancelled("Core Detection"):
                self._log(logging.INFO, "Core Detection", "Running detectors")

                # CMS first (for strong-platform detection)
                cms_results = detect_cms(html, headers)
                strong_platforms: set[str] = {
                    item["name"]
                    for item in cms_results
                    if item["name"] in {"Wix", "Shopify", "Webflow", "Squarespace"}
                    and item["score"] >= 8
                }

                server_results = detect_server(headers)
                backend_results = detect_backend(headers, cookies)
                frontend_results = detect_frontend(
                    body, script_blob=script_blob,
                    strong_platforms=strong_platforms,
                )
                cdn_results = detect_cdn(headers)

                for category, results in [
                    ("Server", server_results),
                    ("Backend", backend_results),
                    ("Frontend", frontend_results),
                    ("CMS", cms_results),
                    ("CDN", cdn_results),
                ]:
                    for result in results:
                        categories.append({**result, "category": category})

                other = detect_other(headers, body)
                self._log(
                    logging.INFO, "Core Detection",
                    "Found %d categories, %d other", len(categories), len(other),
                )
        except KeyboardInterrupt:
            self._cancelled = True
            self._log(logging.WARNING, "Core Detection", "Cancelled by user")
        except Exception as exc:
            self._log(logging.ERROR, "Core Detection", "Failed: %s", exc)

        # ==============================================================
        # Phase 3: Asset analysis (meta tags, scripts, stylesheets)
        # ==============================================================
        try:
            if not self._check_cancelled("Asset Analysis"):
                # Meta generator tag
                raw_gen, matched_cms = detect_from_meta_tags(html)
                if raw_gen:
                    meta_generator = raw_gen
                    self._log(logging.INFO, "Meta Tags", "Generator: %s", raw_gen)
                    if matched_cms:
                        self._boost_or_add_cms(categories, matched_cms)

                # Script sources
                script_techs = detect_from_script_sources(scripts)
                for t in script_techs:
                    if t not in other:
                        other.append(t)

                # Stylesheets
                style_techs = detect_from_stylesheets(stylesheets)
                for t in style_techs:
                    if t not in other:
                        other.append(t)

                # Cookie analysis
                cookie_techs = detect_from_cookies(cookies)
                for t in cookie_techs:
                    if t not in other:
                        other.append(t)

                # Security headers
                security_headers = detect_security_headers(headers)
        except KeyboardInterrupt:
            self._cancelled = True
        except Exception as exc:
            self._log(logging.ERROR, "Asset Analysis", "Failed: %s", exc)

        # ==============================================================
        # Phase 4: Network probes (concurrent)
        # ==============================================================
        dns_hints: list[str] = []

        try:
            if not self._check_cancelled("Probes"):
                self._log(logging.INFO, "Probes", "Running concurrent probes")
                dns_hints, probe_categories, probe_other = self._run_probes(
                    target, base_url, categories,
                )
                # Merge probe results
                existing_names = {c["name"] for c in categories}
                for pc in probe_categories:
                    if pc["name"] not in existing_names:
                        categories.append(pc)
                        existing_names.add(pc["name"])
                for po in probe_other:
                    if po not in other:
                        other.append(po)
        except KeyboardInterrupt:
            self._cancelled = True
        except Exception as exc:
            self._log(logging.ERROR, "Probes", "Failed: %s", exc)

        # ==============================================================
        # Phase 5: Version extraction
        # ==============================================================
        versions: dict[str, str] = {}
        try:
            if not self._check_cancelled("Versions"):
                versions = extract_versions(headers, body, scripts, meta_generator)
                # Apply versions to matching categories
                for cat in categories:
                    if cat["name"] in versions:
                        cat["version"] = versions[cat["name"]]
        except Exception as exc:
            self._log(logging.ERROR, "Versions", "Failed: %s", exc)

        # ==============================================================
        # Build result
        # ==============================================================
        self._log(
            logging.INFO, "Done",
            "Scan complete: %d categories, %d other, %d versions, %d DNS hints%s",
            len(categories), len(other), len(versions), len(dns_hints),
            " (partially cancelled)" if self._cancelled else "",
        )

        result: dict[str, Any] = {
            "target": target,
            "url": base_url,
            "status": response.status_code,
            "categories": categories,
            "other": sorted(set(other)),
        }
        if meta_generator:
            result["meta_generator"] = meta_generator
        if security_headers:
            result["security_headers"] = security_headers
        if dns_hints:
            result["dns_hints"] = dns_hints
        if versions:
            result["versions"] = versions

        return result

    # ------------------------------------------------------------------
    # Probe orchestration
    # ------------------------------------------------------------------

    def _run_probes(
        self,
        target: str,
        base_url: str,
        categories: list[dict[str, Any]],
    ) -> tuple[list[str], list[dict[str, Any]], list[str]]:
        """
        Coordinate concurrent network probes (DNS, robots.txt, favicon, sitemap, and optionally WordPress API) for a target and merge their findings.
        
        Parameters:
            target (str): Original scan target (used for DNS probe).
            base_url (str): Resolved base URL of the site (used for URL-scoped probes).
            categories (list[dict[str, Any]]): Current detected categories used to decide conditional probes (e.g., WordPress API).
        
        Returns:
            tuple[list[str], list[dict[str, Any]], list[str]]: A tuple of
                - `dns_hints`: list of DNS-derived hints (strings),
                - `probe_categories`: list of discovered category dictionaries from probes (e.g., CMS hints, favicon/sitemap findings),
                - `probe_other`: list of additional technology hints (strings), such as plugins or other miscellaneous findings.
        """
        dns_hints: list[str] = []
        probe_categories: list[dict[str, Any]] = []
        probe_other: list[str] = []

        # Check if WordPress is detected (for conditional WP API probe)
        wp_detected = any(
            c["name"] == "WordPress" and c.get("score", 0) >= 5
            for c in categories
        )

        probe_tasks: dict[str, Any] = {
            "dns_hints": lambda: probe_dns_hints(target),
            "robots": lambda: probe_robots_txt(base_url),
            "favicon": lambda: probe_favicon(base_url),
            "sitemap": lambda: probe_sitemap(base_url),
        }
        if wp_detected:
            probe_tasks["wp_api"] = lambda: probe_wp_api(base_url)

        with ThreadPoolExecutor(max_workers=len(probe_tasks)) as executor:
            futures = {
                executor.submit(fn): name
                for name, fn in probe_tasks.items()
            }
            for future in as_completed(futures):
                probe_name = futures[future]
                try:
                    result = future.result()
                    if result is None:
                        continue
                    self._log(logging.INFO, "Probes", "%s completed", probe_name)

                    if probe_name == "dns_hints":
                        dns_hints = result

                    elif probe_name == "robots":
                        probe_categories.extend(result.get("cms_hints", []))
                        probe_other.extend(result.get("other_hints", []))

                    elif probe_name == "favicon":
                        probe_categories.extend(result)

                    elif probe_name == "sitemap":
                        probe_categories.extend(result)

                    elif probe_name == "wp_api" and result:
                        # Add discovered plugins as "other" techs
                        for plugin in result.get("plugins", []):
                            if plugin not in probe_other:
                                probe_other.append(plugin)
                        self._log(
                            logging.INFO, "WP API",
                            "Confirmed WordPress, %d plugins",
                            len(result.get("plugins", [])),
                        )
                except Exception as exc:
                    self._log(logging.ERROR, "Probes", "%s failed: %s", probe_name, exc)

        return dns_hints, probe_categories, probe_other

    # ------------------------------------------------------------------
    # Meta-tag boosting
    # ------------------------------------------------------------------

    @staticmethod
    def _boost_or_add_cms(
        categories: list[dict[str, Any]],
        cms_name: str,
    ) -> None:
        """
        Increase the score of an existing CMS category entry or append a new CMS entry to the list.
        
        If a category with name equal to `cms_name` exists, its `score` is increased by 2 (capped at 10), its `confidence` is updated using `confidence_label(score)`, and its `meter` string is updated to visually reflect the score. If no such entry exists, a new CMS category dictionary is appended with `score` set to 8, `confidence` set to "High", `meter` set to "████████░░", and `category` set to "CMS". The `categories` list is mutated in place.
        
        Parameters:
            categories (list[dict[str, Any]]): Mutable list of category dictionaries to update.
            cms_name (str): Name of the CMS to boost or add.
        """
        existing = [c for c in categories if c["name"] == cms_name]
        if existing:
            entry = existing[0]
            entry["score"] = min(10, entry["score"] + 2)
            entry["confidence"] = confidence_label(entry["score"])
            entry["meter"] = "█" * entry["score"] + "░" * (10 - entry["score"])
        else:
            categories.append({
                "name": cms_name,
                "score": 8,
                "confidence": "High",
                "meter": "████████░░",
                "category": "CMS",
            })

    # ------------------------------------------------------------------
    # HTTP fetch
    # ------------------------------------------------------------------

    def _fetch_response(
        self,
        target: str,
        urls: list[str],
    ) -> httpx.Response | None:
        """
        Attempt candidate URLs in order and return the first successful HTTP response, using redirect and SSL-fallback strategies.
        
        Tries each URL from `urls` until a response is obtained or the scanner is cancelled. For 3xx redirects, if the Location header points to an HTTPS URL the function attempts a follow-up request to that location. On recognized SSL-related errors it retries the request with TLS verification disabled and redirects enabled. The method logs outcomes and returns the first obtained `httpx.Response` or `None` if all attempts fail.
        
        Parameters:
            target (str): Original target string (used for log prefixes).
            urls (list[str]): Candidate URLs to try (e.g., ["https://example", "http://example"]).
        
        Returns:
            httpx.Response | None: The first successful response object, or `None` if no request succeeded.
        """
        last_error: str | None = None
        response: httpx.Response | None = None

        for url in urls:
            if self._cancelled:
                break
            try:
                self._log(logging.INFO, "HTTP Fetch", "Trying %s", url)
                with httpx.Client(
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                ) as client:
                    response = client.get(url)
                    self._log(
                        logging.INFO, "HTTP Fetch",
                        "Got %d from %s", response.status_code, url,
                    )

                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location", "")
                        self._log(logging.INFO, "HTTP Fetch", "Redirect → %s", location or "<missing>")
                        if location.startswith("https://"):
                            try:
                                response = client.get(location)
                                self._log(
                                    logging.INFO, "HTTP Fetch",
                                    "HTTPS redirect succeeded: %d", response.status_code,
                                )
                            except Exception as exc:
                                self._log(
                                    logging.WARNING, "HTTP Fetch",
                                    "HTTPS redirect failed, using original: %s", exc,
                                )
                return response
            except _SSL_ERROR_TYPES as exc:
                self._log(
                    logging.WARNING, "HTTP Fetch",
                    "SSL error on %s: %s — retrying without verification", url, exc,
                )
                try:
                    with httpx.Client(
                        headers=HEADERS,
                        timeout=REQUEST_TIMEOUT,
                        follow_redirects=True,
                        verify=False,
                    ) as client:
                        response = client.get(url)
                    self._log(
                        logging.INFO, "HTTP Fetch",
                        "Unverified TLS succeeded: %d", response.status_code,
                    )
                    return response
                except Exception as inner:
                    last_error = str(inner)
                    self._log(logging.ERROR, "HTTP Fetch", "Unverified TLS also failed: %s", inner)
            except Exception as exc:
                last_error = str(exc)
                self._log(logging.ERROR, "HTTP Fetch", "Request failed for %s: %s", url, exc)

        if response is None and last_error:
            self._log(logging.ERROR, "HTTP Fetch", "All attempts failed, last error: %s", last_error)
        return response

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_result(
        target: str,
        url: str,
        *,
        error: str | None = None,
    ) -> dict[str, Any]:
        """
        Construct a minimal scan result dictionary containing the provided target and URL with empty detection outputs.
        
        Parameters:
            target (str): The original scan target string.
            url (str): The resolved/requested base URL for the scan.
            error (str | None): Optional error message to include in the result.
        
        Returns:
            dict[str, Any]: Result dictionary with keys:
                - "target": the provided target
                - "url": the provided url
                - "categories": empty list for detected categories
                - "other": empty list for miscellaneous findings
                - "error": included only if `error` is provided
        """
        result: dict[str, Any] = {
            "target": target,
            "url": url,
            "categories": [],
            "other": [],
        }
        if error:
            result["error"] = error
        return result

    @staticmethod
    def _normalize_targets(target: str) -> list[str]:
        """
        Produce normalized HTTP(S) candidate URLs for a scan target.
        
        Parameters:
            target (str): A hostname or full URL. If `target` already starts with `http://` or `https://`, it is treated as a full URL.
        
        Returns:
            list[str]: A list containing the input URL if a scheme was present, otherwise a two-item list with `https://{target}` first and `http://{target}` second.
        """
        if target.startswith(("http://", "https://")):
            return [target]
        return [f"https://{target}", f"http://{target}"]
