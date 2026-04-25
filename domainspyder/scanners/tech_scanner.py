"""
DomainSpyder technology scanner.

Multi-method, rule-based technology detection.  Runs a pipeline
of detection strategies (HTTP fingerprinting, meta-tag parsing,
script/stylesheet analysis, robots.txt probing, security-header
audit, and DNS-TXT hints) so that partial failures in one method
do not block the others.
"""

from __future__ import annotations

import logging
import re
import ssl
from typing import Any

import dns.resolver
import httpx

from domainspyder.config import HEADERS, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SSL_ERROR_TYPES = (
    ssl.SSLError,
    httpx.ConnectError,
    httpx.RemoteProtocolError,
)


def _lower_headers(raw: httpx.Headers) -> dict[str, str]:
    """Return a plain dict with all header keys lowercased."""
    return {k.lower(): v for k, v in raw.items()}


def _header_blob(*values: str) -> str:
    """Concatenate header values into one lowercased search string."""
    return " ".join(v.lower() for v in values if v)


class TechScanner:
    """
    Detect common web technologies via a multi-method pipeline.

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

    def _log(
        self,
        level: int,
        phase: str,
        message: str,
        *args: Any,
    ) -> None:
        """Structured log with target + phase context."""
        prefix = f"[tech:{self._target}] {phase} — "
        logger.log(level, prefix + message, *args)

    def _debug_log(self, message: str, *args: Any) -> None:
        """Emit debug logs only when scanner debugging is enabled."""
        if self._debug:
            logger.debug(message, *args)

    def _check_cancelled(self, phase: str) -> bool:
        """Return True (and log) if the scan was cancelled."""
        if self._cancelled:
            self._log(logging.INFO, phase, "Skipped (scan cancelled)")
            return True
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target: str) -> dict[str, Any]:
        """Run multi-method technology detection and return structured results."""
        self._target = target
        self._cancelled = False
        urls = self._normalize_targets(target)

        self._log(logging.INFO, "Start", "Beginning technology scan")

        # ----------------------------------------------------------
        # Phase 1: HTTP Fetch
        # ----------------------------------------------------------
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

        # Extract common fingerprint data
        headers = _lower_headers(response.headers)
        cookies = {name.lower(): value for name, value in response.cookies.items()}
        html = response.text or ""
        body = html.lower()
        scripts = re.findall(r'<script[^\>]+src=[\'"]([^\'"]+)[\'"]', html)
        script_blob = " ".join(s.lower() for s in scripts)
        stylesheets = re.findall(r'<link[^>]+href=[\'"]([^\'"]+)[\'"]', html)
        style_blob = " ".join(s.lower() for s in stylesheets)

        self._log(
            logging.INFO, "HTTP Fetch",
            "Got %d status, %d headers, %d cookies, %d scripts, %d stylesheets, %d body chars",
            response.status_code, len(headers), len(cookies),
            len(scripts), len(stylesheets), len(html),
        )

        # ----------------------------------------------------------
        # Phase 2: Core fingerprinting (existing detectors)
        # ----------------------------------------------------------
        categories: list[dict[str, Any]] = []
        other: list[str] = []
        meta_generator: str | None = None
        security_headers: dict[str, Any] = {}
        dns_hints: list[str] = []

        try:
            if not self._check_cancelled("Core Detection"):
                self._log(logging.INFO, "Core Detection", "Running CMS/server/backend/frontend/CDN detectors")
                cms_results = self.detect_cms(html, headers)
                strong_platforms: set[str] = {
                    item["name"]
                    for item in cms_results
                    if item["name"] in {"Wix", "Shopify", "Webflow", "Squarespace"}
                    and item["score"] >= 8
                }
                server_results = self.detect_server(headers)
                backend_results = self.detect_backend(headers, cookies)
                frontend_results = self.detect_frontend(
                    body, script_blob=script_blob, strong_platforms=strong_platforms,
                )
                cdn_results = self.detect_cdn(headers)

                for category, results in [
                    ("Server", server_results), ("Backend", backend_results),
                    ("Frontend", frontend_results), ("CMS", cms_results),
                    ("CDN", cdn_results),
                ]:
                    for result in results:
                        categories.append({**result, "category": category})

                other = self.detect_other(headers, body)
                self._log(logging.INFO, "Core Detection", "Found %d categories, %d other", len(categories), len(other))
        except KeyboardInterrupt:
            self._cancelled = True
            self._log(logging.WARNING, "Core Detection", "Cancelled by user")
        except Exception as exc:
            self._log(logging.ERROR, "Core Detection", "Failed: %s", exc)

        # ----------------------------------------------------------
        # Phase 3: Meta generator tags
        # ----------------------------------------------------------
        try:
            if not self._check_cancelled("Meta Tags"):
                meta_generator = self._detect_from_meta_tags(html, categories)
        except KeyboardInterrupt:
            self._cancelled = True
        except Exception as exc:
            self._log(logging.ERROR, "Meta Tags", "Failed: %s", exc)

        # ----------------------------------------------------------
        # Phase 4: Script source deep analysis
        # ----------------------------------------------------------
        try:
            if not self._check_cancelled("Script Analysis"):
                self._detect_from_script_sources(scripts, other)
        except KeyboardInterrupt:
            self._cancelled = True
        except Exception as exc:
            self._log(logging.ERROR, "Script Analysis", "Failed: %s", exc)

        # ----------------------------------------------------------
        # Phase 5: Stylesheet analysis
        # ----------------------------------------------------------
        try:
            if not self._check_cancelled("Stylesheet Analysis"):
                self._detect_from_stylesheets(stylesheets, other)
        except KeyboardInterrupt:
            self._cancelled = True
        except Exception as exc:
            self._log(logging.ERROR, "Stylesheet Analysis", "Failed: %s", exc)

        # ----------------------------------------------------------
        # Phase 6: robots.txt probe
        # ----------------------------------------------------------
        try:
            if not self._check_cancelled("robots.txt Probe"):
                self._probe_robots_txt(str(response.url), categories, other)
        except KeyboardInterrupt:
            self._cancelled = True
        except Exception as exc:
            self._log(logging.ERROR, "robots.txt Probe", "Failed: %s", exc)

        # ----------------------------------------------------------
        # Phase 7: Security headers
        # ----------------------------------------------------------
        try:
            if not self._check_cancelled("Security Headers"):
                security_headers = self._detect_security_headers(headers)
        except KeyboardInterrupt:
            self._cancelled = True
        except Exception as exc:
            self._log(logging.ERROR, "Security Headers", "Failed: %s", exc)

        # ----------------------------------------------------------
        # Phase 8: DNS TXT hints
        # ----------------------------------------------------------
        try:
            if not self._check_cancelled("DNS Hints"):
                dns_hints = self._detect_dns_hints(target)
        except KeyboardInterrupt:
            self._cancelled = True
        except Exception as exc:
            self._log(logging.ERROR, "DNS Hints", "Failed: %s", exc)

        self._log(
            logging.INFO, "Done",
            "Scan complete: %d categories, %d other, %d DNS hints%s",
            len(categories), len(other), len(dns_hints),
            " (partially cancelled)" if self._cancelled else "",
        )

        result: dict[str, Any] = {
            "target": target,
            "url": str(response.url),
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

        return result

    # ------------------------------------------------------------------
    # Pipeline helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_result(
        target: str,
        url: str,
        *,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Return a minimal result dict when the scan cannot proceed."""
        result: dict[str, Any] = {
            "target": target,
            "url": url,
            "categories": [],
            "other": [],
        }
        if error:
            result["error"] = error
        return result

    def _fetch_response(
        self,
        target: str,
        urls: list[str],
    ) -> httpx.Response | None:
        """Try each URL candidate, handling redirects and SSL errors."""
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
                self._log(logging.WARNING, "HTTP Fetch", "SSL error on %s: %s — retrying without verification", url, exc)
                try:
                    with httpx.Client(
                        headers=HEADERS,
                        timeout=REQUEST_TIMEOUT,
                        follow_redirects=True,
                        verify=False,
                    ) as client:
                        response = client.get(url)
                    self._log(logging.INFO, "HTTP Fetch", "Unverified TLS succeeded: %d", response.status_code)
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
    # NEW: Meta generator tag detection
    # ------------------------------------------------------------------

    def _detect_from_meta_tags(
        self,
        html: str,
        categories: list[dict[str, Any]],
    ) -> str | None:
        """Parse <meta name='generator'> and boost matching CMS/framework."""
        self._log(logging.INFO, "Meta Tags", "Scanning for generator meta tags")
        match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        if not match:
            # Try reversed attribute order
            match = re.search(
                r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
                html,
                re.IGNORECASE,
            )
        if not match:
            self._log(logging.INFO, "Meta Tags", "No generator tag found")
            return None

        generator = match.group(1).strip()
        self._log(logging.INFO, "Meta Tags", "Found generator: %s", generator)

        gen_lower = generator.lower()
        _generator_map = {
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
        for key, name in _generator_map.items():
            if key in gen_lower:
                # Boost if already in categories, otherwise add
                existing = [c for c in categories if c["name"] == name]
                if existing:
                    existing[0]["score"] = min(10, existing[0]["score"] + 2)
                    existing[0]["confidence"] = self._confidence_label(existing[0]["score"])
                    existing[0]["meter"] = "█" * existing[0]["score"] + "░" * (10 - existing[0]["score"])
                else:
                    categories.append({
                        "name": name,
                        "score": 8,
                        "confidence": "High",
                        "meter": "████████░░",
                        "category": "CMS",
                    })
                self._log(logging.INFO, "Meta Tags", "Boosted %s from generator tag", name)
                break

        return generator

    # ------------------------------------------------------------------
    # NEW: Script source deep analysis
    # ------------------------------------------------------------------

    def _detect_from_script_sources(
        self,
        scripts: list[str],
        other: list[str],
    ) -> None:
        """Detect bundlers, frameworks, and libraries from script src URLs."""
        self._log(logging.INFO, "Script Analysis", "Analysing %d script sources", len(scripts))
        if not scripts:
            return

        blob = " ".join(s.lower() for s in scripts)

        _script_patterns: list[tuple[str, str]] = [
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

        found = 0
        for pattern, label in _script_patterns:
            if pattern in blob and label not in other:
                other.append(label)
                found += 1

        self._log(logging.INFO, "Script Analysis", "Found %d technologies from scripts", found)

    # ------------------------------------------------------------------
    # NEW: Stylesheet analysis
    # ------------------------------------------------------------------

    def _detect_from_stylesheets(
        self,
        stylesheets: list[str],
        other: list[str],
    ) -> None:
        """Detect UI libraries from stylesheet hrefs."""
        self._log(logging.INFO, "Stylesheet Analysis", "Analysing %d stylesheet links", len(stylesheets))
        if not stylesheets:
            return

        blob = " ".join(s.lower() for s in stylesheets)

        _css_patterns: list[tuple[str, str]] = [
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

        found = 0
        for pattern, label in _css_patterns:
            if pattern in blob and label not in other:
                other.append(label)
                found += 1

        self._log(logging.INFO, "Stylesheet Analysis", "Found %d technologies from stylesheets", found)

    # ------------------------------------------------------------------
    # NEW: robots.txt probe
    # ------------------------------------------------------------------

    def _probe_robots_txt(
        self,
        base_url: str,
        categories: list[dict[str, Any]],
        other: list[str],
    ) -> None:
        """Fetch /robots.txt and look for CMS admin paths."""
        # Build robots URL from the response URL
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(base_url)
        robots_url = urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))

        self._log(logging.INFO, "robots.txt Probe", "Fetching %s", robots_url)

        try:
            with httpx.Client(
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = client.get(robots_url)
        except Exception as exc:
            self._log(logging.WARNING, "robots.txt Probe", "Fetch failed: %s", exc)
            return

        if resp.status_code != 200:
            self._log(logging.INFO, "robots.txt Probe", "Got %d, skipping", resp.status_code)
            return

        text = resp.text.lower()
        self._log(logging.INFO, "robots.txt Probe", "Got %d bytes of robots.txt", len(text))

        _robots_hints: list[tuple[str, str, str]] = [
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

        found = 0
        existing_names = {c["name"] for c in categories}
        for pattern, name, cat in _robots_hints:
            if pattern in text:
                if cat and name not in existing_names:
                    categories.append({
                        "name": name,
                        "score": 5,
                        "confidence": "Medium",
                        "meter": "█████░░░░░",
                        "category": cat,
                    })
                    existing_names.add(name)
                    found += 1
                elif not cat and name not in other:
                    other.append(name)
                    found += 1

        self._log(logging.INFO, "robots.txt Probe", "Found %d hints from robots.txt", found)

    # ------------------------------------------------------------------
    # NEW: Security headers analysis
    # ------------------------------------------------------------------

    def _detect_security_headers(
        self,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Audit security-related response headers."""
        self._log(logging.INFO, "Security Headers", "Analysing security headers")

        findings: dict[str, Any] = {}

        # HSTS
        hsts = headers.get("strict-transport-security")
        if hsts:
            findings["hsts"] = {"present": True, "value": hsts}
        else:
            findings["hsts"] = {"present": False}

        # Content-Security-Policy
        csp = headers.get("content-security-policy")
        if csp:
            findings["csp"] = {"present": True, "length": len(csp)}
        else:
            findings["csp"] = {"present": False}

        # X-Frame-Options
        xfo = headers.get("x-frame-options")
        if xfo:
            findings["x_frame_options"] = {"present": True, "value": xfo}
        else:
            findings["x_frame_options"] = {"present": False}

        # X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        findings["x_content_type_options"] = {"present": bool(xcto), "value": xcto or ""}

        # Referrer-Policy
        rp = headers.get("referrer-policy")
        findings["referrer_policy"] = {"present": bool(rp), "value": rp or ""}

        # Permissions-Policy
        pp = headers.get("permissions-policy")
        findings["permissions_policy"] = {"present": bool(pp)}

        present_count = sum(1 for v in findings.values() if v.get("present"))
        self._log(
            logging.INFO, "Security Headers",
            "%d/%d security headers present", present_count, len(findings),
        )

        return findings

    # ------------------------------------------------------------------
    # NEW: DNS TXT hints
    # ------------------------------------------------------------------

    def _detect_dns_hints(self, target: str) -> list[str]:
        """Resolve TXT records for domain verification signals."""
        # Strip protocol/path to get bare domain
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        self._log(logging.INFO, "DNS Hints", "Resolving TXT records for %s", domain)

        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        except Exception as exc:
            self._log(logging.WARNING, "DNS Hints", "TXT lookup failed: %s", exc)
            return []

        hints: list[str] = []
        _verification_patterns: list[tuple[str, str]] = [
            ("google-site-verification", "Google Search Console verified"),
            ("facebook-domain-verification", "Facebook domain verified"),
            ("apple-domain-verification", "Apple domain verified"),
            ("ms=", "Microsoft 365 verified"),
            ("atlassian-domain-verification", "Atlassian verified"),
            ("docusign", "DocuSign verified"),
            ("stripe-verification", "Stripe verified"),
            ("hubspot", "HubSpot verified"),
            ("shopify-verification", "Shopify verified"),
            ("blitz=", "Blitz verified"),
            ("_github-pages-challenge", "GitHub Pages verified"),
            ("postman-domain-verification", "Postman verified"),
            ("twilio-domain-verification", "Twilio verified"),
            ("amazonses", "Amazon SES configured"),
            ("v=spf1", "SPF record configured"),
            ("v=dmarc1", "DMARC configured"),
        ]

        for rdata in answers:
            txt = "".join(part.decode() if isinstance(part, bytes) else part for part in rdata.strings)
            txt_lower = txt.lower()
            for pattern, label in _verification_patterns:
                if pattern in txt_lower and label not in hints:
                    hints.append(label)

        self._log(logging.INFO, "DNS Hints", "Found %d verification/config hints", len(hints))
        return hints

    # ------------------------------------------------------------------
    # Server detection
    # ------------------------------------------------------------------

    def detect_server(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        """Detect the web server from response headers."""
        server_val = headers.get("server", "").lower()
        x_powered = headers.get("x-powered-by", "").lower()
        blob = f"{server_val} {x_powered}"

        candidates: dict[str, dict[str, int]] = {
            "nginx":     {"signals": 0, "score": 0},
            "Apache":    {"signals": 0, "score": 0},
            "IIS":       {"signals": 0, "score": 0},
            "Caddy":     {"signals": 0, "score": 0},
            "LiteSpeed": {"signals": 0, "score": 0},
            "Gunicorn":  {"signals": 0, "score": 0},
            "Cloudflare":{"signals": 0, "score": 0},
            "Kestrel":   {"signals": 0, "score": 0},
        }

        if "nginx" in server_val:
            self._boost(candidates["nginx"], 2, 9)
        if "apache" in server_val:
            self._boost(candidates["Apache"], 2, 9)
        if "microsoft-iis" in server_val or "iis" in server_val:
            self._boost(candidates["IIS"], 2, 9)
        if "caddy" in server_val:
            self._boost(candidates["Caddy"], 2, 9)
        if "litespeed" in server_val or "lsws" in server_val:
            self._boost(candidates["LiteSpeed"], 2, 9)
        if "gunicorn" in server_val:
            self._boost(candidates["Gunicorn"], 2, 9)
        if "cloudflare" in server_val:
            self._boost(candidates["Cloudflare"], 2, 9)
        if "kestrel" in server_val:
            self._boost(candidates["Kestrel"], 2, 9)

        return self._finalize_all(candidates)

    # ------------------------------------------------------------------
    # Backend detection
    # ------------------------------------------------------------------

    def detect_backend(
        self,
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Detect backend language/framework via headers and cookies."""
        x_powered = headers.get("x-powered-by", "").lower()
        server_val = headers.get("server", "").lower()
        set_cookie = headers.get("set-cookie", "").lower()
        blob = f"{x_powered} {server_val} {set_cookie}"

        candidates: dict[str, dict[str, int]] = {
            "PHP":        {"signals": 0, "score": 0},
            "Node.js":    {"signals": 0, "score": 0},
            "Java":       {"signals": 0, "score": 0},
            "Python":     {"signals": 0, "score": 0},
            "Ruby":       {"signals": 0, "score": 0},
            "ASP.NET":    {"signals": 0, "score": 0},
            "Go":         {"signals": 0, "score": 0},
        }

        # PHP
        if "php" in blob:
            self._boost(candidates["PHP"], 2, 8)
        if "phpsessid" in cookies:
            self._boost(candidates["PHP"], 1, 3)
        if re.search(r"php/[\d.]", x_powered):
            self._boost(candidates["PHP"], 1, 2)

        # Node.js / Express / Next
        if any(t in blob for t in ["express", "node.js", "next.js"]):
            self._boost(candidates["Node.js"], 2, 7)
        if any(n in cookies for n in ["connect.sid", "__next_preview_data", "next-auth.session-token"]):
            self._boost(candidates["Node.js"], 1, 3)
        if headers.get("x-powered-by", "").lower() == "next.js":
            self._boost(candidates["Node.js"], 1, 3)

        # Java / Spring / JEE
        if any(t in blob for t in ["jsp", "servlet", "spring", "jsessionid", "java"]):
            self._boost(candidates["Java"], 2, 7)
        if "jsessionid" in cookies:
            self._boost(candidates["Java"], 1, 3)

        # Python (Django / Flask / FastAPI)
        if any(t in blob for t in ["django", "flask", "fastapi", "python", "werkzeug", "uvicorn"]):
            self._boost(candidates["Python"], 2, 7)
        if "csrftoken" in cookies:                        # Django default
            self._boost(candidates["Python"], 1, 3)
        if "sessionid" in cookies and "csrftoken" in cookies:
            self._boost(candidates["Python"], 1, 2)

        # Ruby on Rails
        if any(t in blob for t in ["ruby", "rails", "rack", "passenger", "phusion"]):
            self._boost(candidates["Ruby"], 2, 7)
        if "_session_id" in cookies or "_rails_session" in cookies:
            self._boost(candidates["Ruby"], 1, 3)

        # ASP.NET / .NET Core
        if any(t in blob for t in ["asp.net", "aspnetcore", ".net", "aspxerrorpath", "webmatrix"]):
            self._boost(candidates["ASP.NET"], 2, 8)
        if "asp.net_sessionid" in cookies or ".aspxauth" in cookies:
            self._boost(candidates["ASP.NET"], 1, 3)
        if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
            self._boost(candidates["ASP.NET"], 2, 5)

        # Go
        if any(t in blob for t in ["go ", "golang", "gin-gonic", "gorilla", "echo"]):
            self._boost(candidates["Go"], 2, 6)
        if server_val in ("", "go") or "go/" in server_val:
            self._boost(candidates["Go"], 1, 3)

        return self._finalize_all(candidates)

    # ------------------------------------------------------------------
    # Frontend detection
    # ------------------------------------------------------------------

    def detect_frontend(
        self,
        body: str,
        script_blob: str = "",
        strong_platforms: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Detect frontend SPA frameworks from HTML content (pre-lowercased)."""
        strong_platforms = strong_platforms or set()

        candidates: dict[str, dict[str, int]] = {
            "React":   {"signals": 0, "score": 0},
            "Angular": {"signals": 0, "score": 0},
            "Vue":     {"signals": 0, "score": 0},
            "Svelte":  {"signals": 0, "score": 0},
            "Astro":   {"signals": 0, "score": 0},
            "Ionic":   {"signals": 0, "score": 0},
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
            self._boost(candidates["React"], 2, 8)
        elif react_count >= 2:
            self._boost(candidates["React"], react_count, min(10, 4 + react_count * 2))
        elif react_count == 1:
            self._boost(candidates["React"], 1, 2)

        # Angular
        angular_signals = [
            "ng-version", "ng-app", "ng-controller", "ng-model",
            "main-es2015", "runtime-es2015", "polyfills-es2015",
            "[_nghost", "[_ngcontent", "ng-reflect",
        ]
        ang_count = sum(1 for s in angular_signals if s in body)
        if ang_count >= 2:
            self._boost(candidates["Angular"], ang_count, min(10, 4 + ang_count * 2))
        elif ang_count == 1:
            self._boost(candidates["Angular"], 1, 3)
        # Modern Angular (bundled apps)
        if any(x in body for x in ["main.", "polyfills.", "runtime."]):
            self._boost(candidates["Angular"], 1, 4)
        
        if any(x in script_blob for x in ["main.", "polyfills.", "runtime."]):
            self._boost(candidates["Angular"], 2, 7)

        # Strong Angular signal
        if "ng-version" in body:
            self._boost(candidates["Angular"], 2, 8)
        if "zone.js" in body:
            self._boost(candidates["Angular"], 1, 4)
        
        # ---- Ionic ---------------------------------------------------
        ionic_signals = [
            "ionic", "ion-app", "ion-content", "ion-router", "ion-page"
        ]
        ionic_count = sum(1 for s in ionic_signals if s in body)

        if ionic_count >= 2:
            self._boost(candidates["Ionic"], ionic_count, min(10, 6 + ionic_count))
        elif ionic_count == 1:
            self._boost(candidates["Ionic"], 1, 4)
        # Vue
        vue_signals = [
            "data-v-", "__vue__", "vue.js", "vue.min.js",
            "vue-router", "vuex", "__vue_app__", "createapp(",
            "v-cloak", ":class=", "@click=",
        ]
        vue_count = sum(1 for s in vue_signals if s in body)
        if vue_count >= 2:
            self._boost(candidates["Vue"], vue_count, min(10, 4 + vue_count * 2))
        elif vue_count == 1:
            self._boost(candidates["Vue"], 1, 3)

        # Svelte / SvelteKit
        svelte_signals = [
            "__svelte", "svelte-", "sveltekit", "_app/immutable",
            "data-svelte-h", "svelte/transition",
        ]
        svel_count = sum(1 for s in svelte_signals if s in body)
        if svel_count >= 2:
            self._boost(candidates["Svelte"], svel_count, min(10, 5 + svel_count * 2))
        elif svel_count == 1:
            self._boost(candidates["Svelte"], 1, 4)

        # Astro
        astro_signals = [
            "astro-island", "astro:page-load", "_astro/",
            'data-astro-cid', "astro.config",
        ]
        astro_count = sum(1 for s in astro_signals if s in body)
        if astro_count >= 1:
            self._boost(candidates["Astro"], astro_count, min(10, 5 + astro_count * 2))

        # Suppress frameworks on strong hosted platforms (they fake SPA signals)
        if strong_platforms:
            for name in ("React", "Angular", "Vue", "Svelte", "Astro"):
                candidates[name]["score"] = max(0, candidates[name]["score"] - 3)
                if candidates[name]["score"] < 3:
                    candidates[name]["signals"] = 0

        return self._finalize_all(candidates)

    # ------------------------------------------------------------------
    # CMS detection
    # ------------------------------------------------------------------

    def detect_cms(
        self,
        html: str,
        headers: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Detect CMS / website-builder platforms."""
        body = html.lower()
        headers = headers or {}
        header_blob = _header_blob(*headers.values())

        candidates: dict[str, dict[str, int]] = {
            "WordPress":   {"signals": 0, "score": 0},
            "Joomla":      {"signals": 0, "score": 0},
            "Drupal":      {"signals": 0, "score": 0},
            "Wix":         {"signals": 0, "score": 0},
            "Shopify":     {"signals": 0, "score": 0},
            "Webflow":     {"signals": 0, "score": 0},
            "Squarespace": {"signals": 0, "score": 0},
            "Ghost":       {"signals": 0, "score": 0},
            "HubSpot":     {"signals": 0, "score": 0},
            "Magento":     {"signals": 0, "score": 0},
            "PrestaShop":  {"signals": 0, "score": 0},
            "BigCommerce": {"signals": 0, "score": 0},
        }

        # ---- WordPress ------------------------------------------------
        wp_signals = [
            "wp-content", "wp-includes", "wordpress",
            'generator" content="wordpress',
            "/wp-json/", "wp-block-", "wp-emoji",
        ]
        wp_count = sum(1 for s in wp_signals if s in body)
        if wp_count >= 2:
            self._boost(candidates["WordPress"], wp_count, min(10, 6 + wp_count))
        elif wp_count == 1:
            self._boost(candidates["WordPress"], 1, 5)

        # ---- Joomla ---------------------------------------------------
        joomla_signals = [
            "/media/system/js/", "com_content", "joomla!",
            'generator" content="joomla', "/media/jui/", "joomla.document",
        ]
        joomla_count = sum(1 for s in joomla_signals if s in body)
        if joomla_count >= 1:
            self._boost(candidates["Joomla"], joomla_count, min(10, 6 + joomla_count))

        # ---- Drupal ---------------------------------------------------
        drupal_signals = [
            "/sites/default/", "/misc/drupal.js", "drupal-settings-json",
            'generator" content="drupal', "drupal.js", "drupal.behaviors",
            "/core/themes/", "/modules/contrib/",
        ]
        drupal_count = sum(1 for s in drupal_signals if s in body)
        if drupal_count >= 1:
            self._boost(candidates["Drupal"], drupal_count, min(10, 6 + drupal_count))
        if "x-drupal-cache" in headers or "x-drupal-dynamic-cache" in headers:
            self._boost(candidates["Drupal"], 2, 5)

        # ---- Wix (body + headers) ------------------------------------
        wix_body_signals = [
            "wix.com", "wixstatic.com", "wix-image",
            "siteassets", "wix-code", "parastorage.com",
            "_wixcms", "wix-bolt", "wixapps.net",
        ]
        wix_count = sum(1 for s in wix_body_signals if s in body)
        # Header-based Wix signals
        wix_header_signals = [
            "x-wix-request-id", "x-wix-renderer-server",
            "x-wix-published-version",
        ]
        wix_header_count = sum(1 for h in wix_header_signals if h in headers)
        total_wix = wix_count + wix_header_count * 2  # headers are stronger
        if total_wix >= 2:
            self._boost(candidates["Wix"], 2, min(10, 7 + total_wix))
        elif total_wix == 1:
            self._boost(candidates["Wix"], 1, 5)

        # ---- Shopify (body + headers) --------------------------------
        shopify_body = [
            "cdn.shopify.com", "shopify.com", "shopify",
            "myshopify.com", "/cart.js", "shopify-section",
            "shopify_analytics",
        ]
        shopify_header_keys = [
            "x-shopid", "x-shardid", "x-sorting-hat-podid",
            "x-shopify-stage",
        ]
        # Header blob check for Shopify
        shopify_body_count = sum(1 for s in shopify_body if s in body or s in header_blob)
        shopify_hdr_count = sum(1 for h in shopify_header_keys if h in headers)
        total_shopify = shopify_body_count + shopify_hdr_count * 2
        if total_shopify >= 2:
            self._boost(candidates["Shopify"], 2, min(10, 7 + total_shopify))
        elif total_shopify == 1:
            self._boost(candidates["Shopify"], 1, 5)

        # ---- Webflow -------------------------------------------------
        webflow_signals = [
            "webflow", "webflow.io", "wf-force-outline-none",
            "data-wf-page", "data-wf-site", "js.webflow.com",
        ]
        wf_count = sum(1 for s in webflow_signals if s in body)
        if wf_count >= 2:
            self._boost(candidates["Webflow"], 2, min(10, 7 + wf_count))
        elif wf_count == 1:
            self._boost(candidates["Webflow"], 1, 5)

        # ---- Squarespace --------------------------------------------
        sqsp_signals = [
            "squarespace.com", "squarespace", "static1.squarespace.com",
            "sqsp-templates", "sqsptheme", "data-layout-label",
            "squarespace-cdn.com",
        ]
        sqsp_count = sum(1 for s in sqsp_signals if s in body)
        if "x-servedby" in headers and "squarespace" in headers.get("x-servedby", "").lower():
            sqsp_count += 2
        if sqsp_count >= 2:
            self._boost(candidates["Squarespace"], 2, min(10, 7 + sqsp_count))
        elif sqsp_count == 1:
            self._boost(candidates["Squarespace"], 1, 5)

        # ---- Ghost ---------------------------------------------------
        ghost_signals = [
            "ghost.io", "content/themes/", "ghost/", "ghost-url",
            'generator" content="ghost',
        ]
        ghost_count = sum(1 for s in ghost_signals if s in body)
        if ghost_count >= 1:
            self._boost(candidates["Ghost"], ghost_count, min(10, 6 + ghost_count))

        # ---- HubSpot CMS ---------------------------------------------
        hs_signals = [
            "hs-scripts.com", "hubspot.com", "hscta-", "hs-cta-",
            "_hsp.push", "hubspotutk",
        ]
        hs_count = sum(1 for s in hs_signals if s in body)
        if "x-hs-hub-id" in headers or "hubspotutk" in headers:
            hs_count += 2
        if hs_count >= 2:
            self._boost(candidates["HubSpot"], 2, min(10, 6 + hs_count))
        elif hs_count == 1:
            self._boost(candidates["HubSpot"], 1, 4)

        # ---- Magento (Adobe Commerce) --------------------------------
        magento_signals = [
            "magento", "mage/", "varien", "skin/frontend/",
            "pub/static/", "requirejs/require.js", "checkout/cart/",
        ]
        mag_count = sum(1 for s in magento_signals if s in body)
        if mag_count >= 2:
            self._boost(candidates["Magento"], mag_count, min(10, 6 + mag_count))
        elif mag_count == 1:
            self._boost(candidates["Magento"], 1, 4)

        # ---- PrestaShop ----------------------------------------------
        presta_signals = [
            "prestashop", "presta-shop", "/modules/", "addons.prestashop.com",
            "id_product", "id_category",
        ]
        pre_count = sum(1 for s in presta_signals if s in body)
        if pre_count >= 2:
            self._boost(candidates["PrestaShop"], pre_count, min(10, 6 + pre_count))

        # ---- BigCommerce ---------------------------------------------
        bc_signals = [
            "bigcommerce", "bigcommerce.com", "cdn11.bigcommerce.com",
            "stencil-utils", "bigpay.site",
        ]
        bc_count = sum(1 for s in bc_signals if s in body)
        if bc_count >= 1:
            self._boost(candidates["BigCommerce"], bc_count, min(10, 7 + bc_count))

        # ---- Cross-CMS suppression ----------------------------------
        # If a strong hosted platform is detected, suppress WordPress/Drupal false positives
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

        return self._finalize_all(candidates)

    # ------------------------------------------------------------------
    # CDN / edge detection
    # ------------------------------------------------------------------

    def detect_cdn(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        """Detect CDN / edge network providers from response headers."""
        candidates: dict[str, dict[str, int]] = {
            "Cloudflare":    {"signals": 0, "score": 0},
            "AWS CloudFront":{"signals": 0, "score": 0},
            "Vercel":        {"signals": 0, "score": 0},
            "Fastly":        {"signals": 0, "score": 0},
            "Akamai":        {"signals": 0, "score": 0},
            "Azure CDN":     {"signals": 0, "score": 0},
            "Google Cloud":  {"signals": 0, "score": 0},
            "BunnyCDN":      {"signals": 0, "score": 0},
            "Netlify":       {"signals": 0, "score": 0},
        }

        server_val = headers.get("server", "").lower()
        via_val = headers.get("via", "").lower()
        x_cache = headers.get("x-cache", "").lower()
        blob = _header_blob(server_val, via_val, x_cache)

        # ---- Cloudflare ----------------------------------------------
        # cf-ray is the definitive signal
        if "cf-ray" in headers:
            self._boost(candidates["Cloudflare"], 2, 9)
        if "cloudflare" in server_val:
            self._boost(candidates["Cloudflare"], 2, 9)
        if "cf-cache-status" in headers:
            self._boost(candidates["Cloudflare"], 1, 3)
        if "__cf_bm" in headers.get("set-cookie", "").lower():
            self._boost(candidates["Cloudflare"], 1, 3)

        # ---- AWS CloudFront ------------------------------------------
        # x-amz-cf-id is the definitive signal (header key is lowercased)
        if "x-amz-cf-id" in headers:
            self._boost(candidates["AWS CloudFront"], 2, 9)
        if "cloudfront" in via_val or "cloudfront" in x_cache:
            self._boost(candidates["AWS CloudFront"], 2, 8)
        if "x-amz-cf-pop" in headers:
            self._boost(candidates["AWS CloudFront"], 1, 3)
        # CloudFront sets X-Cache: Hit from cloudfront  or Miss from cloudfront
        if "from cloudfront" in x_cache:
            self._boost(candidates["AWS CloudFront"], 2, 8)

        # ---- Vercel --------------------------------------------------
        if "x-vercel-id" in headers:
            self._boost(candidates["Vercel"], 2, 9)
        if "vercel" in server_val or "vercel" in via_val:
            self._boost(candidates["Vercel"], 1, 5)

        # ---- Fastly --------------------------------------------------
        if "x-served-by" in headers and "cache-" in headers.get("x-served-by", "").lower():
            self._boost(candidates["Fastly"], 1, 4)
        if "fastly" in via_val or "fastly" in x_cache:
            self._boost(candidates["Fastly"], 2, 8)
        if "x-fastly-request-id" in headers:
            self._boost(candidates["Fastly"], 2, 9)
        if "surrogate-control" in headers:     # Fastly-specific header
            self._boost(candidates["Fastly"], 1, 3)

        # ---- Akamai --------------------------------------------------
        if "x-check-cacheable" in headers:
            self._boost(candidates["Akamai"], 1, 5)
        if "akamai" in via_val or "akamaiedge" in via_val:
            self._boost(candidates["Akamai"], 2, 8)
        if "x-akamai-transformed" in headers or "akamai-cache-status" in headers:
            self._boost(candidates["Akamai"], 2, 7)
        if "edgescape" in headers.get("x-akamai-session-info", "").lower():
            self._boost(candidates["Akamai"], 1, 3)

        # ---- Azure CDN / Front Door ----------------------------------
        if "x-azure-ref" in headers:
            self._boost(candidates["Azure CDN"], 2, 9)
        if "x-fd-int-roxy-purgeid" in headers or "x-msedge-ref" in headers:
            self._boost(candidates["Azure CDN"], 2, 8)
        if "azure" in via_val:
            self._boost(candidates["Azure CDN"], 1, 5)

        # ---- Google Cloud CDN / Firebase Hosting ---------------------
        if "x-goog-storage-status" in headers or "x-guploader-uploadid" in headers:
            self._boost(candidates["Google Cloud"], 1, 5)
        if "gcs" in x_cache or "google" in via_val:
            self._boost(candidates["Google Cloud"], 1, 4)
        if "firebase" in server_val:
            self._boost(candidates["Google Cloud"], 2, 7)

        # ---- BunnyCDN ------------------------------------------------
        if "bunnycdn" in headers.get("server", "").lower():
            self._boost(candidates["BunnyCDN"], 2, 9)
        if "cdn-pullzone" in headers or "cdn-uid" in headers:
            self._boost(candidates["BunnyCDN"], 2, 9)
        if "bunny-cache-status" in headers:
            self._boost(candidates["BunnyCDN"], 1, 3)

        # ---- Netlify -------------------------------------------------
        if "x-nf-request-id" in headers:
            self._boost(candidates["Netlify"], 2, 9)
        if "netlify" in server_val:
            self._boost(candidates["Netlify"], 2, 9)
        if "x-netlify-vary" in headers or "x-netlify-cache" in headers:
            self._boost(candidates["Netlify"], 1, 3)

        return self._finalize_all(candidates)

    # ------------------------------------------------------------------
    # Secondary / "other" technologies
    # ------------------------------------------------------------------

    def detect_other(self, headers: dict[str, str], body: str) -> list[str]:
        """Detect secondary tools that don't fit core categories."""
        found: set[str] = set()

        x_powered = headers.get("x-powered-by", "").lower()

        # ---- Meta-frameworks ----------------------------------------
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

        # ---- Analytics & tag management -----------------------------
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

        # ---- Heatmaps / session recording ---------------------------
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

        # ---- Customer support / chat --------------------------------
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

        # ---- Error monitoring / observability -----------------------
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

        # ---- UI libraries -------------------------------------------
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

        # ---- Marketing / CRM ----------------------------------------
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

        # ---- Image / media CDNs -------------------------------------
        if "cloudinary.com" in body:
            found.add("Cloudinary")
        if "imgix.net" in body:
            found.add("Imgix")
        if "imagekit.io" in body:
            found.add("ImageKit")
        if "fastly.picmonkey.com" in body:
            found.add("Fastly Image Optimizer")

        # ---- Payments -----------------------------------------------
        if "stripe.com" in body or "js.stripe.com" in body:
            found.add("Stripe")
        if "paypal.com" in body and "paypalobjects.com" in body:
            found.add("PayPal")
        if "braintree" in body:
            found.add("Braintree")

        # ---- Maps ---------------------------------------------------
        if "maps.googleapis.com" in body:
            found.add("Google Maps")
        if "mapbox.com" in body or "mapboxgl" in body:
            found.add("Mapbox")
        if "leafletjs.com" in body or "leaflet.js" in body:
            found.add("Leaflet")

        # ---- A/B testing / personalisation --------------------------
        if "optimizely" in body:
            found.add("Optimizely")
        if "abtasty" in body:
            found.add("AB Tasty")
        if "vwo.com" in body or "visualwebsiteoptimizer" in body:
            found.add("VWO")

        # ---- Search -------------------------------------------------
        if "algolia" in body:
            found.add("Algolia")
        if "swiftype" in body:
            found.add("Swiftype")

        # ---- Misc HTTP headers --------------------------------------
        if "x-powered-by" in headers:
            powered = headers["x-powered-by"]
            # Surface non-trivial x-powered-by values
            if powered.lower() not in ("", "express", "php", "asp.net"):
                found.add(f"X-Powered-By: {powered}")

        return sorted(found)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_targets(target: str) -> list[str]:
        """Return fetchable URL candidates, preferring HTTPS first."""
        if target.startswith(("http://", "https://")):
            return [target]
        return [f"https://{target}", f"http://{target}"]

    @staticmethod
    def _boost(candidate: dict[str, int], signals: int, score: int) -> None:
        """Accumulate evidence, capping score at 10."""
        candidate["signals"] += signals
        candidate["score"] = min(10, candidate["score"] + score)

    @staticmethod
    def _confidence_label(score: int) -> str:
        if score >= 8:
            return "High"
        if score >= 5:
            return "Medium"
        return "Low"

    @staticmethod
    def _format_detection_names(results: list[dict[str, Any]]) -> str:
        """Return a compact debug representation of detection results."""
        if not results:
            return "none"
        return ", ".join(f"{item['name']}({item['score']})" for item in results)

    def _finalize_all(
        self,
        candidates: dict[str, dict[str, int]],
    ) -> list[dict[str, Any]]:
        """Return all valid detections sorted by score descending."""
        results = []
        for name, data in candidates.items():
            if data["signals"] <= 0 or data["score"] < 3:
                continue
            score = min(10, max(1, data["score"]))
            results.append(
                {
                    "name": name,
                    "score": score,
                    "confidence": self._confidence_label(score),
                    "meter": "█" * score + "░" * (10 - score),
                }
            )
        return sorted(results, key=lambda x: x["score"], reverse=True)
