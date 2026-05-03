"""
DomainSpyder domain-info scanner.

Orchestrates multiple info sources (WHOIS, RDAP, SSL, DNS SOA)
concurrently, merges the results into a unified domain profile,
and generates actionable insights.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from domainspyder.config import (
    DOMAIN_AGE_THRESHOLDS,
    EPP_STATUS_MAP,
    EXPIRY_WARNING_DAYS,
    SSL_EXPIRY_WARNING_DAYS,
    WHOIS_PRIVACY_INDICATORS,
)
from domainspyder.sources.info import (
    ALL_INFO_SOURCES,
    SslSource,
    WhoisSource,
)

logger = logging.getLogger(__name__)


class InfoScanner:
    """
    Multi-source domain intelligence scanner.

    Runs WHOIS, RDAP, SSL, and DNS SOA queries concurrently,
    merges the results, and produces insights.

    Usage::

        scanner = InfoScanner(debug=True)
        data     = scanner.scan("example.com")
        insights = scanner.analyze(data)
    """

    def __init__(self, *, debug: bool = False) -> None:
        self._debug = debug

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        domain: str,
        *,
        skip_ssl: bool = False,
        skip_whois: bool = False,
        brief: bool = False,
    ) -> dict[str, Any]:
        """
        Run multi-source domain info scan and return merged results.

        When *brief* is ``True``, only core registration fields
        are included (SSL and SOA details are omitted from output).
        """
        start_time = time.time()
        logger.debug("InfoScanner: starting scan for %s", domain)

        # Phase 1: Run all sources concurrently
        source_data = self._run_sources(
            domain, skip_ssl=skip_ssl, skip_whois=skip_whois,
        )

        if not source_data:
            logger.error("InfoScanner: all sources failed for %s", domain)
            return {"domain": domain, "error": "All sources failed"}

        logger.debug(
            "InfoScanner: %d sources returned data",
            len(source_data),
        )

        # Phase 2: Merge results from all sources
        merged = self._merge_results(domain, source_data)

        # Phase 3: Compute derived fields
        self._enrich_data(merged)

        # Phase 4: Track metadata
        merged["sources_used"] = sorted(source_data.keys())
        merged["sources_failed"] = sorted(
            set(self._get_source_names(skip_ssl, skip_whois))
            - set(source_data.keys())
        )
        merged["duration"] = round(time.time() - start_time, 3)
        merged["brief"] = brief

        logger.debug(
            "InfoScanner: scan complete in %.3fs — sources: %s, failed: %s",
            merged["duration"],
            merged["sources_used"],
            merged["sources_failed"],
        )

        return merged

    def analyze(self, data: dict) -> list[str]:
        """Generate prioritised insights from merged domain data."""
        insights: list[str] = []

        if data.get("error"):
            return insights

        # ----------------------------------------------------------
        # CRITICAL
        # ----------------------------------------------------------
        expiry = data.get("expiry", {})
        days_left = expiry.get("days_remaining")
        if days_left is not None and days_left <= 30:
            insights.append(
                f"[CRITICAL] Domain expires in {days_left} days",
            )

        ssl_days = data.get("ssl_days_remaining")
        if ssl_days is not None and ssl_days <= 7:
            insights.append(
                f"[CRITICAL] SSL certificate expires in {ssl_days} days",
            )

        # Check for clientHold / serverHold
        for status in data.get("status", []):
            status_lower = status.lower()
            if "hold" in status_lower:
                insights.append(
                    f"[CRITICAL] Domain has hold status: {status}",
                )

        # ----------------------------------------------------------
        # WARNINGS
        # ----------------------------------------------------------
        if days_left is not None and 30 < days_left <= EXPIRY_WARNING_DAYS:
            insights.append(
                f"[WARNING] Domain expires in {days_left} days",
            )

        if ssl_days is not None and 7 < ssl_days <= SSL_EXPIRY_WARNING_DAYS:
            insights.append(
                f"[WARNING] SSL certificate expires in {ssl_days} days",
            )

        registrant = data.get("registrant", {})
        if registrant.get("is_private"):
            insights.append("[INFO] WHOIS privacy protection enabled")

        dnssec = data.get("dnssec", "")
        if dnssec:
            dnssec_lower = dnssec.lower()
            if "unsigned" in dnssec_lower or dnssec_lower == "false":
                insights.append("[WARNING] DNSSEC is not enabled")
            elif "signed" in dnssec_lower or dnssec_lower == "true":
                insights.append("[INFO] DNSSEC is enabled")

        age = data.get("age", {})
        age_label = age.get("label", "")
        age_human = age.get("human", "")
        if age_label in ("Mature", "Veteran"):
            insights.append(
                f"[INFO] Domain is well-established ({age_human})",
            )
        elif age_label == "New":
            insights.append(
                f"[WARNING] Domain is relatively new ({age_human})",
            )

        if ssl_days is not None and ssl_days > SSL_EXPIRY_WARNING_DAYS:
            insights.append("[INFO] SSL certificate is valid")

        # Source health
        used = len(data.get("sources_used", []))
        failed = len(data.get("sources_failed", []))
        total = used + failed
        if failed == 0 and total > 0:
            insights.append(
                f"[INFO] {used}/{total} sources responded successfully",
            )
        elif failed > 0:
            insights.append(
                f"[WARNING] {failed}/{total} sources failed",
            )

        return insights

    # ------------------------------------------------------------------
    # Source execution
    # ------------------------------------------------------------------

    def _run_sources(
        self,
        domain: str,
        *,
        skip_ssl: bool,
        skip_whois: bool,
    ) -> dict[str, dict]:
        """Run all applicable sources concurrently."""
        sources = []
        for cls in ALL_INFO_SOURCES:
            if skip_ssl and cls is SslSource:
                logger.debug("InfoScanner: skipping SSL source")
                continue
            if skip_whois and cls is WhoisSource:
                logger.debug("InfoScanner: skipping WHOIS source")
                continue
            sources.append(cls())

        logger.debug(
            "InfoScanner: running %d sources concurrently",
            len(sources),
        )

        results: dict[str, dict] = {}

        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            futures = {
                executor.submit(src.safe_fetch, domain): src
                for src in sources
            }

            for future in as_completed(futures):
                src = futures[future]
                try:
                    data = future.result()
                    if data:
                        results[src.name] = data
                        logger.debug(
                            "InfoScanner: %s returned %d fields",
                            src.name, len(data),
                        )
                    else:
                        logger.debug(
                            "InfoScanner: %s returned empty", src.name,
                        )
                except Exception as exc:
                    logger.error(
                        "InfoScanner: %s raised: %s", src.name, exc,
                    )

        return results

    # ------------------------------------------------------------------
    # Result merging
    # ------------------------------------------------------------------

    def _merge_results(
        self,
        domain: str,
        source_data: dict[str, dict],
    ) -> dict[str, Any]:
        """
        Merge data from all sources into a single dict.

        Priority order: WHOIS > RDAP > SSL > DNS SOA.
        Later sources fill gaps but do not overwrite.
        """
        merged: dict[str, Any] = {"domain": domain}

        # Priority-ordered source keys
        priority = ["whois", "rdap", "ssl", "dns_soa"]

        # Core fields that can come from WHOIS or RDAP
        core_fields = [
            "domain_name", "registrar", "creation_date",
            "expiration_date", "updated_date", "name_servers",
            "status", "registrant", "dnssec",
        ]

        for source_key in priority:
            data = source_data.get(source_key, {})
            for field in core_fields:
                if field not in merged and field in data:
                    merged[field] = data[field]
                    logger.debug(
                        "Merge: %s ← %s (from %s)",
                        field, data[field], source_key,
                    )

        # SSL-specific fields (always include if available)
        ssl_data = source_data.get("ssl", {})
        for key, value in ssl_data.items():
            if key.startswith("ssl_"):
                merged[key] = value

        # SOA-specific fields (always include if available)
        soa_data = source_data.get("dns_soa", {})
        for key, value in soa_data.items():
            if key.startswith("soa_"):
                merged[key] = value

        logger.debug(
            "Merge: final result has %d fields", len(merged),
        )
        return merged

    # ------------------------------------------------------------------
    # Enrichment (computed fields)
    # ------------------------------------------------------------------

    def _enrich_data(self, data: dict[str, Any]) -> None:
        """Add computed fields: age, expiry, privacy, status explanations."""

        # Domain age
        creation = data.get("creation_date")
        if creation:
            data["age"] = self._compute_age(creation)
            logger.debug("Enrich: age = %s", data["age"])

        # Expiry alert
        expiration = data.get("expiration_date")
        if expiration:
            data["expiry"] = self._check_expiry(expiration)
            logger.debug("Enrich: expiry = %s", data["expiry"])

        # Privacy detection
        registrant = data.get("registrant", {})
        if registrant:
            is_private = self._detect_privacy(registrant)
            registrant["is_private"] = is_private
            data["registrant"] = registrant
            logger.debug("Enrich: is_private = %s", is_private)

        # Deduplicate + explain EPP status codes
        statuses = data.get("status", [])
        if statuses:
            # Deduplicate while preserving order
            seen: set[str] = set()
            unique_statuses: list[str] = []
            for s in statuses:
                code = s.split(" ")[0].strip()
                if code not in seen:
                    seen.add(code)
                    unique_statuses.append(s)
            data["status"] = unique_statuses
            data["status_explained"] = self._explain_status(unique_statuses)

    def _compute_age(self, creation_date: str) -> dict[str, Any]:
        """Calculate domain age from the creation date string."""
        try:
            created = datetime.strptime(creation_date, "%Y-%m-%d")
        except (ValueError, TypeError):
            logger.debug(
                "Enrich: cannot parse creation date: %s", creation_date,
            )
            return {}

        now = datetime.utcnow()
        delta = now - created

        total_months = (now.year - created.year) * 12 + (now.month - created.month)
        years = total_months // 12
        months = total_months % 12

        if months > 0:
            human = f"{years} years, {months} months"
        else:
            human = f"{years} years"

        # Determine category label
        thresholds = DOMAIN_AGE_THRESHOLDS
        if years < thresholds["new"]:
            label = "New"
        elif years < thresholds["established"]:
            label = "Established"
        elif years < thresholds["mature"]:
            label = "Mature"
        else:
            label = "Veteran"

        return {
            "years": years,
            "months": months,
            "label": label,
            "human": human,
            "days": delta.days,
        }

    @staticmethod
    def _check_expiry(expiration_date: str) -> dict[str, Any]:
        """Check how many days until domain expires."""
        try:
            expires = datetime.strptime(expiration_date, "%Y-%m-%d")
        except (ValueError, TypeError):
            return {}

        days_remaining = (expires - datetime.utcnow()).days

        alert = None
        if days_remaining <= 30:
            alert = "CRITICAL"
        elif days_remaining <= EXPIRY_WARNING_DAYS:
            alert = "WARNING"

        return {
            "days_remaining": max(days_remaining, 0),
            "alert": alert,
        }

    @staticmethod
    def _detect_privacy(registrant: dict) -> bool:
        """Check if WHOIS privacy protection is enabled."""
        check_fields = ["org", "name"]
        for field in check_fields:
            value = registrant.get(field, "")
            if not value:
                continue
            value_lower = value.lower()
            for indicator in WHOIS_PRIVACY_INDICATORS:
                if indicator in value_lower:
                    return True
        return False

    @staticmethod
    def _explain_status(statuses: list[str]) -> list[dict[str, str]]:
        """Map EPP status codes to human-readable meanings."""
        explained = []
        for status in statuses:
            # Strip any URL or extra text after the code
            code = status.split(" ")[0].strip()
            meaning = EPP_STATUS_MAP.get(
                code, "Unknown status code",
            )
            explained.append({"code": code, "meaning": meaning})
        return explained

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_source_names(
        skip_ssl: bool,
        skip_whois: bool,
    ) -> list[str]:
        """Return expected source names based on skip flags."""
        names = ["whois", "rdap", "ssl", "dns_soa"]
        if skip_ssl:
            names.remove("ssl")
        if skip_whois:
            names.remove("whois")
        return names
