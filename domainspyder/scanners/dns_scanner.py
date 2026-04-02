"""
DomainSpyder DNS scanner.

Handles DNS record resolution, analysis, and security scoring
for a target domain.
"""

from __future__ import annotations

import logging
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import dns.resolver
from domainspyder.config import DNS_SERVERS, RECORD_TYPES
from domainspyder.utils import normalize_provider, display_provider

logger = logging.getLogger(__name__)


class DNSScanner:
    """
    Resolve, analyse, and score a domain's DNS configuration.

    Usage::

        scanner = DNSScanner(debug=True)
        records  = scanner.scan("example.com")
        insights = scanner.analyze(records, "example.com")
        security = scanner.calculate_security(records, "example.com")
    """

    def __init__(self, *, debug: bool = False, timeout=3.0, lifetime=5.0) -> None:
        self._debug = debug
        self._dmarc_cache: dict[str, tuple[list[str], bool]] = {}
        self._timeout = timeout
        self._lifetime = lifetime
        self._cache_lock = Lock()



    def scan(self, domain: str) -> dict[str, list[str]]:
        """Resolve all configured record types for *domain* (parallel)."""
        output: dict[str, list[str]] = {}

        def resolve(record_type):
            logger.debug("Resolving %s records for %s", record_type, domain)
            result = self._resolve_record(domain, record_type)
            return record_type, result

        with ThreadPoolExecutor() as executor:
            results = executor.map(resolve, RECORD_TYPES)

        for record_type, result in results:
            if result:
                output[record_type] = result

        return output

    def preprocess(self, records: dict[str, list[str]]) -> dict:
        """Precompute shared data to avoid duplication."""
        txt_records = records.get("TXT", [])
        mx_records = records.get("MX", [])

        spf_records = []
        spf_providers = set()
        mx_providers = set()

        for txt in txt_records:
            txt_lower = txt.lower()
            if "v=spf1" in txt_lower:
                spf_records.append(txt)

            prov = normalize_provider(txt)
            if prov:
                spf_providers.add(prov)

        for mx in mx_records:
            prov = normalize_provider(mx)
            if prov:
                mx_providers.add(prov)

        return {
            "txt": txt_records,
            "mx": mx_records,
            "spf_records": spf_records,
            "mx_providers": mx_providers,
            "spf_providers": spf_providers,
        }

    def analyze(
        self,
        records: dict[str, list[str]],
        domain: str,
        data: Optional[dict] = None,
    ) -> list[str]:
        logger.debug("Starting DNS analysis for %s", domain)
        insights: set[str] = set()

        if data is None:
            data = self.preprocess(records)

        ns_records = records.get("NS", [])
        mx_records = data["mx"]
        txt_records = data["txt"]
        spf_records = data["spf_records"]
        mx_providers = data["mx_providers"]
        spf_providers = data["spf_providers"]

        _ns_providers = {
            "wixdns.net": "Hosting/DNS Provider: Wix",
            "cloudflare.com": "DNS/CDN Provider: Cloudflare",
            "domaincontrol.com": "DNS Provider: GoDaddy",
            "awsdns": "DNS Provider: AWS Route53",
            "azure-dns": "DNS Provider: Azure DNS",
            "google": "DNS Provider: Google Cloud DNS",
        }

        for ns in ns_records:
            ns_lower = ns.lower()
            for key, label in _ns_providers.items():
                if key in ns_lower:
                    insights.add(label)

        if any("smtp.google.com" in mx for mx in mx_records):
            insights.add("[INFO] MX may be simplified due to DNS resolver behaviour")

        if mx_providers or spf_providers:
            mx_label = ", ".join(display_provider(p) for p in mx_providers) or "Unknown"
            spf_label = ", ".join(display_provider(p) for p in spf_providers) or "Unknown"

            insights.add(f"Email Setup: MX={mx_label} | SPF={spf_label}")

            if mx_providers != spf_providers:
                insights.add("[WARNING] Possible email misconfiguration (MX != SPF providers)")

        if not spf_records:
            insights.add("SPF: Not configured")
        else:
            for spf in spf_records:
                spf_lower = spf.lower()
                if "-all" in spf_lower:
                    insights.add("SPF: Strict (-all) - strong protection")
                elif "~all" in spf_lower:
                    insights.add("SPF: Soft fail (~all) - weaker protection")
                elif "+all" in spf_lower:
                    insights.add("[WARNING] SPF: Permissive (+all) - insecure")

        dmarc_records, success = self.get_dmarc_cached(domain)

        if not success:
            insights.add("[WARNING] DMARC: Unable to verify")
        elif not dmarc_records:
            insights.add("[WARNING] DMARC: Not configured")
        else:
            for dmarc in dmarc_records:
                dmarc_lower = dmarc.lower()
                if "p=reject" in dmarc_lower:
                    insights.add("DMARC: Strict (reject)")
                elif "p=quarantine" in dmarc_lower:
                    insights.add("DMARC: Moderate (quarantine)")
                elif "p=none" in dmarc_lower:
                    insights.add("[WARNING] DMARC: Monitoring only (none)")

        return sorted(insights)

    def calculate_security(
        self,
        records: dict[str, list[str]],
        domain: str,
        data: Optional[dict] = None,
    ) -> dict:
        score = 10
        issues: list[str] = []
        good: list[str] = []

        if data is None:
            data = self.preprocess(records)

        txt_records = data["txt"]
        mx_records = data["mx"]
        spf_records = data["spf_records"]
        mx_prov = data["mx_providers"]
        spf_prov = data["spf_providers"]

        # --- SPF -------------------------------------------------------
        if not spf_records:
            score -= 2
            issues.append("SPF not configured")
        else:
            good.append("SPF record present")

            if len(spf_records) > 1:
                score -= 2
                issues.append("Multiple SPF records detected")

            for spf in spf_records:
                spf_lower = spf.lower()
                if "+all" in spf_lower:
                    score -= 4
                    issues.append("SPF is permissive (+all)")
                elif "~all" in spf_lower:
                    score -= 1
                    issues.append("SPF is soft fail (~all)")
                elif "-all" in spf_lower:
                    good.append("SPF is strict (-all)")

        dmarc_records, success = self.get_dmarc_cached(domain)

        if not success:
            score -= 1
            issues.append("DMARC lookup failed")
        elif not dmarc_records:
            score -= 2
            issues.append("DMARC not configured")
        else:
            for dmarc in dmarc_records:
                dmarc_lower = dmarc.lower()
                if "p=none" in dmarc_lower:
                    score -= 1
                    issues.append("DMARC policy is none")
                elif "p=quarantine" in dmarc_lower:
                    good.append("DMARC quarantine enabled")
                elif "p=reject" in dmarc_lower:
                    good.append("DMARC strict (reject)")

        if mx_prov and spf_prov and mx_prov != spf_prov:
            score -= 1
            issues.append("Email provider mismatch (MX != SPF)")

        score = max(score, 0)

        if score >= 8:
            risk = "Low Risk"
        elif score >= 5:
            risk = "Moderate Risk"
        else:
            risk = "High Risk"

        return {
            "score": score,
            "risk": risk,
            "issues": issues,
            "good": good,
        }


    def get_dmarc_cached(self, domain: str) -> tuple[list[str], bool]:
        with self._cache_lock:
            if domain not in self._dmarc_cache:
                self._dmarc_cache[domain] = self._get_dmarc_record(domain)
            return self._dmarc_cache[domain]


    def _resolve_record(
        self,
        domain: str,
        record_type: str,
    ) -> list[str]:
        """Resolve a single DNS record type, trying multiple nameservers."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = self._timeout
        resolver.lifetime = self._lifetime
        nameserver_groups = [[ns] for ns in DNS_SERVERS[:3]]

        answers = None

        for ns in nameserver_groups:
            try:
                resolver.nameservers = ns
                answers = resolver.resolve(domain, record_type)
                break
            except Exception:
                continue

        if not answers:
            logger.debug("%s: no valid response for %s", record_type, domain)
            return []

        results: list = []

        try:
            for rdata in answers:
                if record_type == "MX":
                    exchange = str(rdata.exchange).rstrip(".")
                    results.append((rdata.preference, exchange))
                elif record_type == "TXT":
                    results.append(
                        "".join(part.decode() for part in rdata.strings)
                    )
                else:
                    results.append(str(rdata).rstrip("."))
        except Exception as exc:
            logger.debug("%s resolution error: %s", record_type, exc)
            return []

        if record_type == "MX":
            results.sort(key=lambda x: x[0])
            results = [r[1] for r in results]

        logger.debug("%s -> %s", record_type, results)
        return results

    def _get_dmarc_record(
        self,
        domain: str,
    ) -> tuple[list[str], bool]:
        """Query ``_dmarc.<domain>`` and return ``(records, success)``."""
        logger.debug("Querying _dmarc.%s", domain)
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            records = [
                "".join(part.decode() for part in r.strings) for r in answers
            ]
            logger.debug("DMARC found: %s", records)
            return records, True
        except Exception:
            logger.debug("DMARC not found or query failed")
            return [], False
