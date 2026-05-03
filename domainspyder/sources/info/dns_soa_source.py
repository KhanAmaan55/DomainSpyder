"""
DNS SOA data source for domain info.

Uses ``dnspython`` (already a project dependency) to query
the SOA record and extract zone authority information.
"""

from __future__ import annotations

import logging
from typing import Any

import dns.resolver

logger = logging.getLogger(__name__)


class DnsSoaSource:
    """Fetch DNS SOA (Start of Authority) record for a domain."""

    @property
    def name(self) -> str:
        return "dns_soa"

    def fetch(self, domain: str) -> dict[str, Any]:
        logger.debug("DNS SOA: querying SOA for %s", domain)

        try:
            answers = dns.resolver.resolve(domain, "SOA", lifetime=5)
        except dns.resolver.NXDOMAIN:
            logger.debug("DNS SOA: domain %s does not exist", domain)
            return {}
        except dns.resolver.NoAnswer:
            logger.debug("DNS SOA: no SOA record for %s", domain)
            return {}
        except dns.resolver.NoNameservers:
            logger.debug("DNS SOA: no nameservers for %s", domain)
            return {}
        except Exception as exc:
            logger.debug("DNS SOA: query failed for %s: %s", domain, exc)
            return {}

        result: dict[str, Any] = {}

        for rdata in answers:
            # Primary name server
            mname = str(rdata.mname).rstrip(".")
            result["soa_primary_ns"] = mname
            logger.debug("DNS SOA: primary NS = %s", mname)

            # Admin contact (RNAME format: admin.example.com → admin@example.com)
            rname = str(rdata.rname).rstrip(".")
            result["soa_admin"] = self._rname_to_email(rname)
            logger.debug("DNS SOA: admin = %s", result["soa_admin"])

            # Zone parameters
            result["soa_serial"] = rdata.serial
            result["soa_refresh"] = rdata.refresh
            result["soa_retry"] = rdata.retry
            result["soa_expire"] = rdata.expire
            result["soa_min_ttl"] = rdata.minimum

            logger.debug(
                "DNS SOA: serial=%d, refresh=%d, retry=%d, expire=%d, min_ttl=%d",
                rdata.serial, rdata.refresh, rdata.retry,
                rdata.expire, rdata.minimum,
            )

            # Only process the first SOA record (there should only be one)
            break

        logger.debug(
            "DNS SOA: finished — %d fields extracted", len(result),
        )
        return result

    def safe_fetch(self, domain: str) -> dict[str, Any]:
        """
        Wrapper around ``fetch`` that catches and logs exceptions
        so one failing source does not abort the entire scan.
        """
        try:
            results = self.fetch(domain)
            logger.debug(
                "%s: returned %d fields", self.name, len(results),
            )
            return results
        except Exception as exc:
            logger.error("%s failed: %s", self.name, exc)
            return {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rname_to_email(rname: str) -> str:
        """
        Convert SOA RNAME to a human-readable email address.

        The SOA RNAME field uses ``.`` as the separator for the
        local part and domain, so ``admin.example.com`` becomes
        ``admin@example.com``.
        """
        parts = rname.split(".", 1)
        if len(parts) == 2:
            return f"{parts[0]}@{parts[1]}"
        return rname
