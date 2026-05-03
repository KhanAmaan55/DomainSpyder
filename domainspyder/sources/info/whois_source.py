"""
WHOIS data source for domain info.

Uses the ``python-whois`` library to query WHOIS servers
and extract registration data including registrar, dates,
name servers, status codes, and registrant information.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import whois

from domainspyder.sources.info.base_info_source import BaseInfoSource

logger = logging.getLogger(__name__)


class WhoisSource(BaseInfoSource):
    """Fetch domain registration data via WHOIS protocol."""

    @property
    def name(self) -> str:
        return "whois"

    def fetch(self, domain: str) -> dict[str, Any]:
        logger.debug("WHOIS: querying %s", domain)

        w = whois.whois(domain)

        if not w or not w.domain_name:
            logger.debug("WHOIS: no data returned for %s", domain)
            return {}

        logger.debug("WHOIS: raw response received for %s", domain)

        result: dict[str, Any] = {}

        # Domain name (may be a list for some TLDs)
        result["domain_name"] = self._normalize_str(w.domain_name)

        # Registrar
        if w.registrar:
            result["registrar"] = str(w.registrar).strip()
            logger.debug("WHOIS: registrar = %s", result["registrar"])

        # Dates
        result["creation_date"] = self._normalize_date(w.creation_date)
        result["expiration_date"] = self._normalize_date(w.expiration_date)
        result["updated_date"] = self._normalize_date(w.updated_date)

        logger.debug(
            "WHOIS: created=%s, expires=%s, updated=%s",
            result.get("creation_date"),
            result.get("expiration_date"),
            result.get("updated_date"),
        )

        # Name servers
        if w.name_servers:
            ns_list = w.name_servers
            if isinstance(ns_list, str):
                ns_list = [ns_list]
            result["name_servers"] = sorted(
                {ns.lower().rstrip(".") for ns in ns_list},
            )
            logger.debug(
                "WHOIS: %d name servers found", len(result["name_servers"]),
            )

        # Status codes
        if w.status:
            statuses = w.status
            if isinstance(statuses, str):
                statuses = [statuses]
            # Strip URL suffix from EPP status codes
            result["status"] = [
                s.split(" ")[0].strip() for s in statuses
            ]
            logger.debug(
                "WHOIS: %d status codes found", len(result["status"]),
            )

        # Registrant info
        registrant: dict[str, Any] = {}
        if getattr(w, "org", None):
            registrant["org"] = str(w.org).strip()
        if getattr(w, "name", None) and w.name != w.org:
            registrant["name"] = str(w.name).strip()
        if getattr(w, "country", None):
            registrant["country"] = str(w.country).strip()
        if getattr(w, "state", None):
            registrant["state"] = str(w.state).strip()

        if registrant:
            result["registrant"] = registrant
            logger.debug("WHOIS: registrant data = %s", registrant)

        # DNSSEC
        if getattr(w, "dnssec", None):
            result["dnssec"] = str(w.dnssec).strip()
            logger.debug("WHOIS: dnssec = %s", result["dnssec"])

        logger.debug(
            "WHOIS: finished — %d fields extracted", len(result),
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_date(value: Any) -> str | None:
        """
        Convert a WHOIS date field to an ISO-format string.

        The ``python-whois`` library may return a single datetime,
        a list of datetimes, or ``None``.
        """
        if value is None:
            return None

        if isinstance(value, list):
            value = value[0]

        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d")

        return str(value).strip() or None

    @staticmethod
    def _normalize_str(value: Any) -> str:
        """Extract a single string from a possibly-list value."""
        if isinstance(value, list):
            return str(value[0]).lower().strip()
        return str(value).lower().strip()
