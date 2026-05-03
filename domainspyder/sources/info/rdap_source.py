"""
RDAP data source for domain info.

Queries the RDAP bootstrap aggregator (``rdap.org``) for
structured registration data in RFC 9083 JSON format.
Uses ``httpx`` (already a project dependency) — no new
libraries required.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from domainspyder.config import HEADERS, REQUEST_TIMEOUT, RDAP_BASE_URL

logger = logging.getLogger(__name__)


class RdapSource:
    """Fetch domain registration data via RDAP protocol."""

    @property
    def name(self) -> str:
        return "rdap"

    def fetch(self, domain: str) -> dict[str, Any]:
        url = f"{RDAP_BASE_URL}{domain}"
        logger.debug("RDAP: querying %s", url)

        try:
            with httpx.Client(
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=True,
            ) as client:
                response = client.get(url)
        except Exception as exc:
            logger.debug("RDAP: request failed for %s: %s", domain, exc)
            return {}

        if response.status_code == 404:
            logger.debug("RDAP: domain not found (404) for %s", domain)
            return {}

        if response.status_code == 429:
            logger.debug("RDAP: rate limited (429) for %s", domain)
            return {}

        if response.status_code != 200:
            logger.debug(
                "RDAP: unexpected status %d for %s",
                response.status_code, domain,
            )
            return {}

        try:
            data = response.json()
        except Exception as exc:
            logger.debug("RDAP: failed to parse JSON: %s", exc)
            return {}

        logger.debug("RDAP: received JSON with %d keys", len(data))
        return self._parse_rdap(data)

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
    # RDAP JSON parsing (RFC 9083)
    # ------------------------------------------------------------------

    def _parse_rdap(self, data: dict) -> dict[str, Any]:
        """Extract structured fields from RDAP JSON response."""
        result: dict[str, Any] = {}

        # Domain name
        if data.get("ldhName"):
            result["domain_name"] = data["ldhName"].lower()
            logger.debug("RDAP: domain = %s", result["domain_name"])

        # Status codes
        if data.get("status"):
            result["status"] = data["status"]
            logger.debug(
                "RDAP: %d status codes", len(result["status"]),
            )

        # Events → dates
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date_str = event.get("eventDate", "")
            if not date_str:
                continue

            # Truncate to date only (RDAP returns full ISO timestamps)
            date_only = date_str[:10]

            if action == "registration":
                result["creation_date"] = date_only
                logger.debug("RDAP: creation_date = %s", date_only)
            elif action == "expiration":
                result["expiration_date"] = date_only
                logger.debug("RDAP: expiration_date = %s", date_only)
            elif action == "last changed":
                result["updated_date"] = date_only
                logger.debug("RDAP: updated_date = %s", date_only)

        # Entities → registrar + registrant
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])

            if "registrar" in roles:
                vcard = self._extract_vcard_fn(entity)
                if vcard:
                    result["registrar"] = vcard
                    logger.debug("RDAP: registrar = %s", vcard)

            if "registrant" in roles:
                registrant: dict[str, Any] = {}
                vcard = self._extract_vcard_fn(entity)
                if vcard:
                    registrant["org"] = vcard

                if registrant:
                    result["registrant"] = registrant
                    logger.debug(
                        "RDAP: registrant = %s", registrant,
                    )

        # Name servers
        nameservers = data.get("nameservers", [])
        if nameservers:
            ns_list = []
            for ns in nameservers:
                name = ns.get("ldhName", "")
                if name:
                    ns_list.append(name.lower().rstrip("."))
            if ns_list:
                result["name_servers"] = sorted(set(ns_list))
                logger.debug(
                    "RDAP: %d name servers", len(result["name_servers"]),
                )

        # DNSSEC
        dnssec_data = data.get("secureDNS", {})
        if dnssec_data:
            is_signed = dnssec_data.get("delegationSigned", False)
            result["dnssec"] = "signedDelegation" if is_signed else "unsigned"
            logger.debug("RDAP: dnssec = %s", result["dnssec"])

        logger.debug(
            "RDAP: finished — %d fields extracted", len(result),
        )
        return result

    @staticmethod
    def _extract_vcard_fn(entity: dict) -> str | None:
        """
        Extract the ``fn`` (formatted name) from a jCard vcard
        array embedded in an RDAP entity.
        """
        vcard_array = entity.get("vcardArray", [])
        if len(vcard_array) < 2:
            return None

        for field in vcard_array[1]:
            if isinstance(field, list) and len(field) >= 4:
                if field[0] == "fn":
                    return str(field[3]).strip()

        return None
