"""
SSL certificate data source for domain info.

Uses Python's built-in ``ssl`` and ``socket`` modules to
extract certificate details — no new dependencies required.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime
from typing import Any

from domainspyder.config import WHOIS_TIMEOUT

logger = logging.getLogger(__name__)


class SslSource:
    """Extract SSL/TLS certificate information for a domain."""

    @property
    def name(self) -> str:
        return "ssl"

    def fetch(self, domain: str) -> dict[str, Any]:
        logger.debug("SSL: connecting to %s:443", domain)

        cert = self._get_certificate(domain)
        if not cert:
            return {}

        logger.debug(
            "SSL: certificate retrieved, %d fields in raw cert",
            len(cert),
        )

        return self._parse_certificate(cert)

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
    # Certificate retrieval
    # ------------------------------------------------------------------

    def _get_certificate(self, domain: str) -> dict | None:
        """
        Establish a TLS connection and return the peer certificate.

        Tries with verification first, then falls back to
        unverified if the certificate is self-signed or invalid.
        """
        # Attempt 1: verified connection
        cert = self._try_connect(domain, verify=True)
        if cert:
            logger.debug("SSL: verified connection succeeded")
            return cert

        # Attempt 2: unverified (for self-signed certs)
        logger.debug("SSL: verified failed, retrying without verification")
        cert = self._try_connect(domain, verify=False)
        if cert:
            logger.debug("SSL: unverified connection succeeded")
            return cert

        logger.debug("SSL: all connection attempts failed for %s", domain)
        return None

    @staticmethod
    def _try_connect(
        domain: str,
        *,
        verify: bool = True,
    ) -> dict | None:
        """Attempt a single TLS connection and return the cert dict."""
        try:
            if verify:
                context = ssl.create_default_context()
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (domain, 443), timeout=WHOIS_TIMEOUT,
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=domain,
                ) as ssock:
                    return ssock.getpeercert()

        except Exception as exc:
            logger.debug(
                "SSL: connect (verify=%s) failed: %s", verify, exc,
            )
            return None

    # ------------------------------------------------------------------
    # Certificate parsing
    # ------------------------------------------------------------------

    def _parse_certificate(self, cert: dict) -> dict[str, Any]:
        """Extract structured fields from a Python SSL cert dict."""
        result: dict[str, Any] = {}

        # Issuer
        issuer = self._extract_cert_field(cert.get("issuer", ()), "commonName")
        issuer_org = self._extract_cert_field(
            cert.get("issuer", ()), "organizationName",
        )
        if issuer:
            result["ssl_issuer"] = issuer
            logger.debug("SSL: issuer CN = %s", issuer)
        if issuer_org:
            result["ssl_issuer_org"] = issuer_org
            logger.debug("SSL: issuer org = %s", issuer_org)

        # Subject
        subject_cn = self._extract_cert_field(
            cert.get("subject", ()), "commonName",
        )
        if subject_cn:
            result["ssl_subject"] = subject_cn
            logger.debug("SSL: subject = %s", subject_cn)

        # Validity dates
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        if not_before:
            parsed = self._parse_cert_date(not_before)
            if parsed:
                result["ssl_valid_from"] = parsed.strftime("%Y-%m-%d")
                logger.debug("SSL: valid from = %s", result["ssl_valid_from"])

        if not_after:
            parsed = self._parse_cert_date(not_after)
            if parsed:
                result["ssl_valid_until"] = parsed.strftime("%Y-%m-%d")
                days_remaining = (parsed - datetime.utcnow()).days
                result["ssl_days_remaining"] = max(days_remaining, 0)
                logger.debug(
                    "SSL: valid until = %s (%d days remaining)",
                    result["ssl_valid_until"], result["ssl_days_remaining"],
                )

        # Subject Alternative Names (SANs)
        san_entries = cert.get("subjectAltName", ())
        if san_entries:
            san_list = [value for _type, value in san_entries]
            result["ssl_san"] = san_list
            logger.debug("SSL: %d SANs found", len(san_list))

        # Serial number
        serial = cert.get("serialNumber")
        if serial:
            result["ssl_serial"] = serial

        logger.debug(
            "SSL: finished — %d fields extracted", len(result),
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_cert_field(
        cert_tuple: tuple,
        field_name: str,
    ) -> str | None:
        """
        Extract a named field from an SSL cert's issuer/subject tuple.

        The structure is ``((('field', 'value'),), ...)``.
        """
        for entry in cert_tuple:
            for key, value in entry:
                if key == field_name:
                    return str(value)
        return None

    @staticmethod
    def _parse_cert_date(date_str: str) -> datetime | None:
        """Parse the date string from ``getpeercert()``."""
        # Format: 'Jan 15 00:00:00 2024 GMT'
        try:
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            logger.debug("SSL: failed to parse date: %s", date_str)
            return None
