"""AlienVault OTX passive DNS source."""

import logging

import requests

from domainspyder.config import HEADERS, REQUEST_TIMEOUT
from domainspyder.sources.subdomains.base import BaseSource

logger = logging.getLogger(__name__)


class OTXSource(BaseSource):
    """Fetch subdomains from AlienVault OTX passive DNS."""

    @property
    def name(self) -> str:
        return "otx"

    def fetch(self, domain: str) -> list[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        subdomains: set[str] = set()

        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        data = response.json()

        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")
            if hostname and hostname.endswith(domain):
                subdomains.add(hostname)

        return list(subdomains)
