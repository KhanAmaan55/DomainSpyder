"""Wayback Machine CDX source."""

import logging

import requests

from domainspyder.config import HEADERS, REQUEST_TIMEOUT
from domainspyder.sources.subdomains.base import BaseSource

logger = logging.getLogger(__name__)


class WaybackSource(BaseSource):
    """Fetch subdomains from the Wayback Machine CDX API."""

    @property
    def name(self) -> str:
        return "wayback"

    def fetch(self, domain: str) -> list[str]:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json"
        subdomains: set[str] = set()

        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        data = response.json()

        for row in data[1:]:  # skip header row
            host = row[2].split("/")[2]
            if host.endswith(domain):
                subdomains.add(host)

        return list(subdomains)
