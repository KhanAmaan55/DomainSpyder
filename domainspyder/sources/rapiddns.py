"""RapidDNS subdomain scraper source."""

import logging
import re

import requests

from domainspyder.config import HEADERS, REQUEST_TIMEOUT
from domainspyder.sources.base import BaseSource

logger = logging.getLogger(__name__)


class RapidDNSSource(BaseSource):
    """Scrape subdomains from rapiddns.io."""

    @property
    def name(self) -> str:
        return "rapiddns"

    def fetch(self, domain: str) -> list[str]:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        subdomains: set[str] = set()

        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        matches = re.findall(
            rf"([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})", response.text
        )

        for sub in matches:
            subdomains.add(sub)

        return list(subdomains)
