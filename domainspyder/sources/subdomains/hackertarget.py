"""HackerTarget host search source."""

import logging

import requests

from domainspyder.config import HEADERS, REQUEST_TIMEOUT
from domainspyder.sources.subdomains.base import BaseSource

logger = logging.getLogger(__name__)


class HackerTargetSource(BaseSource):
    """Fetch subdomains from HackerTarget host search API."""

    @property
    def name(self) -> str:
        return "hackertarget"

    def fetch(self, domain: str) -> list[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        subdomains: set[str] = set()

        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS)

        for line in response.text.splitlines():
            sub = line.split(",")[0]
            if sub.endswith(domain):
                subdomains.add(sub)

        return list(subdomains)
