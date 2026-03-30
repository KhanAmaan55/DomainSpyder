"""crt.sh certificate transparency source."""

import logging

import requests

from domainspyder.config import HEADERS, REQUEST_TIMEOUT
from domainspyder.sources.base import BaseSource

logger = logging.getLogger(__name__)


class CrtShSource(BaseSource):
    """Fetch subdomains from crt.sh certificate transparency logs."""

    @property
    def name(self) -> str:
        return "crt.sh"

    def fetch(self, domain: str) -> list[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        subdomains: set[str] = set()

        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS)

        if response.status_code != 200:
            logger.debug("crt.sh returned status %d", response.status_code)
            return []

        try:
            data = response.json()
        except ValueError:
            logger.debug("crt.sh returned non-JSON response")
            return []

        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip()
                if name and name.endswith(domain) and "*" not in name and "@" not in name:
                    subdomains.add(name)

        return list(subdomains)
