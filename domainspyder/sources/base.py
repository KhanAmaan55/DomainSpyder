"""
Abstract base class for subdomain data sources.
"""

from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class BaseSource(ABC):
    """
    Interface that every subdomain data source must implement.

    Subclasses should override ``name`` and ``fetch``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable source name (e.g. ``'crt.sh'``)."""
        ...

    @abstractmethod
    def fetch(self, domain: str) -> list[str]:
        """
        Query the source and return a list of discovered subdomains.

        The caller is responsible for deduplication and validation.
        """
        ...

    def safe_fetch(self, domain: str) -> list[str]:
        """
        Wrapper around ``fetch`` that catches and logs exceptions
        so one failing source does not abort the entire scan.
        """
        try:
            results = self.fetch(domain)
            logger.debug("%s: found %d subdomains", self.name, len(results))
            return results
        except Exception as exc:
            logger.error("%s failed: %s", self.name, exc)
            return []
