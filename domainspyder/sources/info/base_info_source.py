"""
Abstract base class for domain-info data sources.

Every info source must implement ``name`` and ``fetch``.
The ``safe_fetch`` wrapper catches errors so one failing
source never aborts the entire pipeline.
"""

from abc import ABC, abstractmethod
import logging
from typing import Any

logger = logging.getLogger(__name__)


class BaseInfoSource(ABC):
    """
    Interface that every domain-info data source must implement.

    Subclasses should override ``name`` and ``fetch``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable source name (e.g. ``'whois'``)."""
        ...

    @abstractmethod
    def fetch(self, domain: str) -> dict[str, Any]:
        """
        Query the source and return a dict of domain info fields.

        Returns an empty dict on failure.  The scanner is
        responsible for merging data from all sources.
        """
        ...

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
