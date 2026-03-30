"""DomainSpyder data-source package."""

from domainspyder.sources.base import BaseSource
from domainspyder.sources.crtsh import CrtShSource
from domainspyder.sources.hackertarget import HackerTargetSource
from domainspyder.sources.otx import OTXSource
from domainspyder.sources.rapiddns import RapidDNSSource
from domainspyder.sources.wayback import WaybackSource
from domainspyder.sources.bruteforce import BruteForceSource

ALL_PASSIVE_SOURCES = [
    CrtShSource,
    OTXSource,
    HackerTargetSource,
    WaybackSource,
    RapidDNSSource,
]

__all__ = [
    "BaseSource",
    "CrtShSource",
    "HackerTargetSource",
    "OTXSource",
    "RapidDNSSource",
    "WaybackSource",
    "BruteForceSource",
    "ALL_PASSIVE_SOURCES",
]
