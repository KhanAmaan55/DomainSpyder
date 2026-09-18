"""DomainSpyder data-source package."""

from domainspyder.sources.subdomains.base import BaseSource
from domainspyder.sources.subdomains.bruteforce import BruteForceSource
from domainspyder.sources.subdomains.crtsh import CrtShSource
from domainspyder.sources.subdomains.hackertarget import HackerTargetSource
from domainspyder.sources.subdomains.otx import OTXSource
from domainspyder.sources.subdomains.rapiddns import RapidDNSSource
from domainspyder.sources.subdomains.wayback import WaybackSource

ALL_PASSIVE_SOURCES = [
    CrtShSource,
    OTXSource,
    HackerTargetSource,
    WaybackSource,
    RapidDNSSource,
]

__all__ = [
    "ALL_PASSIVE_SOURCES",
    "BaseSource",
    "BruteForceSource",
    "CrtShSource",
    "HackerTargetSource",
    "OTXSource",
    "RapidDNSSource",
    "WaybackSource",
]
