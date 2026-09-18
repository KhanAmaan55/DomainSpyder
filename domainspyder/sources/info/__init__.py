"""DomainSpyder domain-info source package."""

from domainspyder.sources.info.base_info_source import BaseInfoSource
from domainspyder.sources.info.dns_soa_source import DnsSoaSource
from domainspyder.sources.info.rdap_source import RdapSource
from domainspyder.sources.info.ssl_source import SslSource
from domainspyder.sources.info.whois_source import WhoisSource

ALL_INFO_SOURCES = [
    WhoisSource,
    RdapSource,
    SslSource,
    DnsSoaSource,
]

__all__ = [
    "ALL_INFO_SOURCES",
    "BaseInfoSource",
    "DnsSoaSource",
    "RdapSource",
    "SslSource",
    "WhoisSource",
]
