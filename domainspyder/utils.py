"""
DomainSpyder shared utilities.

Contains helpers used across multiple modules to avoid duplication.
"""

from __future__ import annotations

import ipaddress
import re
import threading
from urllib.parse import urlsplit

import requests

# ---------------------------------------------------------------------------
# Thread-local HTTP session
# ---------------------------------------------------------------------------

_thread_local = threading.local()


def get_session() -> requests.Session:
    """Return a thread-local ``requests.Session`` for connection reuse."""
    if not hasattr(_thread_local, "session"):
        _thread_local.session = requests.Session()
    return _thread_local.session


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------


def is_valid_subdomain(subdomain: str, parent_domain: str) -> bool:
    """
    Check whether *subdomain* is a valid child of *parent_domain*.

    Filters out wildcard entries, entries with ``@``, and subdomains
    that do not belong to the parent domain.
    """
    subdomain = subdomain.lower().strip()
    parent_domain = parent_domain.lower().strip()
    if not subdomain:
        return False
    if subdomain != parent_domain and not subdomain.endswith("." + parent_domain):
        return False
    return not ("*" in subdomain or "@" in subdomain)


# ---------------------------------------------------------------------------
# User input normalisation
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MAX_HOSTNAME_LENGTH = 253


def _extract_host(value: str) -> str:
    """Pull the hostname out of a bare host, ``host:port`` or full URL."""
    raw = value.strip()
    if not raw:
        raise ValueError("target must not be empty")

    # Prefixing "//" makes urlsplit treat a scheme-less value as a netloc.
    parts = urlsplit(raw if "://" in raw else f"//{raw}")
    if parts.scheme and parts.scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme '{parts.scheme}' in '{raw}'")

    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise ValueError(f"could not find a hostname in '{raw}'")
    return host


def _check_hostname(host: str, original: str) -> str:
    """Validate *host* as an LDH hostname, converting IDNs to punycode."""
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError(f"'{original}' is not a valid hostname") from None

    labels = host.split(".")
    if len(host) > _MAX_HOSTNAME_LENGTH or not all(
        _LABEL_RE.match(label) for label in labels
    ):
        raise ValueError(f"'{original}' is not a valid hostname")
    return host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def normalize_domain(value: str) -> str:
    """
    Reduce user input to a bare, lowercase domain name.

    Accepts ``example.com``, ``Example.COM.``, ``example.com:8443`` or
    ``https://example.com/path`` and returns ``example.com``.  Raises
    ``ValueError`` for IP addresses, single-label names and anything
    that is not a valid hostname.
    """
    host = _extract_host(value)
    if _is_ip(host):
        raise ValueError(f"expected a domain name, got IP address '{host}'")

    domain = _check_hostname(host, value.strip())
    if "." not in domain:
        raise ValueError(f"'{value.strip()}' is not a fully qualified domain name")
    return domain


def normalize_host(value: str) -> str:
    """
    Reduce user input to a bare hostname or IPv4 address.

    Like :func:`normalize_domain` but also accepts IPv4 addresses and
    single-label names such as ``localhost``.
    """
    host = _extract_host(value)
    if _is_ip(host):
        if ipaddress.ip_address(host).version == 6:
            raise ValueError("IPv6 targets are not supported yet")
        return host
    return _check_hostname(host, value.strip())


def normalize_url_target(value: str) -> str:
    """
    Validate a host-or-URL target, preserving any scheme and path.

    ``example.com`` becomes the normalised host, while
    ``https://example.com/blog`` is returned as given once its host
    has been validated.
    """
    raw = value.strip()
    host = normalize_host(raw)
    return raw if "://" in raw else host


def parse_ports(spec: str) -> list[int]:
    """
    Parse a comma-separated port list such as ``"80,443,8080"``.

    Raises ``ValueError`` naming the first entry that is not an
    integer in the range 1-65535.
    """
    ports: list[int] = []
    for raw_item in spec.split(","):
        item = raw_item.strip()
        if not item.isdigit() or not 1 <= int(item) <= 65535:
            raise ValueError(
                f"invalid port '{item}' (expected integers 1-65535, comma-separated)"
            )
        ports.append(int(item))
    return ports


# ---------------------------------------------------------------------------
# Provider normalisation
# ---------------------------------------------------------------------------


def normalize_provider(value: str) -> str | None:
    """Map a DNS record value to a canonical provider key."""
    value = value.lower()
    if "google" in value:
        return "google"
    if "zoho" in value:
        return "zoho"
    if "outlook" in value or "protection.outlook.com" in value:
        return "microsoft"
    if "amazonses" in value:
        return "amazon"
    return None


def display_provider(key: str) -> str:
    """Return the human-friendly label for a provider key."""
    from domainspyder.config import PROVIDER_MAP

    return PROVIDER_MAP.get(key, key)
