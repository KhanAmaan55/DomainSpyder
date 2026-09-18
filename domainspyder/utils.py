"""
DomainSpyder shared utilities.

Contains helpers used across multiple modules to avoid duplication.
"""

from __future__ import annotations

import threading

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
