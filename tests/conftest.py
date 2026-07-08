"""Shared pytest fixtures for DomainSpyder tests."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import Mock, patch

import httpx
import pytest
import responses


# ---------------------------------------------------------------------------
# Sample DNS data
# ---------------------------------------------------------------------------

SAMPLE_A_RECORDS = ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
SAMPLE_MX_RECORDS = [
    "aspmx.l.google.com",
    "alt1.aspmx.l.google.com",
]
SAMPLE_NS_RECORDS = ["a.iana-servers.net", "b.iana-servers.net"]
SAMPLE_TXT_RECORDS = [
    "v=spf1 include:_spf.google.com ~all",
    "google-site-verification=xxx",
]
SAMPLE_CNAME_RECORDS = ["www.example.com."]
SAMPLE_DMARC_RECORD = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]

SAMPLE_DNS_RECORDS: dict[str, list[str]] = {
    "A": SAMPLE_A_RECORDS,
    "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
    "MX": SAMPLE_MX_RECORDS,
    "NS": SAMPLE_NS_RECORDS,
    "TXT": SAMPLE_TXT_RECORDS,
    "CNAME": SAMPLE_CNAME_RECORDS,
}


# ---------------------------------------------------------------------------
# Sample WHOIS data
# ---------------------------------------------------------------------------

SAMPLE_WHOIS_DOMAIN = "example.com"
SAMPLE_WHOIS_DATA: dict[str, Any] = {
    "domain_name": "example.com",
    "registrar": "Example Registrar Inc",
    "creation_date": "2000-01-15",
    "expiration_date": "2030-01-15",
    "updated_date": "2024-06-01",
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "status": [
        "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    ],
    "registrant": {"org": "Example Org", "name": "Admin", "country": "US"},
    "dnssec": "unsigned",
}


# ---------------------------------------------------------------------------
# Sample SSL certificate data
# ---------------------------------------------------------------------------

SAMPLE_SSL_CERT: dict[str, Any] = {
    "subject": (
        (("commonName", "*.example.com"),),
        (("organizationName", "Example Inc"),),
    ),
    "issuer": (
        (("countryName", "US"),),
        (("organizationName", "Example CA"),),
        (("commonName", "Example CA R1"),),
    ),
    "notBefore": "Jan 15 00:00:00 2024 GMT",
    "notAfter": "Jan 15 00:00:00 2026 GMT",
    "subjectAltName": (
        ("DNS", "*.example.com"),
        ("DNS", "example.com"),
    ),
    "serialNumber": "1234567890ABCDEF",
}


# ---------------------------------------------------------------------------
# Sample RDAP JSON
# ---------------------------------------------------------------------------

SAMPLE_RDAP_JSON: dict[str, Any] = {
    "ldhName": "EXAMPLE.COM",
    "status": ["client delete prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "2000-01-15T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-01-15T00:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "Example Registrar Inc"]],
            ],
        },
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "Example Org"]],
            ],
        },
    ],
    "nameservers": [
        {"ldhName": "NS1.EXAMPLE.COM"},
        {"ldhName": "NS2.EXAMPLE.COM"},
    ],
    "secureDNS": {"delegationSigned": False},
}


# ---------------------------------------------------------------------------
# Sample SOA DNS response
# ---------------------------------------------------------------------------

SAMPLE_SOA_RDATA = Mock()
SAMPLE_SOA_RDATA.mname = "ns1.example.com."
SAMPLE_SOA_RDATA.rname = "admin.example.com."
SAMPLE_SOA_RDATA.serial = 2024060101
SAMPLE_SOA_RDATA.refresh = 900
SAMPLE_SOA_RDATA.retry = 900
SAMPLE_SOA_RDATA.expire = 1800
SAMPLE_SOA_RDATA.minimum = 60


# ---------------------------------------------------------------------------
# Sample HTTP response for tech detection
# ---------------------------------------------------------------------------

SAMPLE_TECH_HTML = """
<html>
<head>
  <meta name="generator" content="WordPress 6.5.3">
  <script src="/wp-content/themes/theme/js/jquery.min.js"></script>
  <link rel="stylesheet" href="/wp-content/themes/theme/style.css">
</head>
<body>
  <div id="__next">Hello Next.js</div>
  <script>window.jQuery</script>
</body>
</html>
"""


@pytest.fixture
def mock_dns_resolver():
    """Mock dns.resolver.resolve to return controlled responses."""
    with patch("dns.resolver.resolve") as mock:
        yield mock


@pytest.fixture
def mock_requests():
    """Fixture that wraps test functions in responses.RequestsMock context."""
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def mock_httpx_client():
    """Mock httpx.Client for tech scanner and RDAP tests."""
    with patch("httpx.Client") as mock:
        client_instance = Mock()
        mock.return_value.__enter__.return_value = client_instance
        yield client_instance


@pytest.fixture
def mock_socket():
    """Mock socket operations for port scanner tests."""
    with patch("socket.socket") as mock:
        sock_instance = Mock()
        mock.return_value.__enter__.return_value = sock_instance
        yield sock_instance


@pytest.fixture
def mock_whois():
    """Mock python-whois library."""
    with patch("whois.whois") as mock:
        yield mock


@pytest.fixture
def sample_whois_result():
    """Create a mock whois result object."""
    result = Mock()
    result.domain_name = "example.com"
    result.registrar = "Example Registrar Inc"
    result.creation_date = "2000-01-15"
    result.expiration_date = "2030-01-15"
    result.updated_date = "2024-06-01"
    result.name_servers = ["ns1.example.com", "ns2.example.com"]
    result.status = [
        "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    ]
    result.org = "Example Org"
    result.name = "Admin"
    result.country = "US"
    result.state = "California"
    result.dnssec = "unsigned"
    return result


@pytest.fixture
def mock_wordlist(tmp_path):
    """Create a temporary wordlist file."""
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("www\nmail\nadmin\nftp\nblog\napi\ndev\n")
    return str(wordlist)
