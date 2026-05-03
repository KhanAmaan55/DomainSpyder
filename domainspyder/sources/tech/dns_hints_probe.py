"""DNS TXT hint detection for technology verification signals."""

from __future__ import annotations

import logging

import dns.resolver

logger = logging.getLogger(__name__)

_VERIFICATION_PATTERNS: list[tuple[str, str]] = [
    ("google-site-verification", "Google Search Console verified"),
    ("facebook-domain-verification", "Facebook domain verified"),
    ("apple-domain-verification", "Apple domain verified"),
    ("ms=", "Microsoft 365 verified"),
    ("atlassian-domain-verification", "Atlassian verified"),
    ("docusign", "DocuSign verified"),
    ("stripe-verification", "Stripe verified"),
    ("hubspot", "HubSpot verified"),
    ("shopify-verification", "Shopify verified"),
    ("blitz=", "Blitz verified"),
    ("_github-pages-challenge", "GitHub Pages verified"),
    ("postman-domain-verification", "Postman verified"),
    ("twilio-domain-verification", "Twilio verified"),
    ("amazonses", "Amazon SES configured"),
    ("v=spf1", "SPF record configured"),
    ("v=dmarc1", "DMARC configured"),
]


def probe_dns_hints(target: str) -> list[str]:
    """Resolve TXT records for domain verification signals."""
    domain = target.split("//")[-1].split("/")[0].split(":")[0]
    logger.debug("DNS hints: resolving TXT for %s", domain)

    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
    except Exception as exc:
        logger.debug("DNS hints: TXT lookup failed: %s", exc)
        return []

    hints: list[str] = []
    for rdata in answers:
        txt = "".join(
            part.decode() if isinstance(part, bytes) else part
            for part in rdata.strings
        )
        txt_lower = txt.lower()
        for pattern, label in _VERIFICATION_PATTERNS:
            if pattern in txt_lower and label not in hints:
                hints.append(label)

    logger.debug("DNS hints: found %d verification hints", len(hints))
    return hints
