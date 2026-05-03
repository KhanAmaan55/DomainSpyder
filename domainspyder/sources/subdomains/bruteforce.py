"""DNS brute-force subdomain source."""

from __future__ import annotations


import logging
import random
import time

import dns.resolver

from domainspyder.config import DNS_SERVERS, RESOLVER_POOL_SIZE
from domainspyder.sources.subdomains.base import BaseSource
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class BruteForceSource(BaseSource):
    """
    Brute-force subdomain discovery by resolving words from a wordlist.

    Unlike passive sources, this needs a ``wordlist_path``, ``threads``,
    and ``delay`` to be configured before calling ``fetch``.
    """

    def __init__(
        self,
        wordlist_path: str,
        threads: int = 50,
        delay: float = 0.001,
    ) -> None:
        self._wordlist_path = wordlist_path
        self._threads = threads
        self._delay = delay

    @property
    def name(self) -> str:
        return "bruteforce"

    def fetch(self, domain: str) -> list[str]:
        with open(self._wordlist_path, encoding="utf-8") as fh:
            words = [w.strip() for w in fh if w.strip()]

        logger.debug(
            "Brute-force started: %d words, delay=%.3fs, threads=%d",
            len(words),
            self._delay,
            self._threads,
        )

        targets = [f"{word}.{domain}" for word in words]
        resolvers = self._create_resolver_pool()
        found: list[str] = []

        try:
            with ThreadPoolExecutor(max_workers=self._threads) as executor:
                futures = {
                    executor.submit(
                        self._resolve,
                        sub,
                        random.choice(resolvers),
                    ): sub
                    for sub in targets
                }

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        found.append(result)

        except KeyboardInterrupt:
            logger.warning("Brute-force interrupted by user")
            return found

        return found

    # ----- private helpers -----

    @staticmethod
    def _create_resolver_pool() -> list[dns.resolver.Resolver]:
        """Create a pool of resolvers with randomised nameservers."""
        resolvers: list[dns.resolver.Resolver] = []
        for _ in range(RESOLVER_POOL_SIZE):
            r = dns.resolver.Resolver()
            r.nameservers = [random.choice(DNS_SERVERS)]
            r.timeout = 1
            r.lifetime = 1
            resolvers.append(r)
        return resolvers

    def _resolve(
        self,
        subdomain: str,
        resolver: dns.resolver.Resolver,
    ) -> str | None:
        """Attempt to resolve a single subdomain; return it if successful."""
        try:
            resolver.resolve(subdomain, "A")
            time.sleep(self._delay)
            return subdomain
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
        ):
            return None
        except Exception as exc:
            logger.debug("Unexpected error resolving %s: %s", subdomain, exc)
            return None
