"""DNS brute-force subdomain source."""

from __future__ import annotations

import logging
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver

from domainspyder.config import DNS_SERVERS, RESOLVER_POOL_SIZE, WILDCARD_PROBES
from domainspyder.sources.subdomains.base import BaseSource

logger = logging.getLogger(__name__)


class BruteForceSource(BaseSource):
    """
    Brute-force subdomain discovery by resolving words from a wordlist.

    Unlike passive sources, this needs a ``wordlist_path``, ``threads``,
    and ``delay`` to be configured before calling ``fetch``.

    Before brute-forcing, random labels are resolved to detect wildcard
    DNS at each wordlist-derived suffix.  Any candidate whose A records
    all fall inside the wildcard set for its own suffix is discarded, and
    the union of detected addresses is exposed afterwards as
    ``wildcard_ips``.
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
        self.wildcard_ips: set[str] = set()

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

        targets = {f"{word}.{domain}": self._suffix(word) for word in words}
        resolvers = self._create_resolver_pool()
        found: list[str] = []

        try:
            wildcards = self._detect_wildcard(domain, resolvers, words)
            self.wildcard_ips = set().union(*wildcards.values())
            if self.wildcard_ips:
                logger.debug(
                    "Wildcard DNS detected for *.%s -> %s",
                    domain,
                    ", ".join(sorted(self.wildcard_ips)),
                )

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
                    ips = future.result()
                    if not ips:
                        continue
                    sub = futures[future]
                    wildcard_ips = wildcards.get(targets[sub])
                    if wildcard_ips and ips <= wildcard_ips:
                        continue
                    found.append(sub)

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

    @staticmethod
    def _suffix(word: str) -> str:
        """Return the labels after the first one (``"api.dev"`` -> ``"dev"``)."""
        return ".".join(word.split(".")[1:])

    def _detect_wildcard(
        self,
        domain: str,
        resolvers: list[dns.resolver.Resolver],
        words: list[str],
    ) -> dict[str, set[str]]:
        """
        Resolve random labels at wordlist-derived suffixes for wildcard DNS.

        Returns the wildcard addresses keyed by suffix (``""`` is the apex).
        Probes run concurrently so a wordlist with many suffixes does not
        serialise into a long chain of DNS timeouts.
        """
        suffixes = {self._suffix(word) for word in words}
        suffixes.add("")
        wildcards: dict[str, set[str]] = {}

        with ThreadPoolExecutor(max_workers=self._threads) as executor:
            futures = {}
            for suffix in suffixes:
                wildcard_domain = f"{suffix}.{domain}" if suffix else domain
                for _ in range(WILDCARD_PROBES):
                    label = "".join(
                        random.choices(string.ascii_lowercase + string.digits, k=20)
                    )
                    future = executor.submit(
                        self._resolve,
                        f"{label}.{wildcard_domain}",
                        random.choice(resolvers),
                    )
                    futures[future] = suffix

            for future in as_completed(futures):
                ips = future.result()
                if ips:
                    wildcards.setdefault(futures[future], set()).update(ips)

        return wildcards

    def _resolve(
        self,
        subdomain: str,
        resolver: dns.resolver.Resolver,
    ) -> set[str] | None:
        """Resolve a single subdomain; return its A records, or ``None``."""
        try:
            answer = resolver.resolve(subdomain, "A")
            time.sleep(self._delay)
            return {rdata.to_text() for rdata in answer}
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
