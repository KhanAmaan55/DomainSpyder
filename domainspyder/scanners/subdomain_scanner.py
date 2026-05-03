"""
DomainSpyder subdomain scanner.

Orchestrates passive sources and brute-force discovery,
deduplicates results, and optionally checks which subdomains
are alive.
"""

from __future__ import annotations

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from domainspyder.config import (
    ALIVE_DELAY,
    ALIVE_TIMEOUT,
    BRUTE_CONFIG,
    DEFAULT_BRUTE_MODE,
    DEFAULT_THREADS,
)
from domainspyder.sources.subdomains import ALL_PASSIVE_SOURCES
from domainspyder.sources.subdomains.bruteforce import BruteForceSource
from domainspyder.utils import get_session, is_valid_subdomain

logger = logging.getLogger(__name__)


class SubdomainScanner:
    """
    Discover subdomains via passive sources, brute-force, or both.

    Usage::

        scanner = SubdomainScanner(debug=True)
        results = scanner.scan(
            "example.com",
            wordlist="wordlists/default.txt",
            alive=True,
        )
    """

    def __init__(self, *, debug: bool = False) -> None:
        self._debug = debug

    def scan(
        self,
        domain: str,
        wordlist: str,
        threads: int = DEFAULT_THREADS,
        *,
        alive: bool = False,
        brutemode: str = DEFAULT_BRUTE_MODE,
        brute_only: bool = False,
    ) -> list[Any]:
        """
        Run subdomain enumeration and return results.

        Returns a ``list[str]`` of subdomains, or—when *alive* is
        ``True``—a ``list[dict]`` with keys ``subdomain``, ``status``,
        ``server``, and ``title``.
        """
        if brute_only:
            brute_subs = self._run_bruteforce(
                domain, wordlist, threads, brutemode,
            )
            passive_subs: list[str] = []
        else:
            brute_subs, passive_subs = self._run_combined(
                domain, wordlist, threads,
            )

        logger.debug("Passive total: %d", len(passive_subs))
        logger.debug("Brute-force total: %d", len(brute_subs))

        # Deduplicate + validate
        all_subs = passive_subs + brute_subs
        unique: set[str] = set()
        for sub in all_subs:
            if is_valid_subdomain(sub, domain):
                unique.add(sub.lower().strip())

        logger.debug("Final unique: %d", len(unique))

        if alive:
            return self._check_alive(unique, threads)

        return sorted(unique)

    def _run_bruteforce(
        self,
        domain: str,
        wordlist: str,
        threads: int,
        brutemode: str,
    ) -> list[str]:
        """Run brute-force only, respecting the chosen mode profile."""
        config = BRUTE_CONFIG.get(brutemode, BRUTE_CONFIG[DEFAULT_BRUTE_MODE])
        delay = config["delay"]
        if threads == DEFAULT_THREADS:
            threads = config["threads"]

        logger.debug(
            "Brute-only: mode=%s, delay=%.3f, threads=%d",
            brutemode, delay, threads,
        )

        source = BruteForceSource(
            wordlist_path=wordlist,
            threads=threads,
            delay=delay,
        )
        return source.safe_fetch(domain)

    def _run_combined(
        self,
        domain: str,
        wordlist: str,
        threads: int,
    ) -> tuple[list[str], list[str]]:
        """Run passive sources + brute-force concurrently."""
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_passive = executor.submit(
                self._fetch_passive_sources, domain,
            )
            future_brute = executor.submit(
                BruteForceSource(
                    wordlist_path=wordlist,
                    threads=threads,
                    delay=0.001,
                ).safe_fetch,
                domain,
            )
            passive = future_passive.result()
            brute = future_brute.result()

        return brute, passive

    @staticmethod
    def _fetch_passive_sources(domain: str) -> list[str]:
        """Query all passive sources concurrently."""
        subs: list[str] = []

        sources = [cls() for cls in ALL_PASSIVE_SOURCES]

        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            futures = {
                executor.submit(src.safe_fetch, domain): src
                for src in sources
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    subs.extend(result)

        return subs

    def _check_alive(
        self,
        subdomains: set[str],
        threads: int,
    ) -> list[dict]:
        """Probe each subdomain over HTTP(S) and return alive ones."""
        alive_results: list[dict] = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._probe, sub): sub
                for sub in subdomains
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_results.append(result)

        logger.debug("Alive count: %d", len(alive_results))
        return alive_results

    def _probe(self, subdomain: str) -> dict | None:
        """Try HTTP then HTTPS; return info dict or ``None``."""
        session = get_session()
        headers = {"User-Agent": "DomainSpyder"}

        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                time.sleep(ALIVE_DELAY)
                resp = session.get(
                    url,
                    timeout=ALIVE_TIMEOUT,
                    allow_redirects=True,
                    headers=headers,
                )

                match = re.search(
                    r"<title>(.*?)</title>", resp.text, re.IGNORECASE,
                )
                title = match.group(1).strip() if match else "-"

                return {
                    "subdomain": subdomain,
                    "status": resp.status_code,
                    "server": resp.headers.get("Server", "-"),
                    "title": title[:50],
                }

            except Exception as exc:
                logger.debug("%s failed: %s", subdomain, exc)
                continue

        return None
