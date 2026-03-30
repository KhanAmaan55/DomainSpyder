import requests
import dns.resolver
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import random
import time

DNS_SERVERS = [
    "8.8.8.8",  
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9"
]

BRUTE_MODES = {
    "fast": 0.001,
    "balanced": 0.005,
    "stealth": 0.01
}

def create_resolver_pool(size=10):
    resolvers = []

    for _ in range(size):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [random.choice(DNS_SERVERS)]
        resolver.timeout = 1
        resolver.lifetime = 1
        resolvers.append(resolver)

    return resolvers

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    headers = {"User-Agent": "DomainSpyder"}

    try:
        response = requests.get(
            url,
            timeout=10,
            headers=headers
        )

        # DEBUG
        if response.status_code != 200:
            logging.debug(f"crt.sh status: {response.status_code}")
            return []

        try:
            data = response.json()
        except Exception:
            # DEBUG
            logging.debug("[DEBUG] crt.sh returned non-JSON response")
            return []

        for entry in data:
            names = entry.get("name_value", "")
            for sub in names.split("\n"):
                sub = sub.strip()

                if not sub.endswith(domain):
                    continue
                if "*" in sub or "@" in sub:
                    continue

                subdomains.add(sub)

    # DEBUG
    except Exception as e:
        logging.error(f"crt.sh error: {e}")
    
    return list(subdomains)


def resolve_subdomain(subdomain, resolver, delay):
    try:
        resolver.resolve(subdomain, "A")
        time.sleep(delay)
        return subdomain
    except:
        return None

def brute_force_dns(domain, wordlist_path, threads=30, delay=0.001, debug=False):
    found = []
    with open(wordlist_path) as f:
        words = [w.strip() for w in f if w.strip()]

    if debug:
        logging.debug(f"brute force started with {len(words)} words (delay={delay})")

    subdomains = [f"{word}.{domain}" for word in words]

    try:
        resolvers = create_resolver_pool(size=10)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(
                    resolve_subdomain,
                    sub,
                    random.choice(resolvers),
                    delay
                ): sub
                for sub in subdomains
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        executor.shutdown(wait=False)
        return found

    return found

def get_subdomains_otx(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subs = set()
    headers = {"User-Agent": "DomainSpyder"}

    try:
        response = requests.get(
            url,
            timeout=10,
            headers=headers
        )
        data = response.json()

        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")
            if hostname and hostname.endswith(domain):
                subs.add(hostname)

    # DEBUG
    except Exception as e:
        logging.error(f"otx error: {e}")

    return list(subs)

def get_subdomains_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subs = set()
    headers = {"User-Agent": "DomainSpyder"}

    try:
        response = requests.get(
            url,
            timeout=10,
            headers=headers
        )
        lines = response.text.splitlines()

        for line in lines:
            sub = line.split(",")[0]
            if sub.endswith(domain):
                subs.add(sub)

    # DEBUG
    except Exception as e:
        logging.error(f"hackertarget error: {e}")

    return list(subs)

def get_subdomains_wayback(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json"
    subs = set()
    headers = {"User-Agent": "DomainSpyder"}

    try:
        response = requests.get(
            url,
            timeout=10,
            headers=headers
        )
        data = response.json()

        for row in data[1:]:
            url = row[2]
            host = url.split("/")[2]
            if host.endswith(domain):
                subs.add(host)

    # DEBUG
    except Exception as e:
        logging.error(f"wayback error: {e}")

    return list(subs)

import re

def get_subdomains_rapiddns(domain):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subs = set()
    headers = {"User-Agent": "DomainSpyder"}

    try:
        response = requests.get(
            url,
            timeout=10,
            headers=headers
        )
        matches = re.findall(rf"([a-zA-Z0-9_\-\.]+\.{domain})", response.text)

        for sub in matches:
            subs.add(sub)

    # DEBUG
    except Exception as e:
        logging.error(f"rapiddns error: {e}")

    return list(subs)