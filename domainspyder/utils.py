import requests
import dns.resolver
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    try:
        response = requests.get(url, timeout=10)
        data = response.json()

        for entry in data:
            names = entry.get("name_value", "")
            for sub in names.split("\n"):
                if domain in sub and not "@" in sub:
                    subdomains.add(sub.strip())

    except Exception:
        pass

    return list(subdomains)


def resolve_subdomain(subdomain):
    resolver = dns.resolver.Resolver()
    try:
        resolver.resolve(subdomain, "A")
        return subdomain
    except:
        return None


def brute_force_dns(domain, wordlist_path, threads=20):
    found = []

    with open(wordlist_path) as f:
        words = f.read().splitlines()

    subdomains = [f"{word}.{domain}" for word in words]

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(resolve_subdomain, sub): sub for sub in subdomains}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        executor.shutdown(wait=False)
        return found

    return found