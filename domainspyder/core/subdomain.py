from domainspyder.utils.dns import (
    get_subdomains_crtsh,
    brute_force_dns,
    get_subdomains_hackertarget,
    get_subdomains_otx,
    get_subdomains_rapiddns,
    get_subdomains_wayback
)

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import requests

def fetch_all_sources(domain, debug=False):
    functions = [
        ("crt.sh", get_subdomains_crtsh),
        ("otx", get_subdomains_otx),
        ("hackertarget", get_subdomains_hackertarget),
        ("wayback", get_subdomains_wayback),
        ("rapiddns", get_subdomains_rapiddns)
    ]

    subs = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(func, domain): name
            for name, func in functions
        }

        for future in as_completed(futures):
            name = futures[future]

            try:
                result = future.result()
                if result:
                    subs.extend(result)

                if debug:
                    logging.debug(f"{name}: {len(result) if result else 0} subdomains")

            except Exception as e:
                logging.error(f"{name} failed: {e}")

    return subs


def enumerate_domain(domain, wordlist, threads=50, debug=False, alive=False):
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_passive = executor.submit(fetch_all_sources, domain, debug)
        future_brute = executor.submit(brute_force_dns, domain, wordlist, threads, debug)

        passive_subs = future_passive.result()
        brute_subs = future_brute.result()

    if debug:
        logging.debug(f"passive total: {len(passive_subs)}")
        logging.debug(f"brute force: {len(brute_subs)}")

    all_subs = passive_subs + brute_subs

    results = set()

    for sub in all_subs:
        sub = sub.lower().strip()

        if not sub.endswith(domain):
            continue
        if "*" in sub or "@" in sub:
            continue

        results.add(sub)

    if debug:
        logging.debug(f"final unique: {len(results)}")

    if alive:
        def is_alive(sub):
            try:
                r = requests.get(f"http://{sub}", timeout=3)
                return sub if r.status_code < 500 else None
            except:
                try:
                    r = requests.get(f"https://{sub}", timeout=3)
                    return sub if r.status_code < 500 else None
                except:
                    return None

        alive_results = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(is_alive, sub): sub for sub in results}

            for future in as_completed(futures):
                res = future.result()
                if res:
                    alive_results.append(res)

        if debug:
            logging.debug(f"alive count: {len(alive_results)}")

        return sorted(alive_results)

    return sorted(results)