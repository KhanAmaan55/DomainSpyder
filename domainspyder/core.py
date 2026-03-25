from .utils import get_subdomains_crtsh, brute_force_dns

def enumerate_domain(domain, wordlist, threads=20):
    crt = get_subdomains_crtsh(domain)
    brute = brute_force_dns(domain, wordlist, threads)

    return sorted(set(crt + brute))