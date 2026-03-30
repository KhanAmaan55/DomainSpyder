import dns.resolver
import logging

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

# ---------------------------
# Provider normalization
# ---------------------------
PROVIDER_MAP = {
    "google": "Google Workspace",
    "zoho": "Zoho Mail",
    "microsoft": "Microsoft 365",
    "amazon": "Amazon SES"
}


def normalize_provider(value):
    value = value.lower()
    if "google" in value:
        return "google"
    elif "zoho" in value:
        return "zoho"
    elif "outlook" in value or "protection.outlook.com" in value:
        return "microsoft"
    elif "amazonses" in value:
        return "amazon"
    return None


def display_provider(p):
    return PROVIDER_MAP.get(p, p)


def get_dmarc_record(domain, debug=False):
    if debug:
        logging.debug(f"[DMARC] Querying _dmarc.{domain}")
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        records = ["".join([part.decode() for part in r.strings]) for r in answers]
        if debug:
            logging.debug(f"[DMARC] Found: {records}")
        return records, True
    except Exception:
        if debug:
            logging.debug(f"[DMARC] Not found or failed")
        return [], False
    
def resolve_record(domain, record_type, debug=False):
    if debug:
        logging.debug(f"[DNS] Resolving {record_type} for {domain}")

    resolver = dns.resolver.Resolver()
    DNS_SERVERS = [["8.8.8.8"], ["1.1.1.1"], ["9.9.9.9"]]

    answers = None

    for ns in DNS_SERVERS:
        try:
            resolver.nameservers = ns
            answers = resolver.resolve(domain, record_type)
            break
        except Exception:
            continue

    if not answers:
        if debug:
            logging.debug(f"[DNS] {record_type} → No valid response")
        return []

    results = []

    try:
        for rdata in answers:
            if record_type == "MX":
                exchange = str(rdata.exchange).rstrip(".")
                preference = rdata.preference
                results.append((preference, exchange))

            elif record_type == "TXT":
                results.append("".join([part.decode() for part in rdata.strings]))

            else:
                results.append(str(rdata).rstrip("."))

    except Exception as e:
        if debug:
            logging.debug(f"[DNS ERROR] {record_type} failed: {e}")
        return []

    if record_type == "MX":
        results.sort(key=lambda x: x[0])
        results = [r[1] for r in results]

    if debug:
        logging.debug(f"[DNS] {record_type} → {results}")

    return results

def analyze_dns(records, domain, debug=False):
    if debug:
        logging.debug("[ANALYZE] Starting DNS analysis")

    insights = set()

    ns_records = records.get("NS", [])
    mx_records = records.get("MX", [])
    txt_records = records.get("TXT", [])

    for ns in ns_records:
        ns = ns.lower()
        if "wixdns.net" in ns:
            insights.add("Hosting/DNS Provider: Wix")
        elif "cloudflare.com" in ns:
            insights.add("DNS/CDN Provider: Cloudflare")
        elif "domaincontrol.com" in ns:
            insights.add("DNS Provider: GoDaddy")
        elif "awsdns" in ns:
            insights.add("DNS Provider: AWS Route53")
        elif "azure-dns" in ns:
            insights.add("DNS Provider: Azure DNS")
        elif "google" in ns:
            insights.add("DNS Provider: Google Cloud DNS")

    mx_providers = set()
    spf_providers = set()

    for mx in mx_records:
        p = normalize_provider(mx)
        if p:
            mx_providers.add(p)

    for txt in txt_records:
        p = normalize_provider(txt)
        if p:
            spf_providers.add(p)

    if any("smtp.google.com" in mx for mx in mx_records):
        insights.add("ℹ️ MX may be simplified due to DNS resolver behavior")

    if mx_providers or spf_providers:
        insights.add(
            f"Email Setup: MX={', '.join(display_provider(p) for p in mx_providers) or 'Unknown'} "
            f"| SPF={', '.join(display_provider(p) for p in spf_providers) or 'Unknown'}"
        )

        if mx_providers != spf_providers:
            insights.add("⚠️ Possible email misconfiguration (MX ≠ SPF providers)")

    spf_records = [txt for txt in txt_records if "v=spf1" in txt.lower()]
    if not spf_records:
        insights.add("SPF: Not configured")
    else:
        for spf in spf_records:
            spf = spf.lower()
            if "-all" in spf:
                insights.add("SPF: Strict (-all) - strong protection")
            elif "~all" in spf:
                insights.add("SPF: Soft fail (~all) - weaker protection")
            elif "+all" in spf:
                insights.add("⚠️ SPF: Permissive (+all) - insecure")

    dmarc_records, success = get_dmarc_record(domain, debug)
    if not success:
        insights.add("⚠️ DMARC: Unable to verify")
    elif not dmarc_records:
        insights.add("⚠️ DMARC: Not configured")
    else:
        for dmarc in dmarc_records:
            dmarc = dmarc.lower()
            if "p=reject" in dmarc:
                insights.add("DMARC: Strict (reject) ✓")
            elif "p=quarantine" in dmarc:
                insights.add("DMARC: Moderate (quarantine) ✓")
            elif "p=none" in dmarc:
                insights.add("DMARC: Monitoring only (none) ⚠️")

    return sorted(insights)

def calculate_dns_security(records, domain, debug=False):
    score = 10
    issues = []
    good = []

    txt_records = records.get("TXT", [])
    mx_records = records.get("MX", [])

    spf_records = [txt for txt in txt_records if "v=spf1" in txt.lower()]

    if not spf_records:
        score -= 2
        issues.append("SPF not configured")
    else:
        good.append("SPF record present")

        if len(spf_records) > 1:
            score -= 2
            issues.append("Multiple SPF records detected")

        for spf in spf_records:
            spf = spf.lower()
            if "+all" in spf:
                score -= 4
                issues.append("SPF is permissive (+all)")
            elif "~all" in spf:
                score -= 1
                issues.append("SPF is soft fail (~all)")
            elif "-all" in spf:
                good.append("SPF is strict (-all)")

    dmarc_records, success = get_dmarc_record(domain, debug)

    if not success:
        score -= 1
        issues.append("DMARC lookup failed")
    elif not dmarc_records:
        score -= 2
        issues.append("DMARC not configured")
    else:
        for dmarc in dmarc_records:
            dmarc = dmarc.lower()
            if "p=none" in dmarc:
                score -= 1
                issues.append("DMARC policy is none")
            elif "p=quarantine" in dmarc:
                good.append("DMARC quarantine enabled")
            elif "p=reject" in dmarc:
                good.append("DMARC strict (reject)")

    mx_providers = {normalize_provider(mx) for mx in mx_records if normalize_provider(mx)}
    spf_providers = {normalize_provider(txt) for txt in txt_records if normalize_provider(txt)}

    if mx_providers and spf_providers and mx_providers != spf_providers:
        score -= 1
        issues.append("Email provider mismatch (MX ≠ SPF)")

    score = max(score, 0)

    if score >= 8:
        risk = "Low Risk"
    elif score >= 5:
        risk = "Moderate Risk"
    else:
        risk = "High Risk"

    return {
        "score": score,
        "risk": risk,
        "issues": issues,
        "good": good
    }

def enumerate_dns(domain, debug=False):
    output = {}

    for record in RECORD_TYPES:
        if debug:
            logging.debug(f"Resolving {record} records...")
        result = resolve_record(domain, record, debug)
        if result:
            output[record] = result

    return output