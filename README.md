<h1 align="center">
  <img src="https://raw.githubusercontent.com/KhanAmaan55/DomainSpyder/main/assets/img/logo_readme.png" alt="🕷️ DomainSpyder" width="600">
</h1>

**Domain intelligence from one CLI**: subdomain enumeration, DNS analysis, port
scanning, technology detection and WHOIS, with JSON and HTML reports.

[![PyPI](https://img.shields.io/pypi/v/domainspyder.svg)](https://pypi.org/project/domainspyder/)
[![Python](https://img.shields.io/pypi/pyversions/domainspyder.svg)](https://pypi.org/project/domainspyder/)
[![CI](https://github.com/KhanAmaan55/DomainSpyder/actions/workflows/ci.yml/badge.svg)](https://github.com/KhanAmaan55/DomainSpyder/actions/workflows/ci.yml)
[![CodeQL](https://github.com/KhanAmaan55/DomainSpyder/actions/workflows/codeql.yml/badge.svg)](https://github.com/KhanAmaan55/DomainSpyder/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/KhanAmaan55/DomainSpyder/blob/main/LICENCE)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/KhanAmaan55/DomainSpyder?utm_source=oss&utm_medium=github&utm_campaign=KhanAmaan55%2FDomainSpyder&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)](https://coderabbit.ai)

> ⚠️ **Only scan domains and hosts you own or are authorised to test.**
> Read the Disclaimer section below before running it against anything else.

## Quick start

```bash
pipx install domainspyder

domainspyder subdomains example.com --alive
domainspyder dns example.com
domainspyder info example.com --output report.html
```

## Commands

| Command      | What it does                                                                |
| ------------ | --------------------------------------------------------------------------- |
| `subdomains` | Passive enumeration from 5 public sources plus multithreaded DNS brute force |
| `dns`        | A, AAAA, MX, NS, TXT and CNAME records, SPF/DMARC analysis, a 0-10 security score |
| `ports`      | Concurrent TCP connect scan with service identification and banner grabbing |
| `tech`       | Web technology fingerprinting with confidence scores and versions           |
| `info`       | WHOIS, RDAP, SSL certificate and DNS SOA data merged into one view         |

Every command can export a structured report with `--output` (`.json` or `.html`).

## Installation

Requires Python 3.9 or newer.

```bash
pipx install domainspyder     # recommended: isolated, puts `domainspyder` on your PATH
# or
pip install domainspyder
```

Check the install, or upgrade to the latest release:

```bash
domainspyder --version

pipx upgrade domainspyder
# or
pip install --upgrade domainspyder
```

Release notes are in the [changelog](https://github.com/KhanAmaan55/DomainSpyder/blob/main/CHANGELOG.md).
To install from source for development, see [CONTRIBUTING.md](https://github.com/KhanAmaan55/DomainSpyder/blob/main/CONTRIBUTING.md).

## Features

**Subdomain enumeration**

- Passive sources: crt.sh (Certificate Transparency), AlienVault OTX (passive DNS),
  HackerTarget, RapidDNS and the Wayback Machine
- Multithreaded DNS brute force with `fast`, `balanced` and `stealth` modes and custom wordlists
- Wildcard DNS detection, so wildcard answers are not reported as real subdomains
- Alive detection with status code, server header and page title (HTTPS first, HTTP fallback)

**DNS intelligence**

- Six record types resolved in parallel over a rotating resolver pool
- SPF validation (`-all`, `~all`, `+all`) and DMARC policy detection
- Email provider identification (Google Workspace, Microsoft 365, Zoho, Amazon SES)
  and MX/SPF mismatch warnings
- DNS/CDN provider detection (Cloudflare, AWS Route 53, Azure DNS, Google Cloud, GoDaddy, Wix)
- A 0-10 security score with itemised issues and recommendations

**Port scanning**

- Concurrent TCP connect scanning of common ports, custom lists or preset ranges
- Service identification, safe banner grabbing and reverse DNS
- Exposure insights for remote-access, database and other high-risk services

**Technology detection**

- HTTP headers, cookies, meta tags, HTML signatures, scripts and stylesheets
- Concurrent probes: `robots.txt`, DNS TXT hints, favicon hashes, `sitemap.xml`
  and the WordPress `/wp-json/` API
- Frontend, backend, server, CMS and CDN categories with confidence scores and versions
- Security header analysis (HSTS, CSP, X-Frame-Options)

**Domain info**

- WHOIS, RDAP (RFC 9083), SSL certificate and DNS SOA queried concurrently
- Keeps working when individual sources fail, merging results by priority
  (WHOIS > RDAP > SSL > DNS SOA)
- Domain age, expiry alerts, WHOIS privacy detection and plain-English EPP status codes

## Usage

```bash
domainspyder <command> <target> [options]
domainspyder <command> --help
```

### Targets

Targets are normalised before scanning, so `https://Example.com/path`,
`example.com.` and `example.com:8443` all scan `example.com`.
`subdomains`, `dns` and `info` need a domain name; `ports` also accepts an
IPv4 address, and `tech` accepts a full URL (the path is kept).

### Subdomain enumeration

```bash
domainspyder subdomains example.com
```

Runs all 5 passive sources and a DNS brute force in parallel, then deduplicates the results.

| Option                   | Behaviour                                                       |
| ------------------------ | --------------------------------------------------------------- |
| `--alive`                | Show only live subdomains, with status code, server and title   |
| `--brute-only`           | Skip passive sources and run only the DNS brute force           |
| `--brutemode MODE`       | `fast`, `balanced` (default) or `stealth`; applies with `--brute-only` |
| `--wordlist PATH`        | Use a custom wordlist instead of the bundled one                |
| `--threads N`            | Number of threads (default: 50)                                 |
| `--save PATH`            | Save the subdomain list to a text file                          |

```console
$ domainspyder subdomains example.com --alive

                                    Alive Subdomains
╭───────┬────────────────────────────────┬──────────┬─────────────────┬────────────────╮
│     # │ Subdomain                      │  Status  │ Server          │ Title          │
├───────┼────────────────────────────────┼──────────┼─────────────────┼────────────────┤
│     1 │ www.example.com                │   200    │ cloudflare      │ Example Domain │
╰───────┴────────────────────────────────┴──────────┴─────────────────┴────────────────╯

  TOTAL   1 result(s) found
```

#### Brute-force modes

| Mode       | Delay  | Threads | Best for                                  |
| ---------- | ------ | ------- | ----------------------------------------- |
| `fast`     | 0.001s | 80      | Small wordlists, unrestricted targets     |
| `balanced` | 0.005s | 50      | Medium wordlists, general recon (default) |
| `stealth`  | 0.01s  | 20      | Large wordlists, WAF/rate-limit avoidance |

```bash
domainspyder subdomains example.com --brute-only --brutemode stealth --wordlist words.txt
```

Before brute-forcing, DomainSpyder resolves a few random labels. If the domain
answers for names that don't exist (`*.example.com`), hits that resolve only to
those wildcard addresses are discarded, and the scan reports that a wildcard was
detected.

### DNS analysis

```bash
domainspyder dns example.com
domainspyder dns example.com --raw-only    # records only, no analysis or score
```

```console
$ domainspyder dns example.com

  ────────────────────────────────────────────────────────────
  RAW DNS RECORDS
  ────────────────────────────────────────────────────────────

  [A]
    104.20.23.154
    172.66.147.243

  [AAAA]
    2606:4700:8dd5:72db:f243:0:ef6b:ff98

  [NS]
    elliott.ns.cloudflare.com
    hera.ns.cloudflare.com

  [TXT]
    _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9
    v=spf1 -all

  ────────────────────────────────────────────────────────────
  DNS INSIGHTS
  ────────────────────────────────────────────────────────────

    +  DMARC: Strict (reject)
    +  DNS/CDN Provider: Cloudflare
    +  SPF: Strict (-all) - strong protection

  ────────────────────────────────────────────────────────────
  SECURITY SUMMARY
  ────────────────────────────────────────────────────────────

  Score: [██████████]  10/10  Low Risk

  Passed:
    +  SPF record present
    +  SPF is strict (-all)
    +  DMARC strict (reject)
```

### Port scanning

```bash
domainspyder ports scanme.nmap.org
```

[`scanme.nmap.org`](http://scanme.nmap.org/) is a host the Nmap project provides
for testing scanners.

| Option          | Behaviour                                              |
| --------------- | ------------------------------------------------------ |
| Default         | Scans 14 common ports                                  |
| `--ports LIST`  | Scans a comma-separated list, e.g. `22,80,443`         |
| `--top-100`     | Scans a preset of 20 high-value ports                  |
| `--top-1000`    | Scans ports `1-1000`                                   |
| `--full`        | Scans the full TCP range `1-65535`                     |
| `--fast`        | Higher concurrency, banner grabbing disabled           |
| `--deep`        | Banner grabbing enabled for richer service details     |
| `--threads N`   | Number of threads (default: 50)                        |

```console
$ domainspyder ports scanme.nmap.org

  ────────────────────────────────────────────────────────────
  PORT SCAN SUMMARY
  ────────────────────────────────────────────────────────────

  Target: scanme.nmap.org (45.33.32.156)
  Provider: Unknown
  Reverse DNS: scanme.nmap.org
  Ports Scanned: 14
  Open Ports: 2
  Closed: 12
  Duration: 1.715s

                                        Open Ports
╭───────┬──────────┬────────────┬──────────────┬─────────────────────────────────────────╮
│     # │     Port │   State    │ Service      │ Banner                                  │
├───────┼──────────┼────────────┼──────────────┼─────────────────────────────────────────┤
│     1 │       22 │    open    │ ssh          │ SSH-2.0-OpenSSH_6.6.1p1                 │
│       │          │            │              │ Ubuntu-2ubuntu2.13                      │
│     2 │       80 │    open    │ http         │ HTTP/1.1 200 OK                         │
╰───────┴──────────┴────────────┴──────────────┴─────────────────────────────────────────╯

  ────────────────────────────────────────────────────────────
  PORT INSIGHTS
  ────────────────────────────────────────────────────────────

    !  SSH exposed (remote access)
```

### Technology detection

```bash
domainspyder tech yahoo.com
```

```console
$ domainspyder tech yahoo.com

  ────────────────────────────────────────────────────────────
  TECHNOLOGY DETECTION
  ────────────────────────────────────────────────────────────

  Target: yahoo.com
  URL: https://www.yahoo.com/
  Status: 200

  [Frontend  ] React     ████████░░ (High)
  [CMS       ] Magento   ████░░░░░░ (Low)

  Other Technologies:
    + Next.js
    + Webpack
```

Low-confidence results come from weak signals and are worth confirming by hand.

### Domain info

```bash
domainspyder info example.com
```

| Option       | Behaviour                                                   |
| ------------ | ----------------------------------------------------------- |
| Default      | Queries WHOIS, RDAP, SSL and DNS SOA concurrently           |
| `--brief`    | Show only key registration fields (skip SSL, SOA, status)   |
| `--no-ssl`   | Skip the SSL certificate check, e.g. when port 443 is blocked |
| `--no-whois` | Skip WHOIS (use RDAP, SSL and DNS only), e.g. when WHOIS is rate-limited |

<details>
<summary>Example output</summary>

```console
$ domainspyder info google.com

  ────────────────────────────────────────────────────────────
  DOMAIN INFORMATION
  ────────────────────────────────────────────────────────────

  Domain:       google.com
  Registrar:    MarkMonitor, Inc.
  Created:      1997-09-15  (29 years — Veteran)
  Expires:      2028-09-14  (719 days remaining)
  Updated:      2019-09-09
  Organization: Google LLC
  Country:      US
  DNSSEC:       unsigned

  Sources:      dns_soa, rdap, ssl, whois
  Duration:     2.547s

  ────────────────────────────────────────────────────────────
  NAME SERVERS
  ────────────────────────────────────────────────────────────

    +  ns1.google.com
    +  ns2.google.com
    +  ns3.google.com
    +  ns4.google.com

  ────────────────────────────────────────────────────────────
  REGISTRATION STATUS
  ────────────────────────────────────────────────────────────

    ~  clientDeleteProhibited  — Domain cannot be deleted by registrar
    ~  clientTransferProhibited  — Domain cannot be transferred
    ~  clientUpdateProhibited  — Domain cannot be modified
    ~  serverDeleteProhibited  — Registry prevents deletion
    ~  serverTransferProhibited  — Registry prevents transfer
    ~  serverUpdateProhibited  — Registry prevents modification

  ────────────────────────────────────────────────────────────
  SSL CERTIFICATE
  ────────────────────────────────────────────────────────────

  Issuer:       WE2  (Google Trust Services)
  Subject:      *.google.com
  Valid From:   2026-09-10
  Valid Until:  2026-12-03  (69 days remaining)
  SANs:         *.google.com, *.appengine.google.com, *.bdn.dev, *.origin-test.bdn.dev, *.cloud.google.com
                ... and 60 more

  ────────────────────────────────────────────────────────────
  DNS SOA RECORD
  ────────────────────────────────────────────────────────────

  Primary NS:   ns1.google.com
  Admin:        dns-admin@google.com
  Serial:       987384001
  Refresh:      900s (15m)
  Retry:        900s (15m)
  Expire:       1800s (30m)
  Min TTL:      60s (1m)

  ────────────────────────────────────────────────────────────
  DOMAIN INSIGHTS
  ────────────────────────────────────────────────────────────

    !  DNSSEC is not enabled
    +  Domain is well-established (29 years)
    +  SSL certificate is valid
    +  4/4 sources responded successfully
```

</details>

### Reports

Every command accepts `--output`. The file extension picks the format: `.json`
for raw data, `.html` for a self-contained, readable report. HTML reports use
the light theme by default; add `--html-dark` for the dark theme.

```bash
domainspyder dns example.com --output dns.json
domainspyder ports scanme.nmap.org --output ports.html --html-dark
```

### Debug logging

`--debug` goes before the command and enables detailed logging:

```bash
domainspyder --debug dns example.com
```

### Exit codes

| Exit code | Meaning                                                           |
| --------- | ----------------------------------------------------------------- |
| `0`       | Scan completed (including scans that found nothing)               |
| `1`       | Scan failed (e.g. target did not resolve) or saving/export failed |
| `2`       | Invalid arguments (bad domain, port list, thread count, wordlist) |
| `130`     | Interrupted with Ctrl+C                                           |

## Disclaimer

DomainSpyder is intended for **authorised security testing, research and education**.

- **Only scan targets you own or have explicit permission to test.** Port
  scanning and brute-force subdomain enumeration can break the law, a contract
  or a provider's acceptable-use policy, even when nothing is exploited.
- **Passive enumeration shares the target with third parties.** The
  `subdomains` command sends the domain to crt.sh, AlienVault OTX,
  HackerTarget, RapidDNS and the Wayback Machine. If your scope does not allow
  that, use `--brute-only`, which only makes DNS lookups through public
  resolvers such as `8.8.8.8` and `1.1.1.1`.
- **You are responsible for how you use it.** DomainSpyder is provided "as is",
  without warranty of any kind.

## Contributing

Bug reports, feature requests and pull requests are welcome. See
[CONTRIBUTING.md](https://github.com/KhanAmaan55/DomainSpyder/blob/main/CONTRIBUTING.md)
for development setup, checks, project structure and architecture.

## License

Released under the [MIT License](https://github.com/KhanAmaan55/DomainSpyder/blob/main/LICENCE).
Created by [Amaan Khan](https://github.com/KhanAmaan55).
