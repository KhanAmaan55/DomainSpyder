# 🕷️ DomainSpyder

**DomainSpyder** is a modular **domain reconnaissance and intelligence framework** built in Python.
It is designed to perform fast, scalable, and extensible domain analysis

---

## 🚀 Overview

DomainSpyder is a **multi-command CLI framework** that helps you:

- **Discover assets** (subdomains via passive + active enumeration)
- **Analyze DNS records** (comprehensive DNS data with security scoring)
- **Scan exposed ports** (fast TCP connect scanning with service banners)
- **Detect live services** (HTTP probing with metadata extraction)
- **Gather domain intelligence** (WHOIS, RDAP, SSL certificate, DNS SOA)
- **Intelligence gathering** (email setup analysis, DNS provider detection, security posture)

---

## ✨ Features

### 🔍 Subdomain Enumeration

- **Passive enumeration**:
  - crt.sh (Certificate Transparency logs)
  - AlienVault OTX (Passive DNS)
  - HackerTarget (API)
  - Wayback Machine (Internet Archive CDX)
  - RapidDNS (Web scraper)

- **Active enumeration**:
  - DNS brute force (multithreaded)
  - Configurable brute force modes (fast/balanced/stealth)
  - Custom wordlist support
  - Optional brute-only mode

- **Post-processing**:
  - Deduplication & case-insensitive filtering
  - Subdomain validation (rejects wildcards, invalid domains)

---

### 🌐 Alive Detection

- Parallel HTTP probing with timeout handling
- HTTPS → HTTP fallback
- Status code detection
- Server header extraction
- Page title extraction
- Results filterable by "alive" status

---

### 🔎 DNS Intelligence & Analysis

- **Comprehensive DNS resolving** (6 record types in parallel):
  - A, AAAA (IPv4/IPv6)
  - MX (Mail servers)
  - NS (Nameservers)
  - TXT, CNAME

- **Email security analysis**:
  - SPF record validation (strict/-all, soft fail/~all, permissive/+all)
  - DMARC policy detection (reject, quarantine, none)
  - Email provider identification (Google Workspace, Microsoft 365, Zoho, Amazon SES)
  - MX vs SPF provider mismatch warnings

- **DNS infrastructure insights**:
  - Hosting/CDN provider detection (Cloudflare, AWS Route53, Azure DNS, GoDaddy, Wix, Google Cloud)
  - Nameserver analysis
  - DMARC cached lookups

- **Security scoring** (0-10 scale):
  - Risk assessment (Low/Moderate/High)
  - Itemized issue detection
  - Best-practice recommendations

---

### 🔐 Port Scanning & Exposure Analysis

- **TCP port scanning**:
  - Concurrent TCP connect scanning
  - Default common-port scan (14 ports)
  - Custom port selection support
  - Preset scans (`--top-100`, `--top-1000`, `--full`)

- **Service fingerprinting**:
  - Basic service identification (HTTP, HTTPS, SSH, FTP, SMTP, MySQL, RDP, etc.)
  - Safe banner grabbing for responsive services
  - Reverse DNS lookup
  - Hosting/provider detection

- **Exposure insights**:
  - Open vs closed port statistics
  - High-risk service exposure warnings
  - Database/service exposure detection
  - Web-only exposure identification

---

### 🔬 Technology Detection

- **Multi-method pipeline**:
  - HTTP fingerprinting (headers, cookies)
  - Meta-tag & HTML signature parsing
  - Script & stylesheet dependency extraction
  - `robots.txt` admin panel probing
  - DNS TXT hints (verification tags)

- **Categorized results**:
  - Frontend, Backend, Server, CMS, and CDN categorization
  - Aggregated confidence scoring (`Low` to `High`)
  - Discovery of secondary libraries (Webpack, Next.js, etc.)

---

### 📋 WHOIS & Domain Info

- **Multi-source intelligence** (4 concurrent sources):
  - WHOIS protocol (registrar, dates, status, org, DNSSEC)
  - RDAP protocol (RFC 9083 structured JSON, cross-validation)
  - SSL certificate (issuer, validity, SANs, chain depth)
  - DNS SOA record (primary NS, admin, serial, zone parameters)

- **Enrichment & analysis**:
  - Domain age calculation with category labels (New/Established/Mature/Veteran)
  - Expiry alerts (critical/warning thresholds)
  - WHOIS privacy detection
  - EPP status code explanations in plain English
  - SSL certificate health monitoring

- **Resilient design**:
  - Graceful degradation when individual sources fail
  - Priority-based merge (WHOIS > RDAP > SSL > DNS SOA)
  - Only 1 new dependency (`python-whois`); other sources use existing libraries

---

### ⚡ Performance Optimizations

- Parallel passive + active enumeration
- Concurrent DNS record resolution
- ThreadPool-based concurrency with configurable thread counts
- Concurrent TCP connect scanning for port enumeration
- Resolver pool with DNS nameserver rotation
- Thread-local HTTP session reuse (connection pooling)
- Lightweight throttling for stability and rate-limit avoidance
- DMARC result caching with thread-safe locking

---

### 🖥️ CLI Experience

- Multi-command interface (readily extensible)
- Rich terminal tables & progress indicators
- ASCII banner with framework info
- Debug mode for detailed logging
- Flexible scan tuning via command options
- Color-coded output (semantic themes)

---

## 📦 Installation

### 🔧 From Source

```bash
git clone https://github.com/KhanAmaan55/DomainSpyder.git
cd DomainSpyder

python3 -m venv venv
source venv/bin/activate

pip install -e .
```

> Using `-e` (editable mode) is recommended during development.

---

## ▶️ Usage

### 🟢 Subdomain Enumeration (Default - Passive + Brute Force)

```bash
domainspyder subdomains example.com
```

- Runs **passive enumeration** (all 5 sources) + **DNS brute force** in parallel
- Deduplicates results
- Optimized for speed (balanced mode internally)

---

### ⚡ Alive Subdomain Detection (Filter by Live Services)

```bash
domainspyder subdomains example.com --alive
```

- Filters only **live/responsive subdomains**
- Includes HTTP metadata (status code, server, page title)
- Tries HTTPS first, falls back to HTTP

**Example Output:**

```
api.example.com          200   nginx
dev.example.com          403   cloudflare
admin.example.com        301   Apache/2.4.41
```

---

### 🚀 Brute Force Only Mode

Run only DNS brute force with full control:

```bash
domainspyder subdomains example.com --brute-only
```

- Skips all passive sources
- Runs only dictionary-based DNS brute force
- Uses **balanced mode** by default (50 threads, 0.005s delay)

---

## 🧠 Brute Force Modes (with `--brute-only`)

DomainSpyder provides **execution profiles** that control:

- Request delay between checks
- Thread count (concurrency level)
- Scanning aggressiveness

| Mode       | Delay  | Threads | Best For                                  |
| ---------- | ------ | ------- | ----------------------------------------- |
| `fast`     | 0.001s | 80      | Small wordlists, unrestricted targets     |
| `balanced` | 0.005s | 50      | Medium wordlists, general recon (DEFAULT) |
| `stealth`  | 0.01s  | 20      | Large wordlists, WAF/rate-limit avoidance |

### ⚙️ Examples

**Fast mode (aggressive):**

```bash
domainspyder subdomains example.com --brute-only --brutemode fast
```

Use for small wordlists (< 5,000 entries) on targets without rate limiting.

**Balanced mode (recommended):**

```bash
domainspyder subdomains example.com --brute-only --brutemode balanced
```

Use for medium wordlists (5k – 50k entries) in general recon workflows.

**Stealth mode (slow & reliable):**

```bash
domainspyder subdomains example.com --brute-only --brutemode stealth
```

Use for large wordlists (50k+ entries) or targets with WAF/rate limiting.

> ⚠️ Note: `--brutemode` is only applied when using `--brute-only`. It is ignored in default mode.

---

## ⚙️ Subdomain Enumeration: Common Options

```bash
# Custom wordlist
domainspyder subdomains example.com --wordlist custom_words.txt

# Custom thread count
domainspyder subdomains example.com --threads 100

# Save results to file
domainspyder subdomains example.com --save results.txt

# Combine options
domainspyder subdomains example.com --alive --threads 75 --save live.txt
```

---

## 🔎 DNS Intelligence & Analysis

```bash
domainspyder dns example.com
```

Resolves all DNS records (A, AAAA, MX, NS, TXT, CNAME) and provides:

- **Email security analysis** (SPF, DMARC, email providers)
- **Infrastructure insights** (DNS providers, CDN detection, nameserver analysis)
- **Security scoring** (0-10 risk assessment)

**Example Output:**

```
═══════════════════════════════════════════════════════════════
 DNS Records
═══════════════════════════════════════════════════════════════

A Records:
  93.184.216.34

MX Records:
  aspmx.l.google.com (priority: 10)
  alt1.aspmx.l.google.com (priority: 20)

TXT Records:
  v=spf1 include:_spf.google.com ~all
  google-site-verification=...

NS Records:
  a.iana-servers.net
  b.iana-servers.net

CNAME Records:
  (none)

═══════════════════════════════════════════════════════════════
 DNS Insights
═══════════════════════════════════════════════════════════════

✓ Email Setup: MX=Google Workspace | SPF=Google Workspace
✓ SPF: Strict (-all) - strong protection
✓ DMARC: Strict (reject)
─ DNS Provider: IANA Servers

═══════════════════════════════════════════════════════════════
 Security Score
═══════════════════════════════════════════════════════════════

Score: 9/10 [████████░] Low Risk

Issues: 0
Recommendations:
  ✓ DMARC strict (reject)
  ✓ SPF is strict (-all)
  ✓ SPF record present
```

---

### Raw DNS Records Only

```bash
domainspyder dns example.com --raw-only
```

Shows DNS records without analysis or security scoring.

---

## 🔐 Port Scanning & Exposure Analysis

```bash
domainspyder ports amazon.com
```

Scans the default common ports and provides:

- **Open port detection** (TCP connect scan)
- **Service identification** (basic port-to-service mapping)
- **Banner grabbing** (safe banner collection where applicable)
- **Infrastructure insights** (IP resolution, reverse DNS, hosting/provider detection)
- **Exposure analysis** (risky services, web-only exposure, broad attack surface)

**Example Output:**

```

  TARGET   amazon.com  (ports)


  ────────────────────────────────────────────────────────────
  PORT SCAN SUMMARY
  ────────────────────────────────────────────────────────────

  Target: amazon.com (98.82.161.185)
  Provider: AWS (Amazon Web Services)
  Reverse DNS: ec2-98-82-161-185.compute-1.amazonaws.com
  Ports Scanned: 14
  Open Ports: 2
  Closed: 12
  Duration: 1.156s


                                   Open Ports
╭───────┬──────────┬────────────┬──────────────┬────────────────────────────────╮
│     # │     Port │   State    │ Service      │ Banner                         │
├───────┼──────────┼────────────┼──────────────┼────────────────────────────────┤
│     1 │       80 │    open    │ http         │ HTTP/1.1 301 Moved Permanently │
│     2 │      443 │    open    │ https        │ TLS (banner skipped)           │
╰───────┴──────────┴────────────┴──────────────┴────────────────────────────────╯


  ────────────────────────────────────────────────────────────
  PORT INSIGHTS
  ────────────────────────────────────────────────────────────

    +  Only web ports exposed (80, 443)
```

---

### Port Scan Modes & Presets

DomainSpyder provides **scan presets and modes** that control:

- Port coverage
- Speed vs depth
- Banner grabbing behavior

| Option       | Behavior                                              |
| ------------ | ----------------------------------------------------- |
| Default      | Scans 14 common ports with balanced settings          |
| `--top-100`  | Scans a broader top-port preset                       |
| `--top-1000` | Scans ports `1-1000`                                  |
| `--full`     | Scans the full TCP range `1-65535`                    |
| `--fast`     | Faster scan, higher concurrency, banner grab disabled |
| `--deep`     | Deeper scan with banner grabbing enabled              |

### ⚙️ Examples

**Fast common-port scan:**

```bash
domainspyder ports example.com --fast
```

Use for quick checks where speed matters more than banner collection.

**Scan the top 100 ports:**

```bash
domainspyder ports example.com --top-100
```

Use for broader exposure checks without scanning the full range.

**Scan the top 1000 ports quickly:**

```bash
domainspyder ports example.com --top-1000 --fast
```

Use for expanded reconnaissance with reduced per-port overhead.

**Deep scan with banner grabbing:**

```bash
domainspyder ports example.com --top-100 --deep
```

Use when you want richer service details from responsive ports.

---

## ⚙️ Port Scanning: Common Options

```bash
# Custom ports
domainspyder ports example.com --ports 80,443,8080

# Top 100 ports
domainspyder ports example.com --top-100

# Top 1000 ports
domainspyder ports example.com --top-1000

# Full TCP range
domainspyder ports example.com --full

# Custom thread count
domainspyder ports example.com --top-1000 --threads 100

# Combine options
domainspyder ports example.com --ports 22,80,443,3306 --deep --threads 75
```

---

## 🔬 Technology Detection

```bash
domainspyder tech yahoo.com
```

Scans the target for web technologies using a multi-method pipeline and provides:

- **Framework & CMS identification** (Frontend, Backend, Server)
- **Metadata extraction** (Confidence levels based on signal strength)
- **Other linked tools/libraries** (Analytics, Webpack, UI libraries, etc.)

**Example Output:**

```
  TARGET   yahoo.com  (tech)


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

---

## 📋 WHOIS & Domain Info

```bash
domainspyder info example.com
```

Gathers domain intelligence from **4 concurrent sources** (WHOIS, RDAP, SSL, DNS SOA) and provides:

- **Registration details** (registrar, creation/expiry/update dates, domain age)
- **Name servers & EPP status codes** (with human-readable explanations)
- **SSL certificate health** (issuer, validity, SAN list)
- **DNS SOA record** (primary NS, admin contact, zone parameters)
- **Domain insights** (expiry alerts, DNSSEC status, privacy detection)

**Example Output:**

```
  TARGET   google.com  (info)


  ────────────────────────────────────────────────────────────
  DOMAIN INFORMATION
  ────────────────────────────────────────────────────────────

  Domain:       google.com
  Registrar:    MarkMonitor, Inc.
  Created:      1997-09-15  (28 years, 8 months — Veteran)
  Expires:      2028-09-14  (864 days remaining)
  Updated:      2019-09-09
  Organization: Google LLC
  Country:      US
  DNSSEC:       unsigned

  Sources:      dns_soa, rdap, ssl, whois
  Duration:     2.874s


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

    ~  clientDeleteProhibited   — Domain cannot be deleted by registrar
    ~  clientTransferProhibited — Domain cannot be transferred
    ~  clientUpdateProhibited   — Domain cannot be modified
    ~  serverDeleteProhibited   — Registry prevents deletion
    ~  serverTransferProhibited — Registry prevents transfer
    ~  serverUpdateProhibited   — Registry prevents modification


  ────────────────────────────────────────────────────────────
  SSL CERTIFICATE
  ────────────────────────────────────────────────────────────

  Issuer:       WR2  (Google Trust Services)
  Subject:      *.google.com
  Valid From:   2026-04-08
  Valid Until:  2026-07-01  (58 days remaining)
  SANs:         *.google.com, *.appengine.google.com, *.bdn.dev, ...
                ... and 132 more


  ────────────────────────────────────────────────────────────
  DNS SOA RECORD
  ────────────────────────────────────────────────────────────

  Primary NS:   ns1.google.com
  Admin:        dns-admin@google.com
  Serial:       909143293
  Refresh:      900s (15m)
  Retry:        900s (15m)
  Expire:       1800s (30m)
  Min TTL:      60s (1m)


  ────────────────────────────────────────────────────────────
  DOMAIN INSIGHTS
  ────────────────────────────────────────────────────────────

    !  DNSSEC is not enabled
    +  Domain is well-established (28 years, 8 months)
    +  SSL certificate is valid
    +  4/4 sources responded successfully
```

---

### Info Command Options

| Option       | Behavior                                                       |
| ------------ | -------------------------------------------------------------- |
| Default      | Runs all 4 sources (WHOIS, RDAP, SSL, DNS SOA) concurrently   |
| `--brief`    | Show only key registration fields (skip SSL, SOA, status)      |
| `--no-ssl`   | Skip SSL certificate analysis                                  |
| `--no-whois` | Skip WHOIS lookup (use RDAP + SSL + DNS only)                  |

### ⚙️ Examples

**Brief overview (key fields only):**

```bash
domainspyder info example.com --brief
```

Quick summary showing only registrar, dates, and domain age.

**Skip SSL analysis (faster):**

```bash
domainspyder info example.com --no-ssl
```

Useful behind firewalls or when SSL connection is blocked.

**Use only RDAP + SSL + DNS (skip WHOIS):**

```bash
domainspyder info example.com --no-whois
```

Useful when WHOIS servers are rate-limiting or unreachable.

---

### 🐞 Debug Mode (Global)

```bash
domainspyder --debug subdomains example.com
domainspyder --debug dns example.com
domainspyder --debug ports example.com --top-100
domainspyder --debug info example.com
```

Enables detailed logging for troubleshooting and development.

---

## 📊 Example Workflow

```bash
# Discover subdomains
domainspyder subdomains target.com

# Find live subdomains with HTTP info
domainspyder subdomains target.com --alive --save live-subdomains.txt

# Run aggressive brute force on a small wordlist
domainspyder subdomains target.com --brute-only --brutemode fast

# Analyze DNS security posture
domainspyder dns target.com

# Scan exposed services
domainspyder ports target.com --top-100

# Discover applied web technologies
domainspyder tech target.com

# Gather WHOIS + domain intelligence
domainspyder info target.com

# Quick domain overview
domainspyder info target.com --brief

# Run with debug logging for troubleshooting
domainspyder --debug dns target.com --raw-only
```

---

## 🏗️ Project Structure

```
domainspyder/
├── __init__.py              # Package initialization
├── __main__.py              # Entry point for 'python -m domainspyder'
├── cli.py                   # CLI entry point, argument parsing, command routing
├── config.py                # Configuration & constants (DNS servers, brute modes, providers)
├── utils.py                 # Utilities (HTTP session pooling, domain validation, provider mapping)
│
├── scanners/                # Core scanning logic
│   ├── __init__.py
│   ├── dns_scanner.py       # DNSScanner class (resolution, analysis, security scoring)
│   ├── info_scanner.py      # InfoScanner class (multi-source domain intelligence)
│   ├── port_scanner.py      # PortScanner class (scanning, banner grabbing, analysis)
│   ├── subdomain_scanner.py # SubdomainScanner class (passive + active enumeration)
│   └── tech_scanner.py      # TechScanner class (multi-method web tech detection)
│
├── sources/                 # Data sources for passive enumeration
│   ├── __init__.py
│   ├── base.py              # BaseSource abstract class
│   ├── bruteforce.py        # DNS brute-force enumeration
│   ├── crtsh.py             # Certificate Transparency (crt.sh)
│   ├── hackertarget.py      # HackerTarget API
│   ├── otx.py               # AlienVault OTX
│   ├── rapiddns.py          # RapidDNS web scraper
│   ├── wayback.py           # Internet Archive CDX
│   └── info/                # Domain info data sources
│       ├── __init__.py      # Info source registry
│       ├── base_info_source.py  # BaseInfoSource abstract class
│       ├── whois_source.py  # WHOIS protocol lookup
│       ├── rdap_source.py   # RDAP protocol (RFC 9083 JSON)
│       ├── ssl_source.py    # SSL certificate extraction (stdlib)
│       └── dns_soa_source.py # DNS SOA record query
│
└── display/                 # Output & formatting
    ├── __init__.py
    ├── banner.py            # ASCII art spider banner
    ├── formatter.py         # Rich terminal output (tables, panels, progress)
    └── themes.py            # Color themes & semantic styling

wordlists/
└── default.txt              # Default subdomain wordlist (~50 common subdomains)

requirements.txt             # Project dependencies (alternative to setup.py)
setup.py                     # Package configuration & installation
README.md                    # This file
LICENCE                      # License information
```

---

## 🧠 Architecture

DomainSpyder follows a **modular, layered design**:

### **CLI Layer** (`cli.py`)

- Argument parsing & validation
- Command routing (subdomains, dns, ports, tech, info)
- User interface orchestration

### **Core Scanning Layer** (`scanners/`)

**SubdomainScanner:**

- Orchestrates passive sources + brute-force in parallel
- Deduplicates & validates results
- Optionally probes for live services (HTTP metadata extraction)

**DNSScanner:**

- Parallel DNS record resolution (6 record types)
- Email security analysis (SPF, DMARC provider detection)
- Infrastructure insights (nameserver, CDN, hosting provider detection)
- Security scoring & risk assessment

**PortScanner:**

- Concurrent TCP connect scanning
- Port preset selection and custom port support
- Safe banner grabbing and service identification
- Exposure analysis with provider and reverse-DNS enrichment

**TechScanner:**

- Multi-method detection pipeline (HTTP headers/body, tags, scripts, `robots.txt`, DNS hints)
- Categorized output with confidence scoring
- Security header analysis

**InfoScanner:**

- Multi-source domain intelligence (WHOIS, RDAP, SSL, DNS SOA)
- Concurrent source execution with graceful degradation
- Priority-based result merging (WHOIS > RDAP > SSL > SOA)
- Domain age, expiry alerts, privacy detection, EPP status explanations

### **Data Sources Layer** (`sources/`)

- Pluggable passive enumeration sources
- Inherit from `BaseSource` for consistency
- Each source implements independent HTTP/web requests
- Domain info sources (`sources/info/`) inherit from `BaseInfoSource`
- Info sources return dicts (not lists) for structured field merging

### **Utilities Layer** (`utils.py`)

- DNS & HTTP session management
- Domain validation & filtering
- Provider mapping & normalization
- Shared helper functions

### **Display Layer** (`display/`)

- Banner rendering
- Rich table formatting
- Progress indicators
- Semantic color theming

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.

Do not use DomainSpyder against systems without explicit permission.

---

## 👨‍💻 Author

**Amaan Khan**
GitHub: https://github.com/KhanAmaan55

---

## ⭐ Contributing

Contributions, issues, and feature requests are welcome.

If you’d like to contribute:

1. Fork the repository
2. Create a new branch
3. Submit a pull request

---
