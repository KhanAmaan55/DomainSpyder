# 🕷️ DomainSpyder

**DomainSpyder** is a modular **domain reconnaissance and intelligence framework** built in Python.
It is designed to perform fast, scalable, and extensible domain analysis

---

## 🚀 Overview

DomainSpyder is a **multi-command CLI framework** that helps you:

* **Discover assets** (subdomains via passive + active enumeration)
* **Analyze DNS records** (comprehensive DNS data with security scoring)
* **Detect live services** (HTTP probing with metadata extraction)
* **Intelligence gathering** (email setup analysis, DNS provider detection, security posture)

---

## ✨ Features

### 🔍 Subdomain Enumeration

* **Passive enumeration**:
  * crt.sh (Certificate Transparency logs)
  * AlienVault OTX (Passive DNS)
  * HackerTarget (API)
  * Wayback Machine (Internet Archive CDX)
  * RapidDNS (Web scraper)

* **Active enumeration**:
  * DNS brute force (multithreaded)
  * Configurable brute force modes (fast/balanced/stealth)
  * Custom wordlist support
  * Optional brute-only mode

* **Post-processing**:
  * Deduplication & case-insensitive filtering
  * Subdomain validation (rejects wildcards, invalid domains)

---

### 🌐 Alive Detection

* Parallel HTTP probing with timeout handling
* HTTPS → HTTP fallback
* Status code detection
* Server header extraction
* Page title extraction
* Results filterable by "alive" status

---

### 🔎 DNS Intelligence & Analysis

* **Comprehensive DNS resolving** (6 record types in parallel):
  * A, AAAA (IPv4/IPv6)
  * MX (Mail servers)
  * NS (Nameservers)
  * TXT, CNAME

* **Email security analysis**:
  * SPF record validation (strict/-all, soft fail/~all, permissive/+all)
  * DMARC policy detection (reject, quarantine, none)
  * Email provider identification (Google Workspace, Microsoft 365, Zoho, Amazon SES)
  * MX vs SPF provider mismatch warnings

* **DNS infrastructure insights**:
  * Hosting/CDN provider detection (Cloudflare, AWS Route53, Azure DNS, GoDaddy, Wix, Google Cloud)
  * Nameserver analysis
  * DMARC cached lookups

* **Security scoring** (0-10 scale):
  * Risk assessment (Low/Moderate/High)
  * Itemized issue detection
  * Best-practice recommendations

---

### ⚡ Performance Optimizations

* Parallel passive + active enumeration
* Concurrent DNS record resolution
* ThreadPool-based concurrency with configurable thread counts
* Resolver pool with DNS nameserver rotation
* Thread-local HTTP session reuse (connection pooling)
* Lightweight throttling for stability and rate-limit avoidance
* DMARC result caching with thread-safe locking

---

### 🖥️ CLI Experience

* Multi-command interface (readily extensible)
* Rich terminal tables & progress indicators
* ASCII banner with framework info
* Debug mode for detailed logging
* Flexible scan tuning via command options
* Color-coded output (semantic themes)

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

* Runs **passive enumeration** (all 5 sources) + **DNS brute force** in parallel
* Deduplicates results
* Optimized for speed (balanced mode internally)

---

### ⚡ Alive Subdomain Detection (Filter by Live Services)

```bash
domainspyder subdomains example.com --alive
```

* Filters only **live/responsive subdomains**
* Includes HTTP metadata (status code, server, page title)
* Tries HTTPS first, falls back to HTTP

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

* Skips all passive sources
* Runs only dictionary-based DNS brute force
* Uses **balanced mode** by default (50 threads, 0.005s delay)

---

## 🧠 Brute Force Modes (with `--brute-only`)

DomainSpyder provides **execution profiles** that control:

* Request delay between checks
* Thread count (concurrency level)
* Scanning aggressiveness

| Mode       | Delay  | Threads | Best For                                 |
| ---------- | ------ | ------- | ---------------------------------------- |
| `fast`     | 0.001s | 80      | Small wordlists, unrestricted targets    |
| `balanced` | 0.005s | 50      | Medium wordlists, general recon (DEFAULT)|
| `stealth`  | 0.01s  | 20      | Large wordlists, WAF/rate-limit avoidance|

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

### Basic DNS Enumeration

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


### 🐞 Debug Mode (Global)

```bash
domainspyder --debug subdomains example.com
domainspyder --debug dns example.com
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
│   └── subdomain_scanner.py # SubdomainScanner class (passive + active enumeration)
│
├── sources/                 # Data sources for passive enumeration
│   ├── __init__.py
│   ├── base.py              # BaseSource abstract class
│   ├── bruteforce.py        # DNS brute-force enumeration
│   ├── crtsh.py             # Certificate Transparency (crt.sh)
│   ├── hackertarget.py      # HackerTarget API
│   ├── otx.py               # AlienVault OTX
│   ├── rapiddns.py          # RapidDNS web scraper
│   └── wayback.py           # Internet Archive CDX
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
- Command routing (subdomains, dns)
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

### **Data Sources Layer** (`sources/`)
- Pluggable passive enumeration sources
- Inherit from `BaseSource` for consistency
- Each source implements independent HTTP/web requests

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