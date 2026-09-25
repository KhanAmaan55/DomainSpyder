# Contributing to DomainSpyder

Contributions, bug reports and feature requests are welcome. Please open an
[issue](https://github.com/KhanAmaan55/DomainSpyder/issues) before starting on a
large change, so the approach can be agreed first.

## Development setup

Requires Python 3.9 or newer.

```bash
git clone https://github.com/KhanAmaan55/DomainSpyder.git
cd DomainSpyder

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip     # editable installs need pip >= 21.3
pip install -e ".[dev]"
```

## Checks

CI runs these on every pull request. Run them locally before pushing:

```bash
ruff check domainspyder/
black --check domainspyder/
mypy domainspyder/
pytest tests/ --cov=domainspyder
```

Tests run on Python 3.9 to 3.14. Tests must not make real network requests;
mock them with `pytest-mock` or `responses`.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep each pull request focused on one change, with tests for new behaviour.
3. Add an entry under an `Unreleased` heading in [CHANGELOG.md](CHANGELOG.md).
4. Open the pull request against `main`.

## Project structure

```
domainspyder/
├── __init__.py              # Package initialization
├── __main__.py              # Entry point for 'python -m domainspyder'
├── _version.py              # Single source of truth for the version
├── cli.py                   # CLI entry point, argument parsing, command routing
├── config.py                # Configuration & constants (DNS servers, brute modes, providers)
├── utils.py                 # Utilities (HTTP session pooling, input normalisation, provider mapping)
├── assets/
│   └── img/
│       └── logo.png         # Logo embedded in HTML reports
├── wordlists/
│   └── default.txt          # Bundled subdomain wordlist (~110 common names)
│
├── scanners/                # Core scanning logic
│   ├── __init__.py
│   ├── dns_scanner.py       # DNSScanner class (resolution, analysis, security scoring)
│   ├── info_scanner.py      # InfoScanner class (multi-source domain intelligence)
│   ├── port_scanner.py      # PortScanner class (scanning, banner grabbing, analysis)
│   ├── subdomain_scanner.py # SubdomainScanner class (passive + active enumeration)
│   └── tech_scanner.py      # TechScanner class (multi-method web tech detection)
│
├── sources/                 # Data sources used by the scanners
│   ├── __init__.py
│   ├── subdomains/          # Subdomain enumeration data sources
│   │   ├── __init__.py
│   │   ├── base.py          # BaseSource abstract class
│   │   ├── bruteforce.py    # DNS brute-force enumeration
│   │   ├── crtsh.py         # Certificate Transparency (crt.sh)
│   │   ├── hackertarget.py  # HackerTarget API
│   │   ├── otx.py           # AlienVault OTX
│   │   ├── rapiddns.py      # RapidDNS web scraper
│   │   └── wayback.py       # Internet Archive CDX
│   ├── info/                # Domain info data sources
│   │   ├── __init__.py      # Info source registry
│   │   ├── base_info_source.py  # BaseInfoSource abstract class
│   │   ├── whois_source.py  # WHOIS protocol lookup
│   │   ├── rdap_source.py   # RDAP protocol (RFC 9083 JSON)
│   │   ├── ssl_source.py    # SSL certificate extraction (stdlib)
│   │   └── dns_soa_source.py # DNS SOA record query
│   └── tech/                # Tech detection modular sources & probes
│       ├── __init__.py
│       ├── helpers.py       # Shared scoring utilities
│       ├── http_detectors.py # Server, Backend, CDN detection
│       ├── html_detectors.py # Frontend, CMS detection
│       ├── asset_analysis.py # Scripts, stylesheets, meta tags
│       ├── security_analysis.py # Security header audit
│       ├── cookie_detector.py # Cookie-based tech detection
│       ├── version_extractor.py # Version number extraction
│       ├── dns_hints_probe.py # DNS TXT hint verification
│       ├── robots_probe.py  # robots.txt hint probe
│       ├── favicon_probe.py # Favicon hash fingerprinting
│       ├── sitemap_probe.py # sitemap.xml CMS cross-validation
│       └── wp_api_probe.py  # WordPress /wp-json/ REST API probe
│
├── reporting/               # Structured report export (--output)
│   ├── __init__.py
│   ├── exporter.py          # Exporter registry, picks JSON/HTML by file extension
│   ├── json_report.py       # JSON exporter
│   └── html_report.py       # Standalone HTML exporter (light/dark themes)
│
└── display/                 # Output & formatting
    ├── __init__.py
    ├── banner.py            # ASCII art spider banner
    ├── formatter.py         # Rich terminal output (tables, panels, progress)
    └── themes.py            # Color themes & semantic styling

tests/                       # Pytest suite (one test module per component)
assets/img/                  # Logo artwork (logo_readme.png is the README banner)
.github/
├── workflows/
│   ├── ci.yml               # Lint, type-check and test matrix
│   ├── codeql.yml           # CodeQL security analysis
│   └── release.yml          # Build and publish to TestPyPI / PyPI
├── codeql/codeql-config.yml # CodeQL configuration
└── dependabot.yml           # Dependency update schedule

pyproject.toml               # Package metadata, dependencies & tool configuration
requirements.txt             # Dev shortcut: installs the package editable with dev extras
CHANGELOG.md                 # Release notes
CONTRIBUTING.md              # This file
CODEOWNERS                   # Default reviewers
README.md                    # Project overview and usage
LICENCE                      # License information
```

## Architecture

DomainSpyder follows a modular, layered design.

### CLI layer (`cli.py`)

- Argument parsing & validation
- Command routing (subdomains, dns, ports, tech, info)
- User interface orchestration

### Core scanning layer (`scanners/`)

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

- Orchestrates multi-method detection pipeline (HTTP headers/body, tags, scripts)
- Runs concurrent network probes (`robots.txt`, DNS hints, favicons, sitemaps, `/wp-json/`)
- Merges, scores, and categorizes results with confidence ratings
- Extracts component versions and performs security header analysis

**InfoScanner:**

- Multi-source domain intelligence (WHOIS, RDAP, SSL, DNS SOA)
- Concurrent source execution with graceful degradation
- Priority-based result merging (WHOIS > RDAP > SSL > SOA)
- Domain age, expiry alerts, privacy detection, EPP status explanations

### Data sources layer (`sources/`)

- Pluggable passive enumeration sources
- Inherit from `BaseSource` for consistency
- Each source implements independent HTTP/web requests
- Domain info sources (`sources/info/`) inherit from `BaseInfoSource`
- Tech detection sources (`sources/tech/`) split into stateless detectors and concurrent network probes
- Info sources return dicts (not lists) for structured field merging

### Utilities layer (`utils.py`)

- DNS & HTTP session management
- Domain validation & filtering
- Provider mapping & normalization
- Shared helper functions

### Reporting layer (`reporting/`)

- Exports scan results with `--output`
- Chooses the exporter from the file extension (`.json` or `.html`)
- Self-contained HTML reports with light and dark themes and an embedded logo

### Display layer (`display/`)

- Banner rendering
- Rich table formatting
- Progress indicators
- Semantic color theming

## Releasing

Releases are published by [`.github/workflows/release.yml`](.github/workflows/release.yml)
through PyPI trusted publishing, so no API token is stored anywhere.

1. Bump `__version__` in `domainspyder/_version.py`.
2. Move the `Unreleased` changelog entries under the new version and date.
3. Optional dry run: start the Release workflow manually ("Run workflow") to
   publish to TestPyPI.
4. Merge to `main`, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
   The workflow checks the tag matches the package version and publishes to PyPI.
