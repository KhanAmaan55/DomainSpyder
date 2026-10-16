# Changelog

All notable changes to DomainSpyder are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-10-16

Adds Docker and Homebrew as installation methods, and fixes two CLI bugs.

### Added

- **Docker image**, published to Docker Hub as `khanamaan/domainspyder` and to
  GitHub Container Registry as `ghcr.io/khanamaan55/domainspyder`.
  - Built for `linux/amd64` and `linux/arm64`.
  - Runs as an unprivileged user, with `/data` as the working directory for
    mounted reports and wordlists.
  - Tagged `X.Y.Z`, `X.Y`, `X` and `latest`, and published automatically for
    every release, with provenance and SBOM attestations.
- **Homebrew formula** for macOS and Linux, installed with
  `brew install khanamaan55/tap/domainspyder` from the
  [`khanamaan55/tap`](https://github.com/KhanAmaan55/homebrew-tap) tap, with
  no separate Python install required.

### Fixed

- **`dns`**: a null MX record (RFC 7505), which marks a domain that accepts no
  mail, was shown as an empty value in the terminal and in reports. It is now
  shown as `.`, with a "Null MX" insight explaining it.
- **`--output`**: an unsupported report format, such as `report.pdf`, is now
  rejected before the scan starts, with exit code `2`. Previously the scan ran
  to completion and only the export failed.

## [1.0.1] - 2026-09-25

Documentation-only release; no code changes.

### Added

- `CONTRIBUTING.md` with development setup, checks, project structure and
  architecture.

### Changed

- Rewrote the README, which is also the PyPI project page, with a quick start,
  installation and upgrade steps, per-command usage and example output.

## [1.0.0] - 2026-09-25

First public release on PyPI.

### Added

- **`subdomains`**: passive enumeration from crt.sh, AlienVault OTX,
  HackerTarget, RapidDNS and the Wayback Machine, combined with multithreaded
  DNS brute force.
  - `--brute-only` with `fast`, `balanced` and `stealth` modes, and custom
    wordlists.
  - Wildcard DNS detection, so wildcard answers are not reported as real
    subdomains.
  - Alive detection with status code, server header and page title.
- **`dns`**: parallel A, AAAA, MX, NS, TXT and CNAME lookups over a rotating
  resolver pool.
  - SPF and DMARC analysis, email and DNS provider detection.
  - A 0-10 security score with itemised issues.
  - `--raw-only` to show records without analysis.
- **`ports`**: concurrent TCP connect scanning with the default common ports,
  custom port lists, or `--top-100`, `--top-1000` and `--full` presets.
  - Service identification, safe banner grabbing and reverse DNS.
  - Exposure insights for high-risk and database services.
- **`tech`**: technology detection from HTTP headers, cookies, HTML, scripts,
  favicon hashes, `robots.txt`, `sitemap.xml`, DNS TXT hints and the WordPress
  REST API.
  - Results are categorised, with confidence levels and versions where they
    can be determined.
- **`info`**: WHOIS, RDAP, SSL certificate and DNS SOA lookups run
  concurrently and merged by priority.
  - Domain age, expiry alerts, privacy detection and plain-English EPP status
    codes.
- **Reports**: `--output` exports any scan to JSON or a self-contained HTML
  report, with `--html-light` and `--html-dark` themes.
- **CLI**:
  - Targets are normalised, so URLs, trailing dots and ports are accepted.
  - Documented exit codes (`0`, `1`, `2`, `130`).
  - A global `--debug` flag.
- Support for Python 3.9 to 3.14.

[Unreleased]: https://github.com/KhanAmaan55/DomainSpyder/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/KhanAmaan55/DomainSpyder/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/KhanAmaan55/DomainSpyder/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/KhanAmaan55/DomainSpyder/releases/tag/v1.0.0
