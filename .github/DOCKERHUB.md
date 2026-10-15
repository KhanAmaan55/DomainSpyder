<p align="center">
  <img src="https://raw.githubusercontent.com/KhanAmaan55/DomainSpyder/main/assets/img/logo_readme.png" alt="DomainSpyder" width="500">
</p>

**Domain intelligence from one CLI**: subdomain enumeration, DNS analysis, port
scanning, technology detection and WHOIS, with JSON and HTML reports.

This is the official image of [DomainSpyder](https://github.com/KhanAmaan55/DomainSpyder),
also available on [PyPI](https://pypi.org/project/domainspyder/). It needs no
local Python install.

> ⚠️ **Only scan domains and hosts you own or are authorised to test.**
> See the [disclaimer](https://github.com/KhanAmaan55/DomainSpyder#disclaimer).

## Quick start

```bash
docker run --rm -it khanamaan/domainspyder dns example.com
docker run --rm -it khanamaan/domainspyder subdomains example.com --alive
docker run --rm -it khanamaan/domainspyder info example.com
```

Run it with no arguments to see the help, or add `--help` after any command.

## Commands

| Command      | What it does                                                                |
| ------------ | --------------------------------------------------------------------------- |
| `subdomains` | Passive enumeration from 5 public sources plus multithreaded DNS brute force |
| `dns`        | A, AAAA, MX, NS, TXT and CNAME records, SPF/DMARC analysis, a 0-10 security score |
| `ports`      | Concurrent TCP connect scan with service identification and banner grabbing |
| `tech`       | Web technology fingerprinting with confidence scores and versions           |
| `info`       | WHOIS, RDAP, SSL certificate and DNS SOA data merged into one view         |

Full options and example output are in the
[README](https://github.com/KhanAmaan55/DomainSpyder#usage).

## Saving reports and using wordlists

The container's working directory is `/data`. Mount a host directory there,
and relative paths for `--output`, `--save` and `--wordlist` resolve inside it:

```bash
# Write an HTML report to the current directory
docker run --rm -it -v "$PWD:/data" khanamaan/domainspyder info example.com --output report.html

# Use a wordlist from the current directory
docker run --rm -it -v "$PWD:/data" khanamaan/domainspyder subdomains example.com --brute-only --wordlist words.txt
```

On Linux, add `--user "$(id -u):$(id -g)"` so the container can write to the
mounted directory and the files it creates are owned by you.

To use it like a locally installed command, add an alias to your shell profile:

```bash
alias domainspyder='docker run --rm -it -v "$PWD:/data" khanamaan/domainspyder'
domainspyder dns example.com
```

## Scanning your own machine

Inside the container, `localhost` is the container itself. To scan services on
the host, target `host.docker.internal` on Docker Desktop, or add
`--network host` on Linux.

## Tags

| Tag      | Points to                                               |
| -------- | ------------------------------------------------------- |
| `latest` | The newest release                                      |
| `X.Y.Z`  | An exact release, e.g. `1.0.1`; never changes           |
| `X.Y`    | The newest patch release of that minor version, e.g. `1.0` |
| `X`      | The newest release of that major version, e.g. `1`      |

The same image and tags are mirrored to GitHub Container Registry as
`ghcr.io/khanamaan55/domainspyder`.

Pin an exact version for repeatable results. Release notes are in the
[changelog](https://github.com/KhanAmaan55/DomainSpyder/blob/main/CHANGELOG.md).

## Image details

- **Platforms**: `linux/amd64` and `linux/arm64`
- **Base**: `python:3.13-slim`
- **User**: runs as an unprivileged user (UID 1000), not root
- **Entrypoint**: `domainspyder`, so arguments go straight to the CLI
- **Supply chain**: releases are built from the tagged source by
  [GitHub Actions](https://github.com/KhanAmaan55/DomainSpyder/blob/main/.github/workflows/docker.yml),
  with provenance and SBOM attestations
- **Source**: [Dockerfile](https://github.com/KhanAmaan55/DomainSpyder/blob/main/Dockerfile)

## Support

Report bugs and request features on
[GitHub Issues](https://github.com/KhanAmaan55/DomainSpyder/issues).

Released under the [MIT License](https://github.com/KhanAmaan55/DomainSpyder/blob/main/LICENCE).
Created by [Amaan Khan](https://github.com/KhanAmaan55).
