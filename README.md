# 🕷️ DomainSpyder

**DomainSpyder** is a modular **domain reconnaissance and intelligence framework** built in Python.
It is designed to perform fast, scalable, and extensible domain analysis — starting with subdomain enumeration and evolving into a full recon toolkit.

---

## 🚀 Overview

DomainSpyder is no longer just a subdomain finder.

It is being built as a **multi-command CLI framework** that helps you:

* Discover assets (subdomains)
* Analyze live services
* Gather intelligence about a domain

---

## ✨ Features

### 🔍 Subdomain Intelligence

* Passive enumeration:

  * crt.sh
  * AlienVault OTX
  * HackerTarget
  * Wayback Machine
  * RapidDNS
* Active enumeration:

  * DNS brute force (multithreaded)
  * Configurable brute force modes for speed vs stealth
* Deduplication & filtering

---

### 🌐 Alive Detection (HTTP Probing)

* Detect live subdomains
* HTTP/HTTPS fallback
* Status code detection
* Server header extraction
* Page title extraction
* Colored output (Rich UI)

---

### ⚡ Performance Optimizations

* Parallel passive + active enumeration
* ThreadPool-based concurrency
* Resolver pool with DNS rotation
* Connection reuse for HTTP requests
* Lightweight throttling for stability and reduced rate limiting

---

### 🖥️ CLI Experience

* Multi-command interface (extensible)
* Rich tables & progress indicators
* Debug mode for detailed logging
* Flexible scan tuning via command options

---

## 📦 Installation

### 🔧 From Source

```bash
git clone https://github.com/YOUR_USERNAME/DomainSpyder.git
cd DomainSpyder

python3 -m venv venv
source venv/bin/activate

pip install -e .
```

> Using `-e` (editable mode) is recommended during development.

---

## ▶️ Usage

### 🟢 Subdomain Enumeration

```bash
domainspyder subdomains example.com
```

---

### ⚡ Alive Subdomain Detection

```bash
domainspyder subdomains example.com --alive
```

---

### 🚀 Brute Force Modes

Control the speed and aggressiveness of DNS brute forcing:

```bash
domainspyder subdomains example.com --brutemode fast
domainspyder subdomains example.com --brutemode balanced
domainspyder subdomains example.com --brutemode stealth
```

**Modes:**

| Mode       | Description                                                       |
| ---------- | ----------------------------------------------------------------- |
| `fast`     | Maximum speed, minimal delay (best for quick scans)               |
| `balanced` | Recommended balance between speed and reliability                 |
| `stealth`  | Slower, reduced request rate to avoid detection and rate limiting |

---

### ⚙️ Common Options

```bash
domainspyder subdomains example.com --threads 100
domainspyder subdomains example.com --wordlist wordlists/default.txt
domainspyder subdomains example.com --save results.txt
```

---

### 🐞 Debug Mode (Global)

```bash
domainspyder --debug subdomains example.com
```

---

## 📊 Example Output

```
api.example.com     200   nginx        api service
dev.example.com     403   cloudflare   -
```

---

## 🏗️ Project Structure

```
domainspyder/
├── cli.py                # CLI entry point (multi-command)
├── core/
│   └── subdomain.py     # Subdomain + alive logic
├── utils/
│   └── dns.py           # DNS + data sources
```

---

## 🧠 Architecture

DomainSpyder follows a modular design:

* **CLI Layer** → Command routing & user interface
* **Core Layer** → Feature orchestration
* **Utils Layer** → Data sources & low-level operations

This makes it easy to:

* Add new modules (DNS, ports, HTTP, etc.)
* Extend existing functionality
* Maintain clean separation of concerns

---

## 🔮 Roadmap

### 🟢 Short Term

* Improved HTTP probing (response time, redirects)
* JSON / CSV output support

### 🟡 Mid Term

* DNS record enumeration (A, MX, TXT, NS)
* Port scanning (lightweight)
* Technology detection

### 🔴 Long Term

* Full scan command (`domainspyder scan`)
* Subdomain permutation engine
* Continuous monitoring
* Docker support
* PyPI release

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.

Do not use DomainSpyder against systems without explicit permission.

---

## 👨‍💻 Author

**Amaan Khan**
GitHub: [https://github.com/KhanAmaan55](https://github.com/KhanAmaan55)

---

## ⭐ Contributing

Contributions, issues, and feature requests are welcome.

If you’d like to contribute:

1. Fork the repository
2. Create a new branch
3. Submit a pull request

---