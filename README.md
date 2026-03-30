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
  * Configurable brute force modes (speed vs stealth)
  * Optional brute-only mode
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
* Thread-local HTTP session reuse
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

### 🟢 Subdomain Enumeration (Default)

```bash
domainspyder subdomains example.com
```

* Runs **passive + brute force**
* Optimized for speed (fast mode internally)

---

### ⚡ Alive Subdomain Detection

```bash
domainspyder subdomains example.com --alive
```

* Filters only live subdomains
* Includes HTTP metadata (status, title, server)

---

### 🚀 Brute Force Only Mode

Run only DNS brute force with full control:

```bash
domainspyder subdomains example.com --brute-only
```

---

### ⚙️ Brute Force Modes (with `--brute-only`)

```bash
domainspyder subdomains example.com --brute-only --brutemode fast
domainspyder subdomains example.com --brute-only --brutemode balanced
domainspyder subdomains example.com --brute-only --brutemode stealth
```

> ⚠️ `--brutemode` is only applied when using `--brute-only`

---

## 🧠 Brute Force Modes Explained

DomainSpyder provides **execution profiles** that control:

* Request delay
* Thread count
* Scan aggressiveness

| Mode       | Delay  | Threads | Description                          |
| ---------- | ------ | ------- | ------------------------------------ |
| `fast`     | 0.001s | 80      | Maximum speed, aggressive scanning   |
| `balanced` | 0.005s | 50      | Recommended balance                  |
| `stealth`  | 0.01s  | 20      | Slow, avoids detection & rate limits |

---

## 📊 When to Use Each Mode

### ⚡ `fast` mode

Use when:

* Wordlist is **small (< 5,000 entries)**
* You need **quick results**
* Target is **not sensitive to rate limiting**

**Example:**

```bash
domainspyder subdomains example.com --brute-only --brutemode fast
```

---

### ⚖️ `balanced` mode (Recommended)

Use when:

* Wordlist is **medium (5k – 50k entries)**
* You want **good accuracy + speed**
* General recon / bug bounty workflows

**Example:**

```bash
domainspyder subdomains example.com --brute-only --brutemode balanced
```

---

### 🕵️ `stealth` mode

Use when:

* Wordlist is **large (50k+ entries)**
* Target has **rate limiting / WAF**
* You want **maximum reliability (fewer missed subdomains)**

**Example:**

```bash
domainspyder subdomains example.com --brute-only --brutemode stealth
```

---

## ⚙️ Common Options

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