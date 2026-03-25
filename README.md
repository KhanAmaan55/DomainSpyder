# 🕷️ DomainSpyder

**DomainSpyder** is a fast and simple subdomain enumeration tool built in Python.
It discovers subdomains using passive sources and DNS brute force, with a clean CLI interface.

---

## 🚀 Features

* 🔍 Subdomain enumeration via crt.sh
* ⚡ DNS brute forcing (multithreaded)
* 🎨 Clean terminal output using Rich
* 💾 Save results to file
* 🧵 Configurable threads for faster scans

---

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/DomainSpyder.git
cd DomainSpyder

python3 -m venv venv
source venv/bin/activate

pip install .
```

---

## ▶️ Usage

```bash
domainspyder example.com
```

---

### ⚙️ Options

```bash
domainspyder example.com --threads 50
domainspyder example.com --save results.txt
domainspyder example.com --wordlist wordlists/default.txt
```

---

## 📁 Project Structure

```
domainspyder/
├── cli.py
├── core.py
├── utils.py
```

---

## ⚠️ Disclaimer

This tool is intended for educational and authorized security testing only.
Do not use it on systems without permission.

---

## 👨‍💻 Author

Amaan Khan (KhanAmaan55)
