# Aegis Sentinel — AI Universal Security Mesh

> *"One security layer to rule all devices."*

Aegis Sentinel is an **AI‑driven anti‑malware and surveillance spider** that runs on any
device: Android (Termux), Linux, Windows, macOS, IoT, and cloud servers.

It uses **billions of threat signatures** (via Bloom filter + SQLite), **real‑time
heuristics**, and a **web crawler** to find and neutralise malicious files before they
infect your device or platform.

---

## 🔥 Features

- **Cross‑platform** – pure Python, runs in Termux, desktops, servers
- **Billions of security lines** – probabilistic Bloom filter with exact SQLite fallback
- **AI file scanner** – entropy analysis, suspicious pattern detection, hash lookup
- **Spider/Crawler** – automatically hunts websites, downloads files, scans them
- **Explainable verdicts** – every decision is logged and human‑readable (legal‑ready)
- **Self‑defending core** – memory‑mapped structures survive low‑RAM environments

---

## ⚙️ Quick Start (Termux / Linux)

```bash
pkg update && pkg upgrade
pkg install python sqlite
pip install -r requirements.txt

# Load signatures (get a hash list from VirusShare or similar)
python aegis_billion.py --load example_signatures.txt

# Scan a local file
python aegis_billion.py --file suspicious.apk

# Crawl a website and scan every downloadable file
python aegis_billion.py --crawl http://testphp.vulnweb.com
