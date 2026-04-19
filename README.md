<div align="center">

# APKILIS

### Professional Forensic Analysis Toolkit for Android Applications

*100% Offline · Single-Purchase · Forensic-Grade Reports*

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/DevlsPixls/apkilis)
[![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-informational.svg)](#requirements)
[![License](https://img.shields.io/badge/license-Commercial-red.svg)](./LICENSE.txt)
[![Status](https://img.shields.io/badge/status-active-success.svg)](#)

[**Features**](#-features) · [**Modules**](#-analysis-modules) · [**Install**](#-installation) · [**Usage**](#-usage) · [**FAQ**](#-faq)

---

</div>

## 🔍 What is APKILIS?

**APKILIS** is a professional-grade static analysis framework for Android applications, purpose-built for security researchers, bug bounty hunters, forensic analysts, and mobile app auditors. It processes `APK`, `APKS`, `APKM`, and `XAPK` files entirely offline, producing comprehensive reports suitable for formal security assessments, vulnerability disclosures, and legal forensic proceedings.

Unlike cloud-based alternatives, APKILIS **never uploads your APK samples anywhere** — making it the right choice for malware research, NDA-bound corporate audits, and analysis of confidential or proprietary applications.

> Built by an independent security researcher who actively uses it on bug bounty programs (HackerOne, Bugcrowd, Intigriti) and professional disclosures. **It's a tool made by someone who needs it to work.**

---

## ✨ Features

- **40+ Analysis Modules** — from manifest parsing to MITRE ATT&CK Mobile mapping
- **100% Offline Operation** — no APKs leave your machine, ever
- **Multi-Format Support** — native handling of APK, APKS, APKM, XAPK bundles
- **Forensic Chain of Custody** — MD5, SHA-1, SHA-256, fuzzy hashing (ssdeep, TLSH)
- **MITRE ATT&CK Mobile Mapping** — automated technique detection across tactics
- **OWASP Mobile Top 10 Assessment** — scored evaluation with severity breakdown
- **C2 & Backdoor Detection** — heuristic identification of command & control infrastructure
- **Banking & High-Value App Analysis** — specialized checks for fintech security
- **Anti-Cheat Detection** — identify game protection mechanisms (Denuvo, BattlEye, EAC patterns)
- **Dynamic Kit Generation** — auto-generated Frida, Drozer, ADB, and Objection scripts
- **Rich Cyberpunk TUI** — progress tracking, module timing, and color-coded risk display
- **Multi-Format Reports** — Markdown, JSON, and HTML outputs for all audiences

---

## 🧩 Analysis Modules

APKILIS orchestrates **40+ specialized analyzers** into a single forensic pipeline:

<table>
<tr>
<td valign="top" width="33%">

**Static Analysis**
- Manifest parser (permissions, components, flags)
- Certificate chain (X.509 deep analysis)
- Smali code patterns
- Dex bytecode (Androguard)
- Native libraries (LIEF)
- Enjarify DEX→JAR conversion
- **Jadx Java decompilation**
- String deobfuscation

</td>
<td valign="top" width="33%">

**Threat Detection**
- YARA rule engine
- Quark-Engine heuristics
- Androwarn behaviors
- APKiD packer/obfuscator
- Backdoor & C2 detection
- Endpoint classifier (TOR, VPN, surveillance)
- Data exfiltration correlator
- MITRE ATT&CK mapping

</td>
<td valign="top" width="33%">

**Specialized**
- OWASP Mobile Top 10
- Network security config
- Tracker & SDK detection
- Hardcoded secrets extraction
- Intent/IPC attack surface
- Accessibility/Overlay abuse
- Banking security checks
- Game anti-cheat analysis
- Forensic DB extraction
- Signature scheme verification

</td>
</tr>
</table>

See [`docs/modules.md`](./docs/modules.md) for the complete module reference.

---

## 🆚 Why APKILIS?

| Feature | APKILIS | MobSF | Cloud Scanners |
|---|:---:|:---:|:---:|
| **100% Offline** | ✅ | ✅ | ❌ |
| **Single-file CLI** | ✅ | ❌ (server/Docker) | ❌ |
| **MITRE ATT&CK Mobile mapping** | ✅ | ⚠️ Partial | Varies |
| **Forensic-grade reports** | ✅ | ⚠️ | ❌ |
| **Dynamic kit generator** | ✅ | ⚠️ | ❌ |
| **Anti-cheat/Banking specialized** | ✅ | ❌ | ❌ |
| **Setup time** | ~5 min | ~30 min | Account signup |
| **Per-APK processing cost** | $0 | $0 | Subscription |
| **Suitable for NDA-bound APKs** | ✅ | ✅ | ❌ |

> APKILIS is **not a MobSF killer** — MobSF is an excellent open-source tool. APKILIS is optimized for a different workflow: fast single-file CLI, peri­tage-ready output, and specialized detection categories that general-purpose scanners don't cover.

---

## 📦 Installation

### System Requirements

- **OS:** Linux (Parrot OS, Kali, Ubuntu 20.04+, Debian 11+)
- **Python:** 3.10 or higher
- **RAM:** 4 GB minimum, 8 GB recommended
- **Disk:** 2 GB free for temporary decompilation output

> Windows users: use **WSL2 with Ubuntu 22.04+**. Native Windows is not supported due to POSIX-specific resource isolation (`RLIMIT_AS`).

### Step 1 — Install external tools

```bash
# Core (required)
sudo apt update
sudo apt install -y apktool default-jre-headless python3-pip unzip

# Java toolchain (for certificate analysis)
sudo apt install -y openjdk-17-jdk-headless

# Jadx decompiler (strongly recommended)
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip
sudo mkdir -p /opt/jadx && sudo unzip jadx-1.5.0.zip -d /opt/jadx
sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx

# APKiD packer detector (optional but recommended)
pipx install apkid
```

### Step 2 — Install Python dependencies

```bash
pip install -r requirements.txt

# For full functionality (recommended):
pip install -r requirements-optional.txt
```

### Step 3 — Verify your environment

```bash
python3 apkilis.py
```

On startup, APKILIS runs a **pre-flight check** showing which tools/libraries are detected. Missing optional components degrade gracefully — only `apktool` is strictly required.

---

## 🚀 Usage

### Interactive Mode

```bash
python3 apkilis.py
```

You'll see the main menu:

```
╭──────────────────────────────────────────────────────╮
│  1  Analyze single file (.apk, .apkm, .xapk, .apks)  │
│  2  Batch analysis (entire directory)                │
│  3  Generate dynamic analysis kit (Frida/ADB/Drozer) │
│  0  Exit                                             │
╰──────────────────────────────────────────────────────╯
```

### Output Structure

Each analysis produces a timestamped directory on your Desktop:

```
APKILIS_<app_name>_<timestamp>/
├── decompiled/              # apktool output
├── jadx_output/             # jadx Java sources
├── extracted_bundle/        # (for .apks/.apkm/.xapk)
├── jar_output/              # Enjarify conversion
├── dynamic_kit/             # Frida scripts, ADB cmds, Drozer modules
├── report.md                # Markdown report
├── report.json              # Machine-readable JSON
└── report.html              # Browser-friendly HTML
```

### Sample Reports

Browse full example reports at [`examples/sample_reports/`](./examples/sample_reports/) — these are generated from publicly-available F-Droid apps and are safe to share.

---
</div>

**What you get:**
- ✅ Full source code (single-file Python, readable and modifiable)
- ✅ Lifetime license for the acquired major version
- ✅ 12 months of minor updates and patches via email
- ✅ Installation support during your first 30 days
- ✅ Commercial use permitted (bug bounty, consulting, peritage)

**What's restricted** *(see [LICENSE.txt](./LICENSE.txt)):*
- ❌ Redistribution or resale of the source code
- ❌ Incorporation into other commercial products for resale
- ❌ Public republishing of the codebase

---

## 📋 Changelog

See [CHANGELOG.md](./CHANGELOG.md) for the full version history.

**v2.0** *(current)* — Jadx integration, backdoor/C2 detection, banking security module, MITRE ATT&CK mapping, OWASP Mobile Top 10 automated assessment, cyberpunk dashboard.

---

## ❓ FAQ

<details>
<summary><b>Is APKILIS legal to use?</b></summary>

Yes, as long as you analyze APKs you have the right to analyze: your own apps, client apps with written authorization, apps in bug bounty programs that permit static analysis, or malware samples obtained through legitimate research channels. APKILIS is a static analyzer — you're responsible for legal authorization of your targets.
</details>

<details>
<summary><b>Does it work on Windows?</b></summary>

APKILIS requires POSIX features (signal-based timeouts, `RLIMIT_AS` for subprocess isolation). Use **WSL2 with Ubuntu 22.04+** on Windows. Native Windows support is not planned.
</details>

<details>
<summary><b>Will my license expire?</b></summary>

No. Your license is **perpetual** for the version you purchase. The 12-month update window is for free minor updates — after that, the software you own keeps working forever. Major version upgrades (v3.0) may be offered with a discount to existing customers.
</details>

<details>
<summary><b>Can I use it for bug bounty?</b></summary>

Absolutely — that's one of the primary use cases. APKILIS is actively used on HackerOne, Bugcrowd, and Intigriti programs. Commercial use is explicitly permitted.
</details>

<details>
<summary><b>What if I need a refund?</b></summary>

14-day money-back guarantee, no questions asked. Just email support with your order ID and certify deletion of your copies.
</details>

<details>
<summary><b>Does APKILIS replace MobSF/AppKnox/NowSecure?</b></summary>

It's a different tool optimized for a different workflow. MobSF is excellent for team use via web interface. AppKnox/NowSecure are enterprise SaaS. APKILIS fills the gap for individual researchers and small firms who want fast, offline, CLI-first analysis with forensic-grade output — without subscriptions or cloud uploads.
</details>

<details>
<summary><b>Will you add Windows native support / GUI / plugin system?</b></summary>

Possibly in a future major version. The current focus is on improving detection accuracy and adding more specialized modules. Feature requests via email are welcome and influence the roadmap.
</details>

<div align="center">

**APKILIS** © 2026 DevlsPixls · 

*If APKILIS helps you land a bounty, I'd love to hear about it.*

</div>
