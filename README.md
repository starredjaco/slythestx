# 🐍 Slythestx

<p align="center">
  <img src="assets/slythestx.png" width="250" alt="Slythestx Logo">
</p>

<p align="center">
  <strong>The Swiss Army Worm for Mobile Security</strong><br>
  <i>A unified framework for static code analysis and dynamic vulnerability hunting on iOS and Android.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Slythestx-v1.0.2-brightgreen?style=for-the-badge&logo=kali-linux&logoColor=white" alt="Version">
  <img src="https://img.shields.io/badge/Security-SAST%20%7C%20DAST-red?style=for-the-badge&logo=target" alt="Security">
</p>

<p align="center">
  <a href="https://www.docker.com/" target="_blank">
    <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
  </a>
  <a href="https://nodejs.org/" target="_blank">
    <img src="https://img.shields.io/badge/Node.js-v18+-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node">
  </a>
  <a href="https://www.python.org/" target="_blank">
    <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  </a>
  <a href="https://vitejs.dev/" target="_blank">
    <img src="https://img.shields.io/badge/Vite-Built-646CFF?style=flat-square&logo=vite&logoColor=white" alt="Vite">
  </a>
  <img src="https://img.shields.io/badge/Platform-Multi--OS-lightgrey?style=flat-square&logo=linux" alt="Platform">
  <a href="https://opensource.org/licenses/MIT" target="_blank">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/⚠%20For-Educational%20Purposes%20Only-red" alt="For Educational Purposes Only">
</p>

<p align="center">
  <a href="https://www.buymeacoffee.com/stux" target="_blank">
    <img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="120">
  </a>
</p>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Analyzer Suite](#-analyzer-suite)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Release Notes](#-release--versioning)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Disclaimer](#️-disclaimer)
- [License](#-license)

---

## ⚡ Overview

**Slythestx** is a mobile-focused security toolkit that brings static analysis (SAST) and dynamic analysis (DAST) together under a single interface. It is built for security researchers and mobile pentesters who need to quickly fingerprint a target's technology stack, audit its source for known-bad patterns, and interact with a live device — all without juggling a dozen separate tools.

The engine ships as a containerized web application, exposing a browser-based dashboard (`http://localhost:3000`) backed by a Node.js/TypeScript analysis core.

---

## ✨ Key Features

| Category | Capability |
|---|---|
| **Technology Detection** | Automatic identification of the underlying framework — React Native, Flutter, Xamarin, .NET MAUI, Cordova, or native iOS/Android |
| **Static Analysis (SAST)** | Rule-based scanning engine driven by customizable JSON rule-sets for deep code auditing |
| **Security Posture Detection** | Heuristic regex engine that flags active protections such as root/jailbreak detection, SSL pinning, and debug/anti-tamper checks |
| **Secret Scanning** | Detection of hardcoded credentials, API keys, and other sensitive strings embedded in app code |
| **Permission & Manifest Auditing** | Parsing of Android manifests and app permissions for over-privileged or risky declarations |
| **Android Toolkit (ADB)** | Full ADB integration for package extraction and direct exploration of `/data/data/` app storage |
| **iOS Toolkit** | USB/SSH connectivity to jailbroken devices via `libimobiledevice`, with automatic device detection |
| **App Enumeration** | Cross-platform listing of installed apps (bundle ID, package name, version) |
| **Container & Sandbox Mapping** | Automatic resolution of app sandbox paths — Documents, Library, Preferences, Caches |
| **IPA Extraction** | On-device IPA extraction with automatic `Payload` structure rebuilding and fast SFTP download |
| **Live Log Monitoring** | Real-time Logcat streaming with custom filters for surgical debugging |
| **Smart Tool Suggestions** | Context-aware recommendations of external security tools based on the detected stack |

---

## 🏗️ Architecture

Slythestx is organized around two core pillars: **analyzers** (static, tech-stack aware inspection modules) and **device drivers** (dynamic interaction with connected iOS/Android hardware).

---

## 🧩 Analyzer Suite

Each analyzer plugs into the core engine and runs when its corresponding technology is detected, keeping scans fast and noise-free.

| Analyzer | Target Stack | Purpose |
|---|---|---|
| `technologyDetector` | All | Fingerprints the app's underlying framework |
| `appInfoAnalyzer` | All | Extracts general app metadata |
| `manifestAnalyzer` | Android | Parses `AndroidManifest.xml` |
| `permissionAnalyzer` | Android / iOS | Audits declared permissions |
| `securityMeasuresAnalyzer` | All | Detects root/jailbreak checks, SSL pinning, anti-debug logic |
| `secretScanner` | All | Scans source and binaries for hardcoded secrets |
| `nativeAnalyzer` | Native iOS/Android | Analyzes native code paths |
| `reactAnalyzer` | React Native | React Native-specific static analysis |
| `flutterAnalyzer` | Flutter | Flutter-specific static analysis |
| `xamarinAnalyzer` | Xamarin | Xamarin-specific static analysis |
| `dotnetMauiAnalyzer` | .NET MAUI | .NET MAUI-specific static analysis |
| `cordovaAnalyzer` | Cordova/PhoneGap | Cordova-specific static analysis |

---

## 🚀 Quick Start

### Prerequisites

- [Docker](https://www.docker.com/) & Docker Compose
- Node.js v18+
- Python 3.10+
- (iOS analysis) A jailbroken iOS device with SSH enabled, or USB connectivity via `libimobiledevice`
- (Android analysis) ADB enabled on the target device

### Installation

```bash
# Clone the repository
git clone https://github.com/stuxctf/slythestx/
cd slythestx

# --- Windows ---
docker-compose.exe -f docker-compose.yml -f docker-compose.windows.yml build

# --- Linux ---
docker-compose -f docker-compose.yml -f docker-compose.linux.yml build

# Launch the engine
docker-compose up -d
```

### Access the Dashboard

Once the containers are running, open your browser at:

```
http://localhost:3000
```

---

## 🖥️ Usage

1. **Connect a device** — plug in an Android device with USB/WiFi debugging enabled, or an iOS device (USB or SSH for jailbroken devices).
2. **Enumerate apps** — Slythestx lists installed applications with bundle/package ID, name, and version.
3. **Extract & analyze** — pull the APK/IPA, or explore the app's sandbox directly, and let the technology detector route the package to the right analyzers.
4. **Review findings** — inspect detected security measures, flagged secrets, permission issues, and SAST rule matches from the dashboard.
5. **Go dynamic** — tail live device logs, browse the app's data container, or invoke suggested external tools for deeper manual testing.

---

## 📌 Release & Versioning

### 🟢 v1.0.2_PUBLIC_ALPHA — *Darkapple*

- **iOS Integration** — USB & SSH support for jailbroken devices, automatic device detection, communication via `libimobiledevice`
- **Application Enumeration** — bundle ID/name/version detection, fast filesystem-based enumeration, USB fallback via `ideviceinstaller`
- **App Container Discovery** — bundle/data container mapping, automatic sandbox path resolution, directory listing (Documents, Library, Preferences, Caches)
- **IPA Extraction** — direct on-device extraction, automatic `Payload` structure creation, fast SFTP download, IPA management endpoints (list/delete/clear)
- **Rootful / Rootless Support** — automatic `PlistBuddy` path detection, compatible with modern jailbreak environments
- **Performance Improvements** — faster SSH enumeration, fewer device calls, optimized plist parsing
- Bug fixes and stability improvements

> 🔜 **In Progress:** Keychain dumping, Cycript integration, and additional security tooling; SSH-based syslog streaming.

### 🟢 v1.0.1 — *ShadowLog*

- **Advanced Logcat Integration** — real-time system log monitoring with custom filtering
- **ReactAnalyzer Optimization** — significant performance boost for React Native static analysis, reduced false positives
- Bug fixes and stability improvements

### 🟢 v1.0.0 — *The Awakening*
*Core Engine & Mobile Foundations*

- **Multi-Platform Tech ID** — automated technology stack identification for iOS and Android
- **Smart Tool Suggester** — dynamic recommendation of external security tools based on detected stack
- **Rule-Based SAST** — static analysis engine powered by customizable JSON rule-sets
- **Regex Security Shield** — heuristic detection of root detection, SSL pinning, and debug checks
- **ADB Power Suite** — package extraction and internal filesystem exploration (`/data/data/`)

---

## 🗺️ Roadmap

- [ ] Keychain-dumper, Cycript, and additional security tool integrations
- [ ] SSH-based syslog streaming for iOS
- [ ] Expanded rule-sets for emerging cross-platform frameworks
- [ ] CI/CD-friendly CLI mode for automated pipelines

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or pull request on the [GitHub repository](https://github.com/stuxctf/slythestx/).

---

## ⚠️ Disclaimer

**Slythestx** is developed strictly for **educational and ethical security testing purposes**. Using this tool against targets without prior written authorization is illegal. The developers assume no liability for misuse, legal consequences, or damages resulting from the use of this software.

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT).

---

<p align="center">
  Made with 🐍 by <a href="https://github.com/stuxctf">stuxctf</a> — support the project on <a href="https://www.buymeacoffee.com/stux">Buy Me a Coffee</a>
</p>
