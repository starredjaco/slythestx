# 🐍 Slythestx

<p align="center">
  <img src="assets\slythestx.png" width="250" alt="Slythestx Logo">
</p>

<p align="center">
  <strong>The Swiss Army Worm for Mobile & Web Security</strong><br>
  <i>A multi-tool framework for deep code analysis and dynamic vulnerability hunting.</i>
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
  <a href="https://www.buymeacoffee.com/stux" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="120"></a>
</p>

---

## ⚡ Overview

**Slythestx** is a versatile security toolkit designed for hackers and security researchers. It combines static analysis (SAST) with dynamic testing (DAST) into a single "Swiss Army Knife" interface, specifically optimized for mobile applications and modern web environments.

---

## 📌 Release & Versioning


### 🟢 Version 1.0.2_PUBLIC_ALPHA — Darkapple

- [x] **iOS Integration**
  - Added iOS device support via USB and SSH
  - Jailbreak device connectivity
  - Automatic device detection
  - Communication using libimobiledevice tools

- [x] **Application Enumeration**
  - List installed applications
  - Bundle ID, name and version detection
  - Fast filesystem-based enumeration for jailbroken devices
  - USB fallback using ideviceinstaller

- [x] **App Container Discovery**
  - Bundle container identification
  - Data container mapping
  - Automatic sandbox path resolution
  - Directory listing (Documents, Library, Preferences, Caches)

- [x] **IPA Extraction**
  - Extract installed apps directly from device
  - Automatic Payload structure creation
  - Fast download using SFTP
  - IPA management endpoints (list, delete, clear)

- [x] **Rootful / Rootless Support**
  - Automatic PlistBuddy path detection
  - Compatibility with modern jailbreak environments

- [x] **Performance Improvements**
  - Faster SSH enumeration
  - Reduced device calls
  - Optimized plist parsing

- [ ] **implement security tools**  
  - Pendending add total funcionaliti with security tools, keychain-dumper, cycript and others.
  - Pendending syslog with ssh funcionality.

- [x] **Bug Squashing**

### 🟢 Version 1.0.1 — ShadowLog

- [x] **Advanced Logcat Integration:** Real-time system log monitoring with custom filtering for surgical debugging.
- [x] **ReactAnalyzer Optimization:** Significant performance boost in static analysis for React-based, reducing false positives.
- [x] **Bug Squashing:** Resolved critical issues.


### 🟢 Version 1.0.0 — *The Awakening*
*Core Engine & Mobile Foundations*

- [x] **Multi-Platform Tech ID:** Automated technology stack identification for both iOS and Android environments.
- [x] **Smart Tool Suggester:** Dynamic recommendation of specialized external security tools based on the detected tech stack.
- [x] **Rule-Based SAST:** Static Analysis Security Testing engine powered by customizable JSON rule-sets for deep code auditing.
- [x] **Regex Security Shield:** Heuristic identification of active security measures (Root Detection, SSL Pinning, Debug Checks) using advanced regex patterns.
- [x] **ADB Power Suite:** Full-scale Android Debug Bridge integration featuring:
  - **Package Extraction:** Fast identification and pulling of installed application packages.
  - **Internal Filesystem Explorer:** Direct access, visualization, and download of internal app data (`/data/data/`).

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/stuxctf/slythestx/

# Navigate to the project
cd slythestx

# build docker windows 
docker-compose.exe  -f docker-compose.yml -f docker-compose.windows.yml --build

# build docker linux

docker-compose.exe  -f docker-compose.yml -f docker-compose.linux.yml --build

# Launch the engine 
docker-compose up -d

# Engine up
http://localhost:3000 
```

---

## ⚠️ Disclaimer

**Slythestx** is developed strictly for **educational and ethical security testing purposes**. Using this tool against targets without prior written consent is illegal. The developers assume no liability for misuse, legal consequences, or damages resulting from the use of this software.

---


