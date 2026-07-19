# 🛡️ Honeypot Threat Monitoring Platform

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

A lightweight, low-interaction HTTP honeypot built in Python, featuring a real-time web-based Command Center dashboard, CLI log analysis, and automated CSV reporting. Designed for educational purposes and threat intelligence gathering.

---

## ⚠️ DISCLAIMER
> **This project is for EDUCATIONAL and DEFENSIVE research purposes only.** 
> - Do not deploy this on production systems or networks you do not own.
> - If deploying to the public internet, **always** use an isolated Virtual Machine (VM) or Docker container to prevent host compromise.
> - The author is not responsible for any misuse or damage caused by this software.

---

## ✨ Features

- **🎣 Deceptive Trap**: Mimics a vulnerable "NetGear Pro Router" admin login page to attract automated scanners and brute-force attempts.
- **📝 Intelligent Logging**: Captures IP addresses, User-Agents, request paths, and submitted payloads (e.g., SQL injection, credential stuffing).
- **📊 Live Admin Dashboard**: A beautiful, dark-themed Flask web UI with real-time Chart.js graphics (Attack Timeline, Top IPs, Threat Severity).
- **📈 CLI Analyzer**: A built-in script to parse logs and export clean, structured `.csv` reports for further analysis in Excel or SIEM tools.

---
