# 🛡️ Aegis Network & Web Intelligence Suite (App py. Tools by Faza)

**Aegis** is an advanced Python-based security auditing tool designed for automated reconnaissance and vulnerability assessment. It combines network infrastructure scanning with web application security testing (DAST).

> **⚠️ LEGAL DISCLAIMER**: This tool is for **EDUCATIONAL PURPOSES ONLY**. The developer is not responsible for any misuse or damage caused by this program. Only use this tool on systems you own or have explicit permission to audit.

## 🔥 Key Features

### 1. Network Infrastructure Audit
- **Multi-threaded Port Scanning**: Fast scanning using `socket` and `concurrent.futures`.
- **Service Fingerprinting**: Identifies running services (Apache, Nginx, SSH, etc.).
- **CVE Lookup**: Automatically checks identified services against a vulnerability database.

### 2. Deep Reconnaissance
- **Sensitive File Discovery**: Scans for exposed configuration files (`.env`, `.git`, `.htaccess`, etc.).
- **Smart Firewall Detection**: Filters out false positives from WAFs (Cloudflare/Vercel).

### 3. Web Application Audit (DAST)
- **Session Hijacking Support**: Allows authenticated scanning using PHPSESSID.
- **SQL Injection Scanner**: Detects database vulnerabilities in forms.
- **XSS (Cross-Site Scripting) Scanner**: Identifies reflected XSS points.

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/fazawahyu-ap/aegis-scanner.git](https://github.com/fazawahyu-ap/aegis-scanner.git)
   cd aegis-scanner
