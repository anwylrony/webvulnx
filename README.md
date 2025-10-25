# WebVulnX
"WebVulnX" is a conceptual Python-based tool designed to emulate the thought process of a seasoned bug hunter. It's not a magic bullet, but a powerful assistant that automates the tedious parts of reconnaissance and initial vulnerability scanning.
Core Philosophy:

Intelligent Reconnaissance: It doesn't just scan a single URL. It crawls the website to understand its structure, just like a human would.
Multi-Vector Scanning: It targets the most critical and common vulnerability classes: SQL Injection, Cross-Site Scripting (XSS), and Command Injection.
Adaptive WAF Bypass: It doesn't give up when blocked. It attempts to bypass Web Application Firewalls (WAFs) using common obfuscation techniques.
Clear Reporting: It provides a concise, color-coded report of its findings.



<p align="center">
  <strong>Advanced Automated Vulnerability Discovery for Authorized Testing</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

WebVulnX Pro is a sophisticated, Python-based vulnerability scanner designed to emulate the thought process of a seasoned penetration tester. It goes beyond simple scanners by integrating a headless browser to crawl modern, JavaScript-heavy applications, handle authentication, and intelligently bypass Web Application Firewalls (WAFs).

---

## 🔴 LEGAL AND ETHICAL DISCLAIMER 🔴

This tool is for **EDUCATIONAL and AUTHORIZED TESTING PURPOSES ONLY**. Running this tool against any website for which you do not have explicit, written permission is **ILLEGAL** and can have severe legal consequences. The creator of this tool assumes no liability for any misuse. Always operate within a strict legal framework and adhere to ethical guidelines.

---

## 🚀 Key Features

*   **🌐 Advanced Crawling with Playwright:** Sees the web like a real user. Capable of crawling Single-Page Applications (SPAs) and discovering content rendered by JavaScript.
*   **🔐 Authentication Module:** Log in to target applications to scan protected areas where critical vulnerabilities often reside.
*   **🛡️ Intelligent WAF Fingerprinting & Bypass:** Actively identifies the WAF in use (e.g., Cloudflare, Akamai) and applies tailored, advanced bypass techniques.
*   **🔍 Expanded Vulnerability Scope:** Scans for a wide range of critical vulnerabilities, including:
    *   SQL Injection (SQLi)
    *   Cross-Site Scripting (XSS)
    *   Command Injection
    *   Server-Side Request Forgery (SSRF)
    *   Insecure Direct Object Reference (IDOR)
    *   Open Redirect
*   **📡 API Endpoint Discovery:** Intercepts network traffic during crawling to find and test hidden JSON/XML APIs.
*   **🥷 Stealth Mode:** Implements random delays and User-Agent rotation to avoid triggering simple detection mechanisms.
*   **📄 Structured Reporting:** Exports findings to a clean, parsable JSON file for easy integration into reporting pipelines.

---

## 📦 Installation

### Prerequisites

*   Python 3.8 or higher
*   `pip` (Python package installer)

### Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/anwyllrony/webvulnx-pro.git
    cd webvulnx-pro
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Or manually: `pip install requests beautifulsoup4 playwright`)*

3.  **Install Playwright browser binaries:**
    This is a crucial step to enable the headless browser functionality.
    ```bash
    playwright install
    ```

---

## 💡 Usage

### Basic Scan

Scan a single URL and let the tool discover and test all links and forms within the default depth.

```bash
python webvulnx_pro.py http://testphp.vulnweb.com
```

### Authenticated Scan

Scan a protected application by providing login credentials.

```bash
python webvulnx_pro.py http://example.com/dashboard \
  --login-url http://example.com/login \
  -u your_username \
  -p your_password
```

### Save Results to a File

Export the scan results to a JSON file for later analysis or reporting.

```bash
python webvulnx_pro.py http://testphp.vulnweb.com -o vulnerability_report.json
```

### Command-Line Options

| Option                | Description                                                    |
| --------------------- | -------------------------------------------------------------- |
| `url`                 | The target URL to start the scan from.                         |
| `--depth`             | Maximum crawling depth (default: 2).                           |
| `--login-url`         | The URL of the login page for authentication.                  |
| `-u`, `--username`    | Username for the login form.                                   |
| `-p`, `--password`    | Password for the login form.                                   |
| `-o`, `--output`      | File path to save the JSON report.                             |

---

## ⚙️ How It Works

1.  **Authentication (Optional):** If credentials are provided, the tool first navigates to the login URL, parses the form, and submits the credentials to establish a session.
2.  **Advanced Crawling:** Using Playwright, it launches a headless Chromium browser. It navigates the target site, executing JavaScript. It intercepts network requests to discover API endpoints and parses the final DOM to find all links and forms, recursively up to the specified depth.
3.  **Scanning:** For every discovered URL with parameters and every form, the tool launches a series of tests. It injects payloads for each vulnerability class.
4.  **WAF Detection & Bypass:** If a request is blocked (e.g., HTTP 403), the tool analyzes the response headers to fingerprint the WAF. It then generates a set of tailored bypass payloads (e.g., Unicode encoding, comment obfuscation) and retries the request.
5.  **Analysis & Reporting:** The tool analyzes the server's response for each payload, looking for error messages, reflected content, command output, or time-based delays. Any confirmed vulnerabilities are collected and displayed in a final report, which can also be saved to a JSON file.

---

## 🐛 Limitations & Future Work

This tool is a proof-of-concept and has limitations:

*   **Authentication:** The login module is designed for standard form-based authentication and may not handle complex flows like Multi-Factor Authentication (MFA) or OAuth2 without modification.
*   **API Testing:** API endpoint discovery is included, but in-depth API fuzzing (e.g., with complex JSON objects) is not fully implemented.
*   **Blind Vulnerabilities:** Time-based detection for blind vulnerabilities is rudimentary and can be prone to false positives/negatives due to network latency.
*   **CAPTCHAs:** The tool cannot solve CAPTCHAs.

Future improvements could include:
*   Support for OAuth2 and JWT-based authentication.
*   A dedicated module for in-depth REST API fuzzing.
*   More sophisticated blind vulnerability detection.
*   HTML/PDF report generation.

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## ⚠️ Acknowledgement

Remember, with great power comes great responsibility. Use this tool wisely and ethically. Happy hunting (on authorized targets only)!
