# 📧 Phishing Email Analyser

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=flat)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![Blue Team](https://img.shields.io/badge/Blue-Team-1E8449?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

A Python-based command-line tool for analysing suspicious `.eml` files. Extracts Indicators of Compromise (IOCs), parses email headers, and queries the **VirusTotal API** for automated threat enrichment — helping SOC analysts triage phishing emails faster.

---

## 🎯 Threat Scenario

Phishing emails are the most common initial access vector, mapped to:

| MITRE ATT&CK Technique | ID |
|---|---|
| Phishing | T1566 |
| Spearphishing Attachment | T1566.001 |
| Spearphishing Link | T1566.002 |
| Obtain Capabilities: Malware | T1588.001 |

A SOC analyst receives a suspicious email flagged by a user. This tool automates the first-response triage: parse headers, extract all IOCs, and enrich them against VirusTotal — reducing manual triage time significantly.

---

## ⚙️ Features

- **Header Analysis** — extracts `From`, `Reply-To`, `Return-Path`, `Received`, `X-Originating-IP`
- **IOC Extraction** — IPs, domains, URLs, and MD5/SHA256 file hashes from `.eml` files
- **VirusTotal Enrichment** — automatically queries VT API for each extracted IOC
- **Spoofing Detection** — flags mismatches between `From` display name and actual sending domain
- **Report Generation** — outputs a structured Markdown analysis report

---

## 📁 Repository Structure

```
Phishing-Email-Analyser/
├── src/
│   └── email_analyser.py       # Main analysis script
├── sample-data/
│   └── phishing_sample.eml     # Sanitised phishing email for testing
├── reports/
│   └── sample_analysis_report.md  # Example output report
├── screenshots/
│   └── tool_output.png         # Terminal output screenshot
├── requirements.txt
└── README.md
```

---

## 🚀 Setup & Usage

### 1. Clone the repository
```bash
git clone https://github.com/SathvikManuka/Phishing-Email-Analyser.git
cd Phishing-Email-Analyser
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Add your VirusTotal API key
Create a `.env` file in the root directory:
```
VT_API_KEY=your_virustotal_api_key_here
```
> Get a free API key at [virustotal.com](https://www.virustotal.com)

### 4. Run the analyser
```bash
python src/email_analyser.py --file sample-data/phishing_sample.eml
```

### Sample Output
```
========================================
  PHISHING EMAIL ANALYSER - IOC REPORT
========================================

[HEADERS]
  From        : "PayPal Support" <noreply@paypa1-secure.com>
  Reply-To    : attacker@protonmail.com
  Return-Path : bounce@paypa1-secure.com
  ⚠️  SPOOFING DETECTED: Display name domain (paypal.com) ≠ Sending domain (paypa1-secure.com)

[EXTRACTED IOCs]
  IPs      : 192.168.1[.]45, 10.0.0[.]22
  Domains  : paypa1-secure[.]com, malicious-redirect[.]ru
  URLs     : hxxps://paypa1-secure[.]com/login/update

[VIRUSTOTAL RESULTS]
  paypa1-secure[.]com   → 🔴 MALICIOUS  (32/90 engines flagged)
  malicious-redirect[.]ru → 🔴 MALICIOUS (41/90 engines flagged)

[VERDICT]
  ⚠️  HIGH CONFIDENCE PHISHING — Recommend blocking sender domain and reporting to abuse team.

Report saved → reports/analysis_2024_report.md
```

---

## 📊 Sample Analysis Report

See [`reports/sample_analysis_report.md`](https://github.com/SathvikManuka/Phishing-Email-Analyser/blob/main/sample_analysis_report.md) for a full example of the structured output this tool generates.

---

## 🔧 How It Works

```
.eml File Input
      │
      ▼
Header Parsing (email.parser)
      │
      ├──► Spoofing Check (From vs Reply-To vs Return-Path)
      │
      ▼
IOC Extraction (regex)
      │
      ├──► IPs, Domains, URLs, Hashes
      │
      ▼
VirusTotal API Enrichment
      │
      ├──► Malicious / Suspicious / Clean verdict per IOC
      │
      ▼
Markdown Report Output
```

---

## 📚 Skills Demonstrated

- Python scripting for security automation
- Email header forensics and spoofing detection
- IOC extraction using regular expressions
- REST API integration (VirusTotal v3)
- MITRE ATT&CK framework mapping
- SOC triage workflow automation

---

## 📄 License

MIT License — free to use for educational and research purposes.

---

> **Author:** Manuka Sathvik — [LinkedIn](https://linkedin.com/in/sathvik-manuka) · [GitHub](https://github.com/SathvikManuka)
