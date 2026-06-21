#!/usr/bin/env python3
"""
Phishing Email Analyser
========================
Parses .eml files, extracts IOCs (IPs, domains, URLs, hashes),
and queries the VirusTotal API for automated threat enrichment.

Author : Manuka Sathvik
GitHub : https://github.com/SathvikManuka
MITRE  : T1566 (Phishing), T1566.001 (Spearphishing Attachment),
         T1566.002 (Spearphishing Link)
"""

import argparse
import email
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from email import policy
from email.parser import BytesParser

import requests
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────────

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Defanging separators for safe display of IOCs
DEFANG = str.maketrans({"." : "[.]", ":" : "[:]"})

# ── Regex Patterns ─────────────────────────────────────────────────────────────

IP_REGEX     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|ru|io|co|info|biz|xyz|top|online|site|click|link)\b"
)
URL_REGEX    = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
HASH_MD5     = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA256  = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Private / reserved IP ranges to exclude from IOC results
PRIVATE_RANGES = re.compile(
    r"^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
)


# ── Header Extraction ──────────────────────────────────────────────────────────

def parse_headers(msg: email.message.Message) -> dict:
    """Extract and return key email headers."""
    headers = {
        "From"          : msg.get("From", "N/A"),
        "Reply-To"      : msg.get("Reply-To", "N/A"),
        "Return-Path"   : msg.get("Return-Path", "N/A"),
        "Subject"       : msg.get("Subject", "N/A"),
        "Date"          : msg.get("Date", "N/A"),
        "Message-ID"    : msg.get("Message-ID", "N/A"),
        "Received"      : msg.get_all("Received", []),
        "X-Originating-IP": msg.get("X-Originating-IP", "N/A"),
        "Authentication-Results": msg.get("Authentication-Results", "N/A"),
    }
    return headers


def check_spoofing(headers: dict) -> list[str]:
    """Flag common spoofing indicators."""
    warnings = []
    from_field    = headers.get("From", "")
    reply_to      = headers.get("Reply-To", "N/A")
    return_path   = headers.get("Return-Path", "N/A")

    # Extract display name domain vs sending domain
    display_match = re.search(r'"([^"]+)"', from_field)
    sending_match = re.search(r"@([\w.\-]+)", from_field)

    if display_match and sending_match:
        display_name   = display_match.group(1).lower()
        sending_domain = sending_match.group(1).lower()
        known_brands   = ["paypal", "google", "microsoft", "amazon", "apple", "chase", "bank"]
        for brand in known_brands:
            if brand in display_name and brand not in sending_domain:
                warnings.append(
                    f"SPOOFING: Display name references '{brand}' but sends from '{sending_domain}'"
                )

    # Reply-To domain mismatch
    if reply_to != "N/A":
        from_domain   = re.search(r"@([\w.\-]+)", from_field)
        replyto_domain = re.search(r"@([\w.\-]+)", reply_to)
        if from_domain and replyto_domain:
            if from_domain.group(1) != replyto_domain.group(1):
                warnings.append(
                    f"Reply-To domain ({replyto_domain.group(1)}) differs from From domain ({from_domain.group(1)})"
                )

    # Missing Message-ID
    if headers.get("Message-ID") == "N/A":
        warnings.append("Missing Message-ID header — common in spoofed/bulk emails")

    return warnings


# ── IOC Extraction ─────────────────────────────────────────────────────────────

def extract_iocs(msg: email.message.Message) -> dict:
    """Walk the email body and extract all IOCs."""
    body_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    body_text += part.get_payload(decode=True).decode(errors="replace")
                except Exception:
                    pass
    else:
        try:
            body_text = msg.get_payload(decode=True).decode(errors="replace")
        except Exception:
            pass

    # Combine body + headers for full coverage
    full_text = body_text + " ".join(str(v) for v in msg.values())

    raw_ips     = set(IP_REGEX.findall(full_text))
    public_ips  = {ip for ip in raw_ips if not PRIVATE_RANGES.match(ip)}
    domains     = set(DOMAIN_REGEX.findall(full_text))
    urls        = set(URL_REGEX.findall(full_text))
    md5_hashes  = set(HASH_MD5.findall(full_text))
    sha256s     = set(HASH_SHA256.findall(full_text))

    return {
        "ips"     : sorted(public_ips),
        "domains" : sorted(domains),
        "urls"    : sorted(urls),
        "md5"     : sorted(md5_hashes),
        "sha256"  : sorted(sha256s),
    }


# ── VirusTotal Enrichment ──────────────────────────────────────────────────────

def query_virustotal(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal v3 API for a single IOC."""
    if not VT_API_KEY:
        return {"error": "No VT_API_KEY set in .env"}

    endpoints = {
        "ip"     : f"{VT_BASE_URL}/ip_addresses/{ioc}",
        "domain" : f"{VT_BASE_URL}/domains/{ioc}",
        "url"    : f"{VT_BASE_URL}/urls/{hashlib.sha256(ioc.encode()).hexdigest()}",
        "hash"   : f"{VT_BASE_URL}/files/{ioc}",
    }

    url = endpoints.get(ioc_type)
    if not url:
        return {"error": f"Unknown IOC type: {ioc_type}"}

    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data  = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())
            verdict    = (
                "🔴 MALICIOUS"  if malicious  > 0 else
                "🟡 SUSPICIOUS" if suspicious > 0 else
                "🟢 CLEAN"
            )
            return {
                "verdict"   : verdict,
                "malicious" : malicious,
                "suspicious": suspicious,
                "total"     : total,
            }
        elif resp.status_code == 404:
            return {"verdict": "⚪ NOT FOUND", "malicious": 0, "suspicious": 0, "total": 0}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def enrich_iocs(iocs: dict) -> dict:
    """Run VirusTotal enrichment on all extracted IOCs."""
    results = {}

    for ip in iocs["ips"]:
        results[ip] = query_virustotal(ip, "ip")

    for domain in iocs["domains"]:
        results[domain] = query_virustotal(domain, "domain")

    for h in iocs["md5"] + iocs["sha256"]:
        results[h] = query_virustotal(h, "hash")

    return results


# ── Report Generation ──────────────────────────────────────────────────────────

def generate_report(headers: dict, spoofing: list, iocs: dict, vt_results: dict, outfile: str):
    """Write a structured Markdown analysis report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# Phishing Email Analysis Report",
        f"\n**Generated:** {timestamp}  ",
        f"**Analyst:** Manuka Sathvik  ",
        f"**MITRE ATT&CK:** T1566 – Phishing\n",
        "---\n",
        "## 1. Email Headers\n",
        f"| Field | Value |",
        f"|---|---|",
    ]

    for k, v in headers.items():
        if k != "Received":
            lines.append(f"| {k} | `{str(v)[:120]}` |")

    lines += [
        "\n## 2. Spoofing Indicators\n",
    ]
    if spoofing:
        for w in spoofing:
            lines.append(f"- ⚠️  {w}")
    else:
        lines.append("- ✅ No spoofing indicators detected")

    lines += [
        "\n## 3. Extracted IOCs\n",
        f"| Type | Value (Defanged) |",
        f"|---|---|",
    ]
    for ip in iocs["ips"]:
        lines.append(f"| IP Address | `{ip.translate(DEFANG)}` |")
    for d in iocs["domains"]:
        lines.append(f"| Domain     | `{d.translate(DEFANG)}` |")
    for u in iocs["urls"]:
        lines.append(f"| URL        | `{u.translate(DEFANG)[:100]}` |")
    for h in iocs["md5"]:
        lines.append(f"| MD5 Hash   | `{h}` |")
    for h in iocs["sha256"]:
        lines.append(f"| SHA256     | `{h}` |")

    lines += [
        "\n## 4. VirusTotal Enrichment\n",
        f"| IOC | Verdict | Malicious Engines | Total Engines |",
        f"|---|---|---|---|",
    ]
    for ioc, result in vt_results.items():
        if "error" in result:
            lines.append(f"| `{ioc}` | ❌ Error: {result['error']} | – | – |")
        else:
            lines.append(
                f"| `{ioc.translate(DEFANG)}` | {result['verdict']} "
                f"| {result.get('malicious', 0)} | {result.get('total', 0)} |"
            )

    malicious_count = sum(
        1 for r in vt_results.values()
        if isinstance(r.get("malicious"), int) and r["malicious"] > 0
    )
    verdict = (
        "🔴 HIGH CONFIDENCE PHISHING — Block sender domain and escalate."
        if malicious_count > 0 else
        "🟡 SUSPICIOUS — Manual review recommended."
        if spoofing else
        "🟢 CLEAN — No threats detected."
    )

    lines += [
        "\n## 5. Verdict\n",
        f"> **{verdict}**\n",
        "---",
        "_Report generated by Phishing Email Analyser — github.com/SathvikManuka_",
    ]

    with open(outfile, "w") as f:
        f.write("\n".join(lines))

    print(f"\n✅ Report saved → {outfile}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def print_banner():
    print("""
╔═══════════════════════════════════════════════╗
║       PHISHING EMAIL ANALYSER  v1.0           ║
║       IOC Extraction + VirusTotal Triage      ║
║       MITRE ATT&CK: T1566                     ║
╚═══════════════════════════════════════════════╝
""")


def main():
    parser = argparse.ArgumentParser(
        description="Analyse .eml files for phishing IOCs and VirusTotal enrichment."
    )
    parser.add_argument("--file",   required=True, help="Path to the .eml file")
    parser.add_argument("--report", default="reports/analysis_report.md",
                        help="Output path for Markdown report (default: reports/analysis_report.md)")
    parser.add_argument("--no-vt",  action="store_true",
                        help="Skip VirusTotal enrichment (useful without API key)")
    args = parser.parse_args()

    print_banner()

    # Load email
    try:
        with open(args.file, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except FileNotFoundError:
        print(f"❌ File not found: {args.file}")
        sys.exit(1)

    print(f"📂 Analysing: {args.file}\n")

    # Parse headers
    print("[1/4] Parsing headers...")
    headers  = parse_headers(msg)
    spoofing = check_spoofing(headers)

    print(f"\n  From       : {headers['From']}")
    print(f"  Reply-To   : {headers['Reply-To']}")
    print(f"  Subject    : {headers['Subject']}")
    if spoofing:
        for w in spoofing:
            print(f"  ⚠️  {w}")

    # Extract IOCs
    print("\n[2/4] Extracting IOCs...")
    iocs = extract_iocs(msg)
    print(f"  IPs      : {len(iocs['ips'])}")
    print(f"  Domains  : {len(iocs['domains'])}")
    print(f"  URLs     : {len(iocs['urls'])}")
    print(f"  Hashes   : {len(iocs['md5']) + len(iocs['sha256'])}")

    # VirusTotal enrichment
    vt_results = {}
    if not args.no_vt:
        print("\n[3/4] Querying VirusTotal...")
        vt_results = enrich_iocs(iocs)
        for ioc, result in vt_results.items():
            verdict = result.get("verdict", result.get("error", "?"))
            print(f"  {ioc.translate(DEFANG)[:50]:<50} → {verdict}")
    else:
        print("\n[3/4] VirusTotal skipped (--no-vt)")

    # Generate report
    print("\n[4/4] Generating report...")
    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    generate_report(headers, spoofing, iocs, vt_results, args.report)

    # Final verdict
    malicious = sum(
        1 for r in vt_results.values()
        if isinstance(r.get("malicious"), int) and r["malicious"] > 0
    )
    print("\n" + "═" * 50)
    if malicious > 0:
        print("🔴 VERDICT: HIGH CONFIDENCE PHISHING")
        print("   → Block sender domain and escalate.")
    elif spoofing:
        print("🟡 VERDICT: SUSPICIOUS — Manual review recommended.")
    else:
        print("🟢 VERDICT: CLEAN — No threats detected.")
    print("═" * 50)


if __name__ == "__main__":
    main()
