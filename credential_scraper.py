#!/usr/bin/env python3
import re
import requests
import json
import socket
from pathlib import Path


def normalize_target(target: str):
    """
    Accepts either a domain or IP.
    - If input is IP, resolve it to domain (reverse DNS).
    - If reverse fails, fallback to original IP string.
    """
    try:
        
        socket.inet_aton(target)
        
        try:
            domain = socket.gethostbyaddr(target)[0]
            return domain
        except socket.herror:
            return target  
    except OSError:
        
        return target



def extract_emails(text):
    """Regex to extract emails from text."""
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return re.findall(email_pattern, text)


def extract_credentials(text):
    """Find potential credentials, API keys, tokens, passwords."""
    patterns = [
        r"(?i)password\s*[:=]\s*['\"]?(\S+)['\"]?",
        r"(?i)api[_-]?key\s*[:=]\s*['\"]?(\S+)['\"]?",
        r"(?i)secret\s*[:=]\s*['\"]?(\S+)['\"]?",
        r"(?i)token\s*[:=]\s*['\"]?(\S+)['\"]?"
    ]
    creds = []
    for pat in patterns:
        creds.extend(re.findall(pat, text))
    return creds


def extract_internal_info(text, domain_or_ip):
    """Find URLs, subdomains, or endpoints related to the target (domain or IP)."""
    findings = []

    
    try:
        socket.inet_aton(domain_or_ip)
        ip_pattern = re.escape(domain_or_ip)
        ip_refs = re.findall(ip_pattern, text)
        findings.extend(ip_refs)
    except OSError:
        
        url_pattern = rf"https?://(?:[a-zA-Z0-9.-]*\.)?{re.escape(domain_or_ip)}(?:/\S*)?"
        subdomain_pattern = rf"[a-zA-Z0-9.-]+\.{re.escape(domain_or_ip)}"
        urls = re.findall(url_pattern, text)
        subs = re.findall(subdomain_pattern, text)
        findings.extend(urls + subs)

    return list(set(findings))



def github_search(domain, github_token=None):
    """Search GitHub for leaks mentioning the domain."""
    headers = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    query = f'"{domain}"'
    url = f"https://api.github.com/search/code?q={query}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return {"error": f"GitHub search failed: {resp.text}"}
        return resp.json().get("items", [])
    except Exception as e:
        return {"error": str(e)}


def pastebin_search(domain):
    """Scrape Pastebin dumps mentioning the domain (unofficial API)."""
    url = f"https://psbdmp.ws/api/search/{domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        return {"error": str(e)}
    return []



def save_report(data, out_file):
    Path("reports").mkdir(exist_ok=True)
    path = Path("reports") / out_file
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[✔] Report saved: {path}")



def run_credential_scraper(target, github_token=None):
    
    domain_for_scan = normalize_target(target)

    report = {
        "input": target,           
        "used_for_scan": domain_for_scan,  
        "emails": [],
        "potential_credentials": [],
        "internal_info": [],
        "github": [],
        "pastebin": []
    }

    # GitHub
    print("[*] Searching GitHub...")
    gh_data = github_search(domain_for_scan, github_token)
    report["github"] = gh_data

    # Pastebin
    print("[*] Searching Pastebin...")
    pb_data = pastebin_search(domain_for_scan)
    if isinstance(pb_data, list):
        for paste in pb_data:
            paste.pop("text", None)
    report["pastebin"] = pb_data

    
    combined_text = json.dumps(gh_data) + json.dumps(pb_data)

    report["emails"] = list(set(extract_emails(combined_text)))
    report["potential_credentials"] = list(set(extract_credentials(combined_text)))
    report["internal_info"] = list(set(extract_internal_info(combined_text, domain_for_scan)))

    
    safe_name = target.replace(".", "_").replace(":", "_")
    save_report(report, f"credentials_report_{safe_name}.json")

    return report


# CLI usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python credential_scraper.py <domain_or_ip> [github_token]")
    else:
        target = sys.argv[1]
        github_token = sys.argv[2] if len(sys.argv) > 2 else None
        run_credential_scraper(target, github_token)
