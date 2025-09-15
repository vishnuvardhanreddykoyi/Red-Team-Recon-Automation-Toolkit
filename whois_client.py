# whois_client.py
import socket
import json
import requests
from datetime import datetime
from tldextract import extract
from pathlib import Path

def clean_subdomains(raw_subdomains):
    cleaned = []
    for entry in raw_subdomains:
        if "\n" in entry:
            cleaned.extend(entry.split("\n"))
        else:
            cleaned.append(entry)
    return list(set([s.strip() for s in cleaned if s.strip()]))

def discover_subdomains(domain, wordlist=None):
    
    return [domain]

def fetch_whois_data(domain):
    API_KEY = "at_9CV57FfdUhOaOKAJRsdvhSzWiTf6f"  
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={API_KEY}&domainName={domain}&outputFormat=JSON"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        registry_data = data.get("WhoisRecord", {})

        result = {
            "registrar": registry_data.get("registrarName"),
            "org": registry_data.get("registryData", {}).get("registrant", {}).get("organization"),
            "name_servers": registry_data.get("registryData", {}).get("nameServers", {}).get("hostNames"),
            "emails": registry_data.get("registryData", {}).get("contacts", {}).get("registrant", {}).get("email"),
            "creation_date": registry_data.get("registryData", {}).get("createdDate"),
            "expiration_date": registry_data.get("registryData", {}).get("registryExpiryDate"),
        }
        return result
    except Exception as e:
        return {"error": str(e)}

def run_whois(subdomains, output_file):
    results = {}
    subdomains = clean_subdomains(subdomains)

    if not subdomains:
        return {"report": {"error": "No valid domains provided"}}

    target = subdomains[0]

    
    try:
        socket.inet_aton(target)  
        try:
            
            parsed_domain = socket.gethostbyaddr(target)[0]
            parsed = extract(parsed_domain)
            root_domain = f"{parsed.domain}.{parsed.suffix}" if parsed.domain and parsed.suffix else None
            if not root_domain:
                return {"target": target, "report": {}, "note": "IP resolved but no root domain found"}
        except Exception:
            
            return {"target": target, "report": {}, "note": "IP could not be resolved to a domain"}
    except OSError:
        
        parsed = extract(target)
        root_domain = f"{parsed.domain}.{parsed.suffix}" if parsed.domain and parsed.suffix else None
        if not root_domain:
            return {"report": {"error": f"Could not parse domain from {target}"}}

    try:
        ip = socket.gethostbyname(root_domain)
        whois_info = fetch_whois_data(root_domain)
        results[root_domain] = {
            "ip": ip,
            **whois_info,
            "scanned_at": datetime.now().isoformat()
        }
    except Exception as e:
        results[root_domain] = {"error": str(e)}

    
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    
    output_path = reports_dir / output_file
    report = {"target": root_domain, "report": results}
    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)

    return report

if __name__ == "__main__":
    
    target_domains = ["youtube.com", "rmkec.ac.in", "8.8.8.8"]  
    subdomains = []

    for domain in target_domains:
        subdomains.extend(discover_subdomains(domain))

    output = run_whois(subdomains, "whois_results.json")
    print(json.dumps(output, indent=4))
