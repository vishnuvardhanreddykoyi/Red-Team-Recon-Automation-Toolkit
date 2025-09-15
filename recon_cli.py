#!/usr/bin/env python3
import argparse
import requests
import json
import socket
import subprocess   
from shodan_client import shodan_lookup
from sublist3r import main as sublist3r_main
from credential_scraper import run_credential_scraper
from harvester_client import run_theharvester
from whois_client import run_whois
from techstack_client import run_techstack
from buckets_client import run_buckets
from phishing_client import run_phishing
from cve_client import CVEClient
from iprange_client import run_iprange
from pathlib import Path
import subprocess
import tldextract

def run_fastscan_tasks(domain):
    print(f"[*] Starting fast scan (via npn.py) for {domain}...")

   
    cmd = f"python npn.py {domain}"
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running npn.py: {e}")


def fetch_subdomains_crtsh(domain: str):
    """Query crt.sh for subdomains of a domain."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        subdomains = {entry['name_value'] for entry in data}
        return list(subdomains)
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return []


def fetch_subdomains_sublist3r(domain: str):
    """Use Sublist3r to find subdomains."""
    try:
        subs = sublist3r_main(domain, 40, None, ports=None,
                              silent=True, verbose=False,
                              enable_bruteforce=False, engines=None)
        return list(subs)
    except Exception as e:
        print(f"[!] Sublist3r error: {e}")
        return []


def resolve_subdomains(subdomains):
    """Resolve subdomains to IPs (if possible)."""
    results = []
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            results.append({"subdomain": sub, "ip": ip})
        except socket.gaierror:
            results.append({"subdomain": sub, "ip": None})
    return results


def run_subdomain_recon(domain):
    print(f"[*] Starting subdomain recon for {domain}...")

    subs_crt = fetch_subdomains_crtsh(domain)
    print(f"[+] Found {len(subs_crt)} subdomains from crt.sh")

    subs_sublist3r = fetch_subdomains_sublist3r(domain)
    print(f"[+] Found {len(subs_sublist3r)} subdomains from Sublist3r")

    all_subs = set(subs_crt) | set(subs_sublist3r)
    print(f"[+] Total unique subdomains: {len(all_subs)}")

    resolved = resolve_subdomains(all_subs)

    
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / f"subdomain_report_{domain}.json"
    report = {
        "target": domain,
        "total_subdomains": len(all_subs),
        "results": resolved
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[✔] Subdomain recon completed. Report saved to {output_file.resolve()}")


def run_shodan_for_target(target):
    print(f"[*] Running Shodan lookup for {target}...")
    result = shodan_lookup(target)

    
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / f"shodan_report_{target}.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[✔] Shodan report saved to {output_file.resolve()}")


def run_all_tasks(domain):
    """Run everything except Shodan and --out."""

    run_subdomain_recon(domain)

    creds = run_credential_scraper(domain,
        github_token="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")
    with open(f"credentials_{domain}.json", "w") as f:
        json.dump(creds, f, indent=2)

    harv = run_theharvester(domain)
    with open(f"harvester_report_{domain}.json", "w") as f:
        json.dump(harv, f, indent=2)

    subs = fetch_subdomains_crtsh(domain)
    run_whois(subs, f"whois_report_{domain}.json")

    run_techstack(domain, f"techstack_report_{domain}.json")
    run_buckets(domain, f"buckets_report_{domain}.json")
    run_phishing(domain, f"phishing_report_{domain}.json")
    run_iprange(domain, mask=24, outfile=f"iprange_report_{domain}.json")

    print("\n[✔] All recon modules finished.")
    run_postprocessors()


def run_postprocessors():
    """Run normalize_reports.py and import_spiderfoot.py once."""
    print("[*] Running normalize_reports.py...")
    subprocess.run(["python", "normalize_reports.py"], check=True)

    print("[*] Running import_spiderfoot.py...")
    subprocess.run(["python", "import_spiderfoot.py"], check=True)

    print("\n[✔] Postprocessing completed successfully.")


def main():
    parser = argparse.ArgumentParser(description="Red Team Recon CLI")
    parser.add_argument("--target", help="Target domain (e.g., example.com)")
    parser.add_argument("--all", action="store_true", help="Run full pipeline (everything except shodan/out)")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--shodan", action="store_true", help="Run Shodan lookup using hardcoded API key")
    parser.add_argument("--out", default="report.json", help="Output JSON file")
    parser.add_argument("--creds", action="store_true", help="Scrape leaked credentials & emails")
    parser.add_argument("--harvest", action="store_true", help="Run theHarvester for emails and hosts")
    parser.add_argument("--whois", action="store_true", help="Run WHOIS lookup on discovered subdomains")
    parser.add_argument("--techstack", action="store_true", help="Detect target's technology stack")
    parser.add_argument("--buckets", action="store_true", help="Check for public S3 buckets")
    parser.add_argument("--phishing", action="store_true", help="Find potential phishing vectors")
    parser.add_argument("--iprange", action="store_true", help="Scan target's IP range for active hosts")
    parser.add_argument("--cves", action="store_true", help="Fetch CVEs related to the target")
    parser.add_argument("--fastscan", action="store_true", help="Run fast scan mode")

    


    args = parser.parse_args()

    modules_ran = False  

    if args.target and args.all:
        run_all_tasks(args.target)
        return  

    if args.target and args.subdomains:
        run_subdomain_recon(args.target)
        modules_ran = True

    if args.target and args.harvest:
        print(f"[*] Running theHarvester for {args.target}...")
        result = run_theharvester(args.target)
        output_file = f"harvester_report_{args.target}.json"
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[✔] theHarvester completed. Report saved to {output_file}")
        modules_ran = True
    if args.target and args.cves:
    
        extracted = tldextract.extract(args.target)
        keyword = extracted.domain

        print(f"[*] Fetching CVEs for keyword: {keyword}...")
        client = CVEClient(args.target)
        output_file = f"cve_report_{args.target}.json"
        client.run(keyword=keyword, output_file=output_file)
        print(f"[✔] CVE report saved to {output_file}")
        modules_ran = True


    if args.target and args.whois:
        print(f"[*] Running WHOIS lookup for {args.target}...")
        subs = fetch_subdomains_crtsh(args.target)
        output_file = f"whois_report_{args.target}.json"
        run_whois(subs, output_file)
        print(f"[✔] WHOIS lookup completed. Report saved to {output_file}")
        modules_ran = True

    if args.target and args.techstack:
        print(f"[*] Running tech stack detection for {args.target}...")
        output_file = f"techstack_report_{args.target}.json"
        run_techstack(args.target, output_file)
        modules_ran = True

    if args.target and args.buckets:
        print(f"[*] Checking for public S3 buckets for {args.target}...")
        output_file = f"buckets_report_{args.target}.json"
        run_buckets(args.target, output_file)
        modules_ran = True

    if args.target and args.phishing:
        print(f"[*] Running phishing vector discovery for {args.target}...")
        output_file = f"phishing_report_{args.target}.json"
        run_phishing(args.target, output_file)
        print(f"[✔] Phishing vector discovery completed. Report saved to {output_file}")
        modules_ran = True

    if args.target and args.iprange:
        print(f"[*] Running IP range scan for {args.target}...")
        output_file = f"iprange_report_{args.target}.json"
        run_iprange(args.target, mask=24, outfile=output_file)
        modules_ran = True
    if args.target and args.fastscan:
        print(f"[*] Running fast scan for {args.target} using npn.py...")
        subprocess.run(["python", "npn.py", args.target], check=True)
        modules_ran = True


    if args.target and args.creds:
        print(f"[*] Scraping leaked credentials for {args.target}...")
        result = run_credential_scraper(
            args.target,
            github_token="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"
        )
        output_file = f"credentials_{args.target}.json"
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[✔] Credential scraping completed. Report saved to {output_file}")
        modules_ran = True

    if args.target and args.shodan:
        run_shodan_for_target(args.target)
        
    if modules_ran:
        run_postprocessors()


if __name__ == "__main__":
    main()
