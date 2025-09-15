#!/usr/bin/env python3
import socket
import ipaddress
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

def get_asn_info(ip: str):
    """Fetch ASN info using ipapi.co"""
    try:
        url = f"https://ipapi.co/{ip}/json/"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "asn": data.get("asn"),
                "org": data.get("org"),
                "network": data.get("network"),
                "country": data.get("country_name")
            }
    except Exception as e:
        print(f"[!] ASN info fetch error: {e}")
    return {}

def check_ip(ip: str):
    """Check if an IP is active on HTTP/HTTPS"""
    for port in (80, 443):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, port))
            s.close()
            return True
        except:
            pass
    return False

def run_iprange(target: str, mask: int = 24, outfile: str = None):
    print(f"[*] Resolving {target} to IP...")

    
    try:
        ip = str(ipaddress.ip_address(target))  
    except ValueError:
        
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            print(f"[!] Could not resolve {target}: {e}")
            return {}

    print(f"[+] Resolved {target} → {ip}")

    
    asn_info = get_asn_info(ip)
    print(f"[+] ASN Info: {asn_info}")

    
    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    print(f"[*] Scanning {len(list(network.hosts()))} IPs in {network}")

    
    active_ips = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_ip, [str(host) for host in network.hosts()])
        for host, is_up in zip(network.hosts(), results):
            if is_up:
                active_ips.append(str(host))

    report = {
        "target": target,
        "source_ip": ip,
        "asn_info": asn_info,
        "active_ips": active_ips,
        "total_active": len(active_ips)
    }

    Path("reports").mkdir(exist_ok=True)
    if not outfile:
        outfile = f"iprange_report_{target.replace('.', '_')}.json"
    path = Path("reports") / outfile

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[✔] IP range scan completed. Report saved to {path}")

    return report


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python iprange_scanner.py <domain_or_ip> [mask] [output_file.json]")
        sys.exit(1)

    target = sys.argv[1]
    mask = int(sys.argv[2]) if len(sys.argv) > 2 else 24
    outfile = sys.argv[3] if len(sys.argv) > 3 else None

    run_iprange(target, mask, outfile)
