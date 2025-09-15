import subprocess
import json
import socket
from pathlib import Path

def run_theharvester(target):
    """
    Run theHarvester for a domain or IP.
    If an IP is given, try reverse DNS to get a domain.
    """
    
    try:
        socket.inet_aton(target)
        
        try:
            domain = socket.gethostbyaddr(target)[0]
            print(f"[+] Reverse DNS: {target} → {domain}")
        except socket.herror:
            domain = target
            print(f"[!] No PTR record found for IP {target}, using IP directly")
    except socket.error:
        domain = target  

    print(f"[*] Running theHarvester for {domain}...")

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / f"harvester_{domain}.json"

    
    cmd = [
        "python",
        "C:/npncyber/theHarvester/theHarvester.py",
        "-d", domain,
        "-b", "yahoo,duckduckgo,crtsh",
        "-f", f"reports/harvester_report_{domain}"
    ]

    subprocess.run(cmd)

    
    result = {"input": target, "resolved_domain": domain, "report_file": str(output_file)}
    return result



if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python harvester_client.py <domain_or_ip>")
    else:
        target = sys.argv[1]
        report = run_theharvester(target)
        print(json.dumps(report, indent=2))
