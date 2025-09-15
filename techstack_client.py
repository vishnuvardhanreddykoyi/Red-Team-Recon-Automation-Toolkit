
import builtwith
import socket
import json
from pathlib import Path

def run_techstack(target, output_file=None):
    try:
        
        try:
            socket.inet_aton(target)
            
            try:
                domain = socket.gethostbyaddr(target)[0]
                print(f"[+] Reverse DNS for {target} → {domain}")
            except socket.herror:
                domain = target
                print(f"[!] No PTR record for {target}, using IP directly")
        except socket.error:
            
            domain = target

        url = f"http://{domain}"
        results = builtwith.parse(url)

        report = {
            "target": target,
            "used_for_scan": domain,
            "technologies": results
        }

        
        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)

        if output_file:
            output_file = output_dir / Path(output_file).name  
        else:
            safe_name = target.replace(":", "_")  
            output_file = output_dir / f"techstack_{safe_name}.json"

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[✔] Tech stack report saved to {output_file.resolve()}")
        return report

    except Exception as e:
        print(f"[!] Error fetching tech stack for {target}: {e}")
        return None



if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python techstack_client.py <domain_or_ip> [output_file.json]")
    else:
        target = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        run_techstack(target, output_file)
