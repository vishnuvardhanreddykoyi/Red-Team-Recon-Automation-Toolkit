import subprocess
import json
from pathlib import Path

def run_phishing(domain, output_file=None):
    try:
        print(f"[*] Running theHarvester to find emails/domains for {domain}...")

        # Ensure reports folder exists
        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)

        # Construct base report path for theHarvester
        base_report = output_dir / f"harvester_{domain}"

        # Run theHarvester (sources can be changed as needed)
        cmd = [
            "python",
            r"C:\npncyber\theHarvester\theHarvester.py",
            "-d", domain,
            "-b", "yahoo,duckduckgo,crtsh",
            "-f", str(base_report)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[!] theHarvester failed: {result.stderr}")
            return None

        # Extract emails from theHarvester output
        emails = []
        for line in result.stdout.splitlines():
            if "@" in line and not line.strip().startswith("["):
                emails.append(line.strip())

        if not emails:
            print("[!] No emails found for this domain.")
            return None

        # --- Phishing Vector Analysis ---
        risk_emails = []
        high_risk_keywords = ["admin", "support", "info", "hr", "accounts", "helpdesk"]

        for email in emails:
            risk = "Low"
            local_part = email.split("@")[0].lower()

            if any(keyword in local_part for keyword in high_risk_keywords):
                risk = "High"
            elif len(local_part) <= 5:
                risk = "Medium"

            risk_emails.append({
                "email": email,
                "risk": risk
            })

        # Final report with both raw emails + phishing risk
        report = {
            "target": domain,
            "emails": emails,
            "phishing_vectors": risk_emails
        }

        # Always save inside reports/
        if output_file:
            output_file = output_dir / Path(output_file).name
        else:
            output_file = output_dir / f"phishing_vectors_{domain}.json"

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[✔] Phishing vector report saved to {output_file.resolve()}")
        return report

    except Exception as e:
        print(f"[!] Error running theHarvester for {domain}: {e}")
        return None


# Run standalone
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python phishing_client.py <domain> [output_file.json]")
    else:
        domain = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        run_phishing(domain, output_file)
