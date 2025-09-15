import requests
import json
from pathlib import Path
import time
import ipaddress
import socket

COMMON_BUCKET_SUFFIXES = [
    "", "-backup", "-dev", "-staging", "-test", "-files", "-data"
]

def resolve_to_domain(target):
    """Convert IP to domain if possible, else return the same target."""
    try:
        
        ipaddress.ip_address(target)
        
        host = socket.gethostbyaddr(target)[0]
        print(f"[+] Resolved IP {target} → domain {host}")
        return host
    except ValueError:
        
        return target
    except socket.herror:
        
        print(f"[!] No reverse DNS found for {target}, using IP directly")
        return target

def generate_bucket_names(domain):
    """Generate possible S3 bucket names from domain or IP string."""
    domain_parts = domain.replace(".", "-")
    base = domain.split(".")[0]
    names = [base, domain, domain_parts]

    buckets = []
    for name in names:
        for suffix in COMMON_BUCKET_SUFFIXES:
            buckets.append(f"{name}{suffix}")
    return list(set(buckets))

def check_bucket_exists(bucket_name):
    """Check if a bucket exists by making a request to S3 endpoint."""
    url = f"https://{bucket_name}.s3.amazonaws.com"
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        if 200 <= response.status_code < 300:
            return True, "Accessible"
        elif response.status_code == 403:
            return True, "Exists but Forbidden"
        elif response.status_code == 301:
            return True, "Redirected (maybe exists)"
    except requests.RequestException:
        return False, None
    return False, None

def run_buckets(target, output_file=None):
    try:
        
        resolved_target = resolve_to_domain(target)

        results = []
        candidate_buckets = generate_bucket_names(resolved_target)

        for bucket in candidate_buckets:
            exists, status = check_bucket_exists(bucket)
            if exists:
                results.append({
                    "bucket": bucket,
                    "url": f"https://{bucket}.s3.amazonaws.com",
                    "status": status
                })
            time.sleep(0.5)

        report = {
            "input": target,
            "used_for_scan": resolved_target,
            "buckets": results if results else [{"message": "No public S3 buckets found."}]
        }

        
        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)

        if output_file:
            output_file = output_dir / Path(output_file).name
        else:
            safe_target = resolved_target.replace(".", "_")
            output_file = output_dir / f"s3_buckets_{safe_target}.json"

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[✔] S3 bucket report saved to {output_file.resolve()}")
        return report

    except Exception as e:
        print(f"[!] Error checking buckets for {target}: {e}")
        return None

# CLI usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python buckets_client.py <domain_or_ip> [output_file.json]")
    else:
        target = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        run_buckets(target, output_file)
