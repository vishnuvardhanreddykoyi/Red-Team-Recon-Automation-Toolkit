import subprocess
import multiprocessing
import sys
import time

def run_module(args):
    module, target = args
    cmd = f"python recon_cli.py --target {target} {module}"
    print(f"[+] Running: {cmd}")
    process = subprocess.Popen(cmd, shell=True)
    process.wait()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python npn.py <target-domain>")
        sys.exit(1)

    target = sys.argv[1]

    modules = [
        "--creds",
        "--harvest",
        "--whois",
        "--techstack",
        "--buckets",
        "--phishing",
        "--iprange",
        "--subdomains",
        "--cves",
        "--shodan"
    ]

    start_time = time.time()

    
    args_list = [(module, target) for module in modules]

    with multiprocessing.Pool(processes=len(modules)) as pool:
        pool.map(run_module, args_list)

    end_time = time.time()
    elapsed = end_time - start_time

    print(f"\n[✓] All scans finished in {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
