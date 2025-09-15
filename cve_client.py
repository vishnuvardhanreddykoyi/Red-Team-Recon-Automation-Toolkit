import requests
import json
import os
import re
import socket

class CVEClient:
    def __init__(self, user_input):
        
        self.domain = self._resolve_input(user_input)
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _resolve_input(self, user_input: str) -> str:
        """
        Accepts either a domain or IP.
        If IP -> try reverse DNS -> domain.
        If domain -> return as is.
        """
        try:
            socket.inet_aton(user_input)  
            try:
                domain = socket.gethostbyaddr(user_input)[0]
                print(f"[+] Resolved IP {user_input} -> domain {domain}")
                return domain
            except Exception as e:
                print(f"[!] Could not resolve IP {user_input}: {e}")
                return user_input  
        except OSError:
            
            return user_input

    def _normalize_keywords(self):
        """
        Generate possible keywords from the domain.
        Example: 'netflix.com' -> ['netflix.com', 'netflix']
        """
        keywords = [self.domain]

        
        cleaned = re.sub(r"\.[a-z]{2,6}$", "", self.domain)
        if cleaned != self.domain:
            keywords.append(cleaned)

        return list(set(keywords))  

    def fetch_cves(self, keyword: str, max_results: int = 10):
        """
        Fetch real CVEs from NVD API using a keyword.
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results
        }

        response = requests.get(self.api_url, params=params, timeout=15)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch CVEs for {keyword}: {response.status_code}")

        data = response.json()
        return [item["cve"]["id"] for item in data.get("vulnerabilities", [])]

    def run(self, keyword: str = None, output_file: str = None, max_results: int = 10):
        """
        Fetch CVEs, prepare report, and save/return JSON.
        """
        cves = set()

        if keyword:
            
            print(f"[*] Using explicit keyword: {keyword}")
            cves.update(self.fetch_cves(keyword, max_results))
        else:
            
            for kw in self._normalize_keywords():
                print(f"[*] Searching CVEs with keyword: {kw}")
                try:
                    cves.update(self.fetch_cves(kw, max_results))
                except Exception as e:
                    print(f"[!] Error fetching CVEs for {kw}: {e}")

        report = {
            "target": self.domain,
            "cves": sorted(cves),
            "total_found": len(cves),
        }

        if output_file:
            reports_dir = "reports"
            os.makedirs(reports_dir, exist_ok=True)
            output_path = os.path.join(reports_dir, output_file)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"[✔] CVE report saved to {output_path}")
        else:
            print(json.dumps(report, indent=2))

        return report



if __name__ == "__main__":
    
    client = CVEClient("netflix.com")
    client.run(output_file="cve_report_netflix.json", max_results=20)

    
    client_ip = CVEClient("8.8.8.8")
    client_ip.run(output_file="cve_report_google_dns.json", max_results=20)
