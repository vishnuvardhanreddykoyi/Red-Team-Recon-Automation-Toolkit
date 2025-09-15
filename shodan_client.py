import socket
import shodan

def shodan_lookup(target):
    """Query Shodan for info about a domain or IP using a hardcoded API key."""
    api_key = "C6sxvSmTBzIuQMJGZBzKtHzUTSR3q3mu"
    api = shodan.Shodan(api_key)

    
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"target": target, "error": "Invalid domain or unable to resolve"}

    try:
        result = api.host(ip)
        services = []
        for item in result.get('data', []):
            port = item.get("port")
            banner = item.get("data", "").strip()[:200]  
            services.append({
                "port": port,
                "banner": banner,
                "hostnames": result.get('hostnames', []),
                "org": result.get("org"),
                "os": result.get("os"),
                "location": result.get("location"),
            })
        return {
            "input": target,
            "ip": ip,
            "hostnames": result.get("hostnames", []),
            "org": result.get("org"),
            "os": result.get("os"),
            "services": services,
            "location": result.get("location"),
        }
    except shodan.APIError as e:
        return {"ip": ip, "error": str(e)}

domain_to_lookup = "google.com"
info = shodan_lookup(domain_to_lookup)
print(info)
