import subprocess
import json
from typing import List, Dict, Any

def run_subfinder(domain: str, verbose: int = 0) -> List[str]:
    """Runs subfinder to discover subdomains for a given domain."""
    if verbose >= 1:
        print(f"[*] Running subfinder for: {domain}")
    try:
        command = ["subfinder", "-d", domain, "-json"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        subdomains = []
        for line in result.stdout.strip().split('\n'):
            try:
                data = json.loads(line)
                subdomains.append(data['host'])
            except json.JSONDecodeError:
                continue # Ignore invalid JSON lines
        
        if verbose >= 1:
            print(f"[+] Found {len(subdomains)} subdomains.")
        return subdomains
    except FileNotFoundError:
        if verbose >= 1:
            print("[!] Error: 'subfinder' command not found. Please ensure it is installed and in your PATH.")
        return []
    except subprocess.CalledProcessError as e:
        if verbose >= 3:
            print(f"[subfinder] {e.stderr}")
        return []

def run_dnsx(subdomains: List[str], verbose: int = 0) -> List[Dict[str, Any]]:
    """Runs dnsx to resolve and find live subdomains."""
    if not subdomains:
        return []
        
    if verbose >= 1:
        print(f"[*] Running dnsx for {len(subdomains)} subdomains...")
    try:
        # Prepare input for dnsx
        subdomain_input = "\n".join(subdomains)
        
        command = ["dnsx", "-json", "-resp"]
        result = subprocess.run(command, input=subdomain_input, capture_output=True, text=True, check=True)
        
        resolved_domains = []
        for line in result.stdout.strip().split('\n'):
            try:
                data = json.loads(line)
                if "a" in data or "aaaa" in data:
                    resolved_domains.append({
                        "host": data.get("host", ""),
                        "ip": data.get("a", []) + data.get("aaaa", [])
                    })
            except json.JSONDecodeError:
                continue
        
        if verbose >= 1:
            print(f"[+] Found {len(resolved_domains)} live hosts.")
        return resolved_domains
    except FileNotFoundError:
        if verbose >= 1:
            print("[!] Error: 'dnsx' command not found. Please ensure it is installed and in your PATH.")
        return []
    except subprocess.CalledProcessError as e:
        if verbose >= 3:
            print(f"[dnsx] {e.stderr}")
        return []
