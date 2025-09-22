import subprocess
import json
import re
from typing import List, Dict, Any, Optional, Set
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_naabu(resolved_domains: List[Dict[str, Any]], ports: Optional[str] = None, verbose: int = 0) -> List[str]:
    """Runs naabu to find open ports with per-host progress (counts zero-open hosts).

    - Default: use '-top-ports 100'
    - If 'ports' provided: use '-ports <ports>' (supports '1-1024', '80,443', ...)
    - Scans per host concurrently and updates progress on host completion
    """
    if not resolved_domains:
        return []

    hosts = [d['host'] for d in resolved_domains]
    if verbose >= 1:
        print(f"[*] Running naabu for {len(hosts)} hosts...")
    try:
        # Build base command once
        base_cmd = ["naabu", "-json", "-silent"]
        if ports:
            base_cmd += ["-port", ports]
        else:
            base_cmd += ["-top-ports", "100"]

        total_hosts = len(hosts)
        if verbose >= 1:
            print(f"[naabu] hosts={total_hosts}")
        open_ports: List[str] = []
        hosts_with_findings: Set[str] = set()

        def scan_single_host(host: str) -> List[str]:
            cmd = base_cmd + ["-host", host]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            host_lines: List[str] = []
            stdout = (result.stdout or "").strip()
            if stdout:
                for line in stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        _ = json.loads(line)
                        host_lines.append(line)
                    except json.JSONDecodeError:
                        if verbose >= 3:
                            print(f"[naabu][{host}] {line}")
            if result.returncode != 0:
                print(f"[naabu][{host}] exited code {result.returncode}. stderr={(result.stderr or '').strip()}")
            return host_lines

        max_workers = min(32, total_hosts or 1)
        pbar = tqdm(total=total_hosts, desc="naabu hosts", unit="host") if total_hosts > 0 else None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {executor.submit(scan_single_host, h): h for h in hosts}
            for future in as_completed(future_to_host):
                h = future_to_host[future]
                try:
                    lines = future.result()
                except Exception as e:
                    if verbose >= 3:
                        print(f"[naabu][{h}] error: {e}")
                    lines = []
                if lines:
                    hosts_with_findings.add(h)
                    open_ports.extend(lines)
                if pbar is not None:
                    pbar.update(1)
        if pbar is not None:
            pbar.close()

        if verbose >= 1:
            print(f"[naabu] hosts with findings: {len(hosts_with_findings)}/{total_hosts}; zero-open: {total_hosts - len(hosts_with_findings)}")
            print(f"[+] Found {len(open_ports)} open ports.")
        return open_ports
    except FileNotFoundError:
        print("[!] Error: 'naabu' command not found. Please ensure it is installed and in your PATH.")
        return []
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running naabu: {e}")
        return []

def run_nmap(open_ports: List[str]) -> Dict[str, Any]:
    """Runs nmap for detailed service enumeration on open ports."""
    if not open_ports:
        return {}

    print(f"[*] Running nmap for {len(open_ports)} host:port combinations...")
    # This is a simplified approach. For a large number of targets, 
    # you would need to handle input/output more carefully.
    # For this example, we'll just show the concept.
    # In a real scenario, you'd parse nmap's XML output.
    
    # For demonstration, we'll just return the list of open ports.
    # A real implementation would parse nmap XML output.
    scan_details = {"nmap_results": open_ports}
    print("[+] Nmap scan complete (conceptual).")
    return scan_details
