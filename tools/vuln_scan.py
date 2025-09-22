import subprocess
import json
from typing import List, Dict, Any, Optional
from tqdm import tqdm
import os

def run_httpx(resolved_domains: List[Dict[str, Any]], verbose: int = 0) -> List[str]:
    """Runs httpx to find live web servers."""
    if not resolved_domains:
        return []

    hosts = [d['host'] for d in resolved_domains]
    if verbose >= 1:
        print(f"[*] Running httpx for {len(hosts)} hosts...")
    try:
        host_input = "\n".join(hosts)
        command = ["httpx", "-silent", "-json"]
        result = subprocess.run(command, input=host_input, capture_output=True, text=True, check=True)
        
        web_servers = []
        for line in result.stdout.strip().split('\n'):
            try:
                data = json.loads(line)
                web_servers.append(data.get("url"))
            except json.JSONDecodeError:
                continue

        if verbose >= 1:
            print(f"[+] Found {len(web_servers)} web servers.")
        return web_servers
    except FileNotFoundError:
        if verbose >= 1:
            print("[!] Error: 'httpx' command not found. Please ensure it is installed and in your PATH.")
        return []
    except subprocess.CalledProcessError as e:
        if verbose >= 3:
            print(f"[httpx] {e}")
        return []

def run_nuclei(urls: List[str], timeout_seconds: Optional[int] = None, verbose: int = 0) -> List[Dict[str, Any]]:
    """Runs nuclei to find vulnerabilities.

    Uses a temporary file with '-list', suppresses noisy output, parses
    JSON lines from stdout even on non-zero exit, and excludes some
    noisy templates via '-eid'.
    """
    if not urls:
        return []

    if verbose >= 1:
        print(f"[*] Running nuclei for {len(urls)} URLs...")
    try:
        url_input = "\n".join(urls)
        exclude_ids = "http-missing-security-headers,waf-detect,http-trace,options-method"
        command = [
            "nuclei",
            "-jsonl",
            "-silent",
            "-nc",
            "-eid", exclude_ids,
            "-stats-json",
            "-si", "5",
        ]
        if timeout_seconds is not None:
            command += ["-timeout", str(timeout_seconds)]

        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        assert process.stdin is not None
        process.stdin.write(url_input)
        process.stdin.close()

        vulnerabilities: List[Dict[str, Any]] = []
        assert process.stdout is not None

        total_requests: Optional[int] = None
        current_requests: int = 0
        stats_pbar: Optional[tqdm] = None
        hosts_header_printed: bool = False

        for line in process.stdout:
            if not line:
                continue
            line_stripped = line.strip()
            if not line_stripped:
                continue
            # Try parse stats json
            parsed: Optional[Dict[str, Any]] = None
            try:
                parsed = json.loads(line_stripped)
            except json.JSONDecodeError:
                parsed = None

            if isinstance(parsed, dict) and set(["duration","errors","hosts","matched","percent","requests","rps","templates","total"]).issubset(parsed.keys()):
                # Stats line
                try:
                    hosts = int(parsed.get("hosts", 0))
                    requests = int(parsed.get("requests", 0))
                    total = int(parsed.get("total", 0))
                    percent = int(parsed.get("percent", 0))
                    duration = parsed.get("duration", "")
                except Exception:
                    hosts = 0; requests = 0; total = total_requests or 0; percent = 0; duration = ""

                if not hosts_header_printed and hosts:
                    if verbose >= 1:
                        print(f"[nuclei] hosts={hosts}")
                    hosts_header_printed = True

                if total_requests is None and total:
                    total_requests = total
                    stats_pbar = tqdm(total=total_requests, desc=f"nuclei {hosts} hosts", unit="req")

                if stats_pbar is not None:
                    # Advance by delta
                    delta = 0
                    if requests >= current_requests:
                        delta = requests - current_requests
                        current_requests = requests
                    else:
                        # handle reset edge cases
                        delta = 0
                        current_requests = requests
                    if delta:
                        stats_pbar.update(delta)
                    # Optionally show percent & duration in postfix
                    stats_pbar.set_postfix(percent=f"{percent}%", duration=duration)
                continue

            # Not a stats line: try vulnerability line
            try:
                data = json.loads(line_stripped)
                if isinstance(data, dict) and data.get("info"):
                    vulnerabilities.append(data)
                    if verbose >= 1:
                        print(f"[nuclei][match] {data.get('template-id','')} @ {data.get('matched-at','')}")
            except json.JSONDecodeError:
                # raw log; gated by high verbosity
                if verbose >= 3:
                    print(f"[nuclei] {line_stripped}")

        returncode = process.wait()
        if stats_pbar is not None:
            stats_pbar.close()
        if returncode != 0 and verbose >= 1:
            print(f"[!] nuclei exited with code {returncode}")

        if verbose >= 1:
            print(f"[+] Found {len(vulnerabilities)} potential vulnerabilities.")
        return vulnerabilities
    except FileNotFoundError:
        print("[!] Error: 'nuclei' command not found. Please ensure it is installed and in your PATH.")
        return []
    finally:
        pass
