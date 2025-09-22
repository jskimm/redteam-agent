import json
from typing import Dict, Any

def generate_html_report(state: Dict[str, Any], domain: str) -> str:
    """Generates an HTML report from the final agent state."""
    
    # --- Data Extraction ---
    subdomains = state.get("subdomains", [])
    resolved_domains = state.get("resolved_domains", [])
    scan_results = state.get("scan_results", {})
    open_ports_raw = scan_results.get("open_ports", [])
    web_servers = scan_results.get("web_servers", [])
    vulnerabilities = state.get("vulnerabilities", [])

    # Process open ports for better display (group by host)
    # Normalize ports to integers when possible for consistent sorting and checks
    ports_by_host = {}
    for item in open_ports_raw:
        try:
            data = json.loads(item)
            host = data.get("host")
            port = data.get("port")
            if host and port is not None:
                try:
                    port_num = int(str(port).strip())
                except ValueError:
                    # Skip non-numeric ports (should not occur for naabu JSON)
                    continue
                if host not in ports_by_host:
                    ports_by_host[host] = []
                ports_by_host[host].append(port_num)
        except json.JSONDecodeError:
            # Handle cases where the line is not a valid JSON (e.g., "host:port")
            if ":" in item:
                host, port = item.split(":", 1)
                try:
                    port_num = int(str(port).strip())
                except ValueError:
                    # Skip non-numeric ports
                    continue
                if host not in ports_by_host:
                    ports_by_host[host] = []
                ports_by_host[host].append(port_num)

    # Prepare columns: all unique ports across hosts, sorted
    unique_ports = sorted({p for ports in ports_by_host.values() for p in ports})

    # --- HTML & CSS Template ---
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Red Team Agent Report for {domain}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f9; color: #333; }}
            .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; }}
            h1, h2 {{ color: #4a4a4a; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
            h1 {{ font-size: 2em; }}
            h2 {{ font-size: 1.5em; margin-top: 30px; }}
            .card {{ background-color: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; }}
            .card-title {{ font-weight: bold; color: #555; margin-bottom: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            ul {{ list-style-type: disc; padding-left: 20px; }}
            .severity-critical {{ background-color: #990000; color: white; padding: 3px 8px; border-radius: 3px; }}
            .severity-high {{ background-color: #dc3545; color: white; padding: 3px 8px; border-radius: 3px; }}
            .severity-medium {{ background-color: #ffc107; color: black; padding: 3px 8px; border-radius: 3px; }}
            .severity-low {{ background-color: #17a2b8; color: white; padding: 3px 8px; border-radius: 3px; }}
            .severity-info {{ background-color: #6c757d; color: white; padding: 3px 8px; border-radius: 3px; }}
            .port-table th, .port-table td {{ text-align: center; }}
            .port-table th:first-child, .port-table td:first-child {{ text-align: left; white-space: nowrap; }}
            .check {{ color: #2e7d32; font-weight: bold; }}
            .copy-btn {{ background: transparent; border: none; cursor: pointer; font-size: 16px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Red Team Agent Report</h1>
            <div class="card">
                <p><strong>Target Domain:</strong> {domain}</p>
                <p><strong>Subdomains Found:</strong> {len(subdomains)}</p>
                <p><strong>Live Hosts Found:</strong> {len(resolved_domains)}</p>
                <p><strong>Web Servers Found:</strong> {len(web_servers)}</p>
                <p><strong>Vulnerabilities Found:</strong> {len(vulnerabilities)}</p>
            </div>

            <h2>1. Discovered Subdomains</h2>
            <div class="card">
                <ul>
                    {''.join(f'<li>{s}</li>' for s in subdomains)}
                </ul>
            </div>

            <h2>2. Port Scan Results</h2>
            <div class="card">
                {'' if ports_by_host else '<p>No port scan data available.</p>'}
                {'' if not ports_by_host else f'''
                <table class="port-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            {''.join(f'<th>{p}</th>' for p in unique_ports)}
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(f'''<tr>
                            <td>{host}</td>
                            {''.join(f'<td class="port-cell">' + (f'<button class="copy-btn" data-host="{host}" data-port="{p}" title="Copy {host}:{p}" onclick="copyFromEl(this)">✅️</button> <span class="port-label">({p})</span>' if p in set(ports) else '') + '</td>' for p in unique_ports)}
                        </tr>''' for host, ports in sorted(ports_by_host.items(), key=lambda x: x[0]))}
                    </tbody>
                </table>
                '''}
            </div>

            <h2>3. Web Services</h2>
            <div class="card">
                <ul>
                    {''.join(f'<li><a href="{url}" target="_blank">{url}</a></li>' for url in web_servers)}
                </ul>
            </div>

            <h2>4. Vulnerability Scan Results</h2>
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Name</th>
                            <th>Template</th>
                            <th>Matched At</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(f'''
                        <tr>
                            <td><span class="severity-{vuln['info']['severity']}">{vuln['info']['severity'].upper()}</span></td>
                            <td>{vuln['info'].get('name', 'N/A')}</td>
                            <td>{vuln.get('template-id', 'N/A')}</td>
                            <td>{vuln.get('matched-at', 'N/A')}</td>
                        </tr>
                        ''' for vuln in sorted(vulnerabilities, key=lambda x: x['info'].get('severity', 'info')))}
                    </tbody>
                </table>
            </div>
        </div>
        <script>
        function copyFromEl(el){{
            var text = (el.dataset.host || '') + ':' + (el.dataset.port || '');
            copyText(text);
        }}
        function copyText(text){{
            if (navigator.clipboard && navigator.clipboard.writeText){{
                navigator.clipboard.writeText(text).catch(function(){{ fallbackCopy(text); }});
            }} else {{ fallbackCopy(text); }}
        }}
        function fallbackCopy(text){{
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.top = '-1000px';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            try {{ document.execCommand('copy'); }} catch(e){{}}
            document.body.removeChild(ta);
        }}
        </script>
    </body>
    </html>
    """
    return html
