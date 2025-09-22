from langgraph.graph import StateGraph, END
from .state import RedteamAgentState
from .tools.recon import run_subfinder, run_dnsx
from .tools.scanning import run_naabu, run_nmap
from .tools.vuln_scan import run_httpx, run_nuclei

def subfinder_node(state: RedteamAgentState):
    """Runs subfinder to discover subdomains."""
    if state.get("verbose", 0) >= 1:
        print("--- Starting Subdomain Enumeration ---")
    domain = state.get("target_domain")
    subdomains = run_subfinder(domain, verbose=state.get("verbose", 0))
    return {"subdomains": subdomains}

def dnsx_node(state: RedteamAgentState):
    """Resolves active domains using dnsx."""
    if state.get("verbose", 0) >= 1:
        print("--- Resolving Active Subdomains ---")
    subdomains = state.get("subdomains")
    resolved_domains = run_dnsx(subdomains, verbose=state.get("verbose", 0))
    return {"resolved_domains": resolved_domains}

def naabu_node(state: RedteamAgentState):
    """Finds open ports on live hosts."""
    if state.get("verbose", 0) >= 1:
        print("--- Starting Port Scan ---")
    resolved_domains = state.get("resolved_domains")
    naabu_ports = state.get("naabu_ports")
    open_ports = run_naabu(resolved_domains, ports=naabu_ports, verbose=state.get("verbose", 0))
    return {"scan_results": {"open_ports": open_ports}}

def nmap_node(state: RedteamAgentState):
    """Runs a detailed scan on open ports."""
    if state.get("verbose", 0) >= 1:
        print("--- Starting Detailed Service Scan ---")
    open_ports = state.get("scan_results", {}).get("open_ports", [])
    scan_details = run_nmap(open_ports)
    return {"scan_results": {**state["scan_results"], **scan_details}}

def httpx_node(state: RedteamAgentState):
    """Finds live web servers."""
    if state.get("verbose", 0) >= 1:
        print("--- Identifying Web Servers ---")
    resolved_domains = state.get("resolved_domains")
    web_servers = run_httpx(resolved_domains, verbose=state.get("verbose", 0))
    # Add web servers to the state
    current_scan_results = state.get("scan_results", {})
    current_scan_results["web_servers"] = web_servers
    return {"scan_results": current_scan_results}

def nuclei_node(state: RedteamAgentState):
    """Runs vulnerability scan on web servers."""
    if state.get("verbose", 0) >= 1:
        print("--- Starting Vulnerability Scan ---")
    if not state.get("enable_nuclei"):
        print("[*] Nuclei disabled via CLI flag; skipping.")
        return {"vulnerabilities": []}
    web_servers = state.get("scan_results", {}).get("web_servers", [])
    timeout_seconds = state.get("nuclei_timeout")
    vulnerabilities = run_nuclei(web_servers, timeout_seconds=timeout_seconds, verbose=state.get("verbose", 0))
    return {"vulnerabilities": vulnerabilities}

def create_graph():
    """Creates the main workflow graph for the agent."""
    workflow = StateGraph(RedteamAgentState)

    # Define the nodes
    workflow.add_node("subfinder", subfinder_node)
    workflow.add_node("dnsx", dnsx_node)
    workflow.add_node("naabu", naabu_node)
    workflow.add_node("nmap", nmap_node)
    workflow.add_node("httpx", httpx_node)
    workflow.add_node("nuclei", nuclei_node)

    # Set the entry point
    workflow.set_entry_point("subfinder")

    # Add edges
    workflow.add_edge("subfinder", "dnsx")
    workflow.add_edge("dnsx", "naabu")
    workflow.add_edge("naabu", "nmap")
    workflow.add_edge("nmap", "httpx")
    workflow.add_edge("httpx", "nuclei")
    workflow.add_edge("nuclei", END)

    # Compile the graph
    app = workflow.compile()
    return app
