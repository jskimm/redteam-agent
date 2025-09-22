from typing import TypedDict, List, Dict, Any, Optional

class RedteamAgentState(TypedDict):
    """
    Represents the state of our Red Team agent.
    This state is passed between nodes in the graph.
    """
    target_domain: str
    subdomains: List[str]
    resolved_domains: List[Dict[str, Any]] # e.g., [{"host": "...", "ip": "..."}]
    scan_results: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    error: str
    naabu_ports: Optional[str]
    enable_nuclei: bool
    nuclei_timeout: Optional[int]
    verbose: int
