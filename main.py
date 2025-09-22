import argparse
import json
from .graph import create_graph
from .report_generator import generate_html_report

def main():
    """Main function to run the Red Team agent."""
    parser = argparse.ArgumentParser(description="LangGraph-based Red Team Agent")
    parser.add_argument("domain", help="The target domain to scan.")
    parser.add_argument("--port", dest="naabu_ports", default=None,
                        help="Port range/list for naabu (e.g., '1-1024' or '80,443,8080'). Defaults to '1-1024' if omitted.")
    parser.add_argument("--nuclei", dest="enable_nuclei", action="store_true",
                        help="Enable nuclei vulnerability scanning stage.")
    parser.add_argument("--nuclei-timeout", dest="nuclei_timeout", type=int, default=5,
                        help="Per-request timeout (seconds) for nuclei. If omitted, nuclei default is used.")
    parser.add_argument("-v", dest="verbose", action="count", default=0,
                        help="Increase verbosity (-v, -vv, -vvv).")
    args = parser.parse_args()

    app = create_graph()

    # Define the initial state
    initial_state = {
        "target_domain": args.domain,
        "subdomains": [],
        "resolved_domains": [],
        "scan_results": {},
        "vulnerabilities": [],
        "error": None,
        "naabu_ports": args.naabu_ports,
        "enable_nuclei": args.enable_nuclei,
        "nuclei_timeout": args.nuclei_timeout,
        "verbose": args.verbose,
    }

    print(f"--- Initializing Agent for target: {args.domain} ---")

    # Run the graph
    final_state = app.invoke(initial_state)

    print("--- Agent Run Complete ---")
    print("Final State:")
    print(json.dumps(final_state, indent=2))

    # --- Generate HTML Report ---
    print("--- Generating HTML Report ---")
    try:
        html_content = generate_html_report(final_state, args.domain)
        report_filename = f"report_{args.domain}.html"
        with open(report_filename, "w") as f:
            f.write(html_content)
        print(f"[+] Report saved successfully: {report_filename}")
    except Exception as e:
        print(f"[!] Failed to generate HTML report: {e}")

if __name__ == "__main__":
    main()
