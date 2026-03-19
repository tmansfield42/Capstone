import sys
import os
import yaml
from datetime import datetime

from scans import scanner
from scans import port_scanner
from scans import credential_tester
from scans import tls_scanner
from scans import nikto_scanner
from utils import collector
from utils import uploader
from utils import logger


# ─────────────────────────────────────────────
# LOAD CONFIG
# ─────────────────────────────────────────────

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "settings.yaml")

def load_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[!] Config file not found: {CONFIG_PATH}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"[!] Invalid YAML in config: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────
# PIPELINE RUNNER
# ─────────────────────────────────────────────

def run_pipeline():
    config = load_config()
    logger.setup_logger(config)

    pi_id       = config["pi"]["id"]
    client_id   = config["client"]["id"]
    client_name = config["client"]["name"]
    network     = config["scan"]["network_range"]
    timing      = config["scan"]["intensity"]   # port_scanner normalises "T4" → "4" internally
    timeout     = config["scan"]["timeout"]
    interface   = config["scan"].get("interface", "")
    results_dir = config["storage"]["results_dir"] or "scan_results"
    features    = config["features"]

    print("=" * 50)
    print("  ProbePoint - Vulnerability Scanner")
    print(f"  Pi: {pi_id}  |  Client: {client_name}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 50)

    output_file = None  # passed between phases


    # ── PHASE 1: Host Discovery ──────────────────
    print("\n[PHASE 1] Host Discovery")
    print("-" * 30)
    try:
        network_range = scanner.get_network_range(network)
        xml_data = scanner.run_nmap(network_range, interface=interface)

        if not xml_data:
            raise Exception("Nmap returned no data.")

        hosts = scanner.parse_nmap_xml(xml_data)

        if not hosts:
            raise Exception("No hosts found on the network.")

        output_file = scanner.save_results(network_range, hosts, pi_id, client_id, client_name, results_dir)
        print(f"[PHASE 1] Complete. {len(hosts)} host(s) found.")

    except Exception as e:
        print(f"[PHASE 1] Failed: {e}")
        print("[!] Cannot continue without host data. Exiting.")
        sys.exit(1)



    # ── DONE ─────────────────────────────────────
    print("\n" + "=" * 50)
    print(f"  Scan complete. Data saved to: {output_file}")
    print("=" * 50)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    run_pipeline()
