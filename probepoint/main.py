import sys
import os
import yaml
from datetime import datetime

from scans import scanner
from scans import port_scanner
from scans import credential_tester
from scans import tls_scanner
from scans import nikto_scanner
from scans import iot_scanner
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


    # ── PHASE 2: Deep Port Scan ──────────────────
    # Always runs — port data is required by all downstream phases
    print("\n[PHASE 2] Deep Port Scan")
    print("-" * 30)
    port_scan_ok = False
    try:
        port_scanner.scan_all_hosts(output_file, timing=timing, timeout=timeout, interface=interface)
        port_scan_ok = True
        print("[PHASE 2] Complete.")
    except Exception as e:
        print(f"[PHASE 2] Failed: {e}")
        print("[PHASE 2] Phases 3–5 will be skipped — no port data.")


    # ── PHASE 2.5: IoT Classification ───────────
    print("\n[PHASE 2.5] IoT Classification")
    print("-" * 30)
    if not port_scan_ok:
        print("[PHASE 2.5] Skipped — Phase 2 did not complete.")
    elif not features.get("iot_scanning", False):
        print("[PHASE 2.5] Disabled in settings.yaml — skipping.")
    else:
        try:
            iot_scanner.scan_all_hosts(output_file, http_timeout=timeout, ssdp_timeout=3)
            print("[PHASE 2.5] Complete.")
        except Exception as e:
            print(f"[PHASE 2.5] Failed: {e}")


    # ── PHASE 3: Credential Testing ─────────────
    print("\n[PHASE 3] Credential Testing")
    print("-" * 30)
    if not port_scan_ok:
        print("[PHASE 3] Skipped — Phase 2 did not complete.")
    elif not features.get("credential_testing", False):
        print("[PHASE 3] Disabled in settings.yaml — skipping.")
    else:
        try:
            wordlist = config.get("hydra", {}).get("wordlist", "testing")
            credential_tester.test_all_hosts(output_file, wordlist=wordlist, timeout=timeout)
            print("[PHASE 3] Complete.")
        except Exception as e:
            print(f"[PHASE 3] Failed: {e}")


    # ── PHASE 4: TLS Scanning ────────────────────
    print("\n[PHASE 4] TLS Scanning")
    print("-" * 30)
    if not port_scan_ok:
        print("[PHASE 4] Skipped — Phase 2 did not complete.")
    elif not features.get("tls_scanning", False):
        print("[PHASE 4] Disabled in settings.yaml — skipping.")
    else:
        try:
            tls_scanner.scan_all_hosts(output_file, timeout=timeout)
            print("[PHASE 4] Complete.")
        except Exception as e:
            print(f"[PHASE 4] Failed: {e}")


    # ── PHASE 5: Nikto Web Scan ──────────────────
    print("\n[PHASE 5] Nikto Web Scan")
    print("-" * 30)
    if not port_scan_ok:
        print("[PHASE 5] Skipped — Phase 2 did not complete.")
    elif not features.get("nikto_scanning", False):
        print("[PHASE 5] Disabled in settings.yaml — skipping.")
    else:
        try:
            nikto_scanner.scan_all_hosts(output_file, timeout=timeout)
            print("[PHASE 5] Complete.")
        except Exception as e:
            print(f"[PHASE 5] Failed: {e}")


    # ── PHASE 6: Collect & Upload ────────────────
    print("\n[PHASE 6] Collect & Upload")
    print("-" * 30)
    try:
        payload = collector.collect(output_file)
        endpoint  = config["aws"]["endpoint"]
        api_key   = config["aws"]["api_key"]
        retries   = config["aws"].get("retry_attempts", 3)
        delay     = config["aws"].get("retry_delay", 10)
        uploader.upload(payload, endpoint, api_key, retries, delay)
        print("[PHASE 6] Complete.")
    except Exception as e:
        print(f"[PHASE 6] Failed: {e}")


    # ── DONE ─────────────────────────────────────
    print("\n" + "=" * 50)
    print(f"  Scan complete. Data saved to: {output_file}")
    print("=" * 50)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    run_pipeline()
