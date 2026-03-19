import subprocess
import json
import os
import socket
import xml.etree.ElementTree as ET
from datetime import datetime
import ipaddress


# ─────────────────────────────────────────────
# STEP 1: RESOLVE NETWORK RANGE
# ─────────────────────────────────────────────

def get_network_range(configured_range=None):
    """
    Returns the network range to scan.

    If configured_range is provided from settings.yaml, use it directly.
    else, auto-detect from the Pi's active interface by connecting a
    UDP socket to 8.8.8.8 (no data is sent — this just reveals the local IP). assumes /24 subnet 
    in prod we make this configurable per client since some clients might have different subnet sizes. 
    If auto-detection fails  it raises an exception with instructions to set the range manually.
    """
    if configured_range:
        print(f"[*] Using configured network range: {configured_range}")
        return configured_range

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except OSError:
        raise Exception(
            "Could not auto-detect network range — no active network interface. "
            "Set scan.network_range in config/settings.yaml."
        )
    finally:
        s.close()

    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    print(f"[*] Auto-detected local IP: {local_ip}")
    print(f"[*] Scanning network range: {network}")
    return str(network)


# ─────────────────────────────────────────────
# STEP 2: RUN NMAP
# ─────────────────────────────────────────────

def run_nmap(network_range, interface=None):
    """
    Runs a broad host discovery scan using Nmap.
    -sn  : Ping scan - find live hosts without port scanning
    -oX  : Output as XML so we can parse it
    interface, if set, is passed as -e <interface> to bind Nmap to
    a specific network card (e.g. "eth0").
    Returns the raw XML string.
    """
    print(f"[*] Running Nmap host discovery on {network_range}...")

    cmd = ["nmap", "-sn", network_range]
    if interface:
        cmd += ["-e", interface]
    cmd += ["-oX", "-"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] Nmap error: {result.stderr}")
        return None

    print("[*] Nmap scan complete.")
    return result.stdout


# ─────────────────────────────────────────────
# STEP 3: PARSE NMAP XML
# ─────────────────────────────────────────────

def parse_nmap_xml(xml_data):
    """
    Parses Nmap XML output and extracts:
    - IP address
    - MAC address (if available)
    - Vendor (if available)
    - Host status (up/down)

    Returns a dict keyed by IP address.
    """
    hosts = {}

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        raise Exception(f"Failed to parse Nmap XML: {e}")

    for host in root.findall("host"):

        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None

        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor", "Unknown")

        if ip is None:
            continue

        hosts[ip] = {
            "status": "up",
            "mac": mac,
            "vendor": vendor,
            "os_guess": None,   # filled by port_scanner.py
            "ports": {}         # filled by port_scanner.py; each port entry
                                # gets credential_test/tls/web_vulns added in-place
        }

        print(f"  [+] Found host: {ip} | MAC: {mac} | Vendor: {vendor}")

    return hosts


# ─────────────────────────────────────────────
# STEP 4: BUILD AND SAVE JSON
# ─────────────────────────────────────────────

def save_results(network_range, hosts, pi_id, client_id, client_name, results_dir="scan_results"):
    """
    Wraps hosts in a full scan object with metadata and saves to a
    timestamped JSON file in the results directory.
    """
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d_%H-%M")

    scan_data = {
        "scan_meta": {
            "timestamp": now.isoformat(),
            "pi_id": pi_id,
            "client_id": client_id,
            "client_name": client_name,
            "network_range": network_range,
            "hosts_found": len(hosts)
        },
        "hosts": hosts
    }

    os.makedirs(results_dir, exist_ok=True)
    filename = os.path.join(results_dir, f"scan_{timestamp}.json")

    with open(filename, "w") as f:
        json.dump(scan_data, f, indent=2)

    print(f"\n[*] Results saved to: {filename}")
    return filename


# ─────────────────────────────────────────────
# STANDALONE ENTRY POINT
# ─────────────────────────────────────────────

def main():
    print("=" * 50)
    print("  ProbePoint - Host Discovery Scanner")
    print("=" * 50)

    network_range = get_network_range()
    xml_data = run_nmap(network_range)

    if not xml_data:
        print("[!] Scan failed. Exiting.")
        return

    hosts = parse_nmap_xml(xml_data)
    print(f"\n[*] Total hosts discovered: {len(hosts)}")

    if not hosts:
        print("[!] No hosts found. Check network connection.")
        return

    output_file = save_results(network_range, hosts, "standalone", "standalone", "Standalone Run")
    print(f"\n[*] Discovery scan complete. Pass '{output_file}' to the next scanner.")


if __name__ == "__main__":
    main()
