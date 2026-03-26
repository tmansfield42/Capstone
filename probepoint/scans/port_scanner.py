import subprocess
import json
import xml.etree.ElementTree as ET


# ─────────────────────────────────────────────
# STEP 1: RUN DEEP NMAP SCAN
# ─────────────────────────────────────────────

def run_deep_scan(ip, timing="T4", timeout=300, interface=None):
    """
    Runs a deep Nmap scan against a single host to detect:
    - Open ports and their states
    - Service names and version info
    - OS fingerprint guess

    timing accepts "T4" or "4" — the T prefix is normalised here.
    interface, if set, is passed as -e <interface> to bind Nmap to
    a specific network card (e.g. "eth0").
    Returns raw XML string on success, or None on failure.
    XML is piped to stdout (-oX -) so no temp file is written.
    """
    timing_val = str(timing).lstrip("Tt") or "4"
    print(f"[*] Deep scanning {ip}...")

    cmd = ["sudo", "nmap", "-sV", "-O", f"-T{timing_val}", "--host-timeout", f"{timeout}s"]
    if interface:
        cmd += ["-e", interface]
    cmd += ["-oX", "-", ip]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] Nmap error on {ip}: {result.stderr.strip()}")
        return None

    return result.stdout


# ─────────────────────────────────────────────
# STEP 2: PARSE DEEP SCAN XML
# ─────────────────────────────────────────────

def parse_deep_scan(xml_data):
    """
    Parses Nmap deep scan XML and extracts:
    - os_guess: best OS match name (or None if not detected)
    - ports: dict keyed by port number, only open ports

    Returns:
    {
        "os_guess": "Linux 4.15" or None,
        "ports": {
            "22": {
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "7.9p1"
            },
            ...
        }
    }
    """
    root = ET.fromstring(xml_data)

    # ── OS guess ─────────────────────────────
    os_guess = None
    host_elem = root.find("host")
    if host_elem is not None:
        os_elem = host_elem.find("os")
        if os_elem is not None:
            # osmatch elements have an 'accuracy' attribute (0-100)
            # pick the highest-accuracy match
            matches = os_elem.findall("osmatch")
            if matches:
                best = max(matches, key=lambda m: int(m.get("accuracy", 0) or 0))
                os_guess = best.get("name")

    # ── Open ports ───────────────────────────
    ports = {}
    for port_elem in root.iter("port"):
        state_elem = port_elem.find("state")
        if state_elem is None or state_elem.get("state") != "open":
            continue

        port_id = port_elem.get("portid")
        protocol = port_elem.get("protocol", "tcp")

        service_elem = port_elem.find("service")
        if service_elem is not None:
            service = service_elem.get("name", "")
            product = service_elem.get("product", "")
            version = service_elem.get("version", "")
        else:
            service = ""
            product = ""
            version = ""

        ports[port_id] = {
            "protocol": protocol,
            "state": "open",
            "service": service,
            "product": product,
            "version": version
        }

    return {"os_guess": os_guess, "ports": ports}


# ─────────────────────────────────────────────
# STEP 3: SCAN ALL HOSTS AND UPDATE JSON
# ─────────────────────────────────────────────

def scan_all_hosts(json_file, timing="T4", timeout=300, interface=None):
    """
    Reads the scan JSON written by scanner.py, runs a deep Nmap scan
    on each host, and writes os_guess + ports back into the same file.
    """
    with open(json_file, "r") as f:
        scan_data = json.load(f)

    hosts = scan_data.get("hosts", {})

    for ip in hosts:
        xml_data = run_deep_scan(ip, timing, timeout, interface)

        if xml_data is None:
            print(f"[-] Deep scan failed for {ip}, skipping.")
            continue

        try:
            result = parse_deep_scan(xml_data)
        except ET.ParseError:
            print(f"[-] Could not parse Nmap XML for {ip}, skipping.")
            continue

        os_guess = result["os_guess"]
        ports = result["ports"]

        hosts[ip]["os_guess"] = os_guess
        hosts[ip]["ports"] = ports

        print(f"[+] {ip}: os={os_guess}, {len(ports)} open port(s)")

    # Write updated data back to the same file
    with open(json_file, "w") as f:
        json.dump(scan_data, f, indent=2)

    print(f"[*] Deep scan results written to: {json_file}")


# ─────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: sudo python3 port_scanner.py <scan_results/scan_YYYY-MM-DD_HH-MM.json>")
        sys.exit(1)
    scan_all_hosts(sys.argv[1])
