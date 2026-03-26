import subprocess
import json
import os
import tempfile
import xml.etree.ElementTree as ET


# ─────────────────────────────────────────────
# SERVICES / PORTS ELIGIBLE FOR NIKTO SCANNING
# ─────────────────────────────────────────────

HTTP_SERVICES  = {"http", "http-alt", "http-proxy"}
HTTPS_SERVICES = {"https", "https-alt"}
HTTP_PORTS     = {"80", "8080", "8000", "8008"}
HTTPS_PORTS    = {"443", "8443"}


# ─────────────────────────────────────────────
# STEP 1: RUN NIKTO AGAINST ONE HOST/PORT
# ─────────────────────────────────────────────

def run_nikto(ip, port, use_ssl=False, timeout=300):
    """
    Runs Nikto against a single host:port and returns a list of findings.

    Each finding is a dict:
    {
        "id":          "OSVDB-3268",
        "url":         "/icons/",
        "description": "Directory indexing found.",
        "method":      "GET"
    }

    Returns [] if Nikto finds nothing or fails.
    """
    print(f"[*] Nikto scanning {ip}:{port}{'  (SSL)' if use_ssl else ''}...")

    tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    tmp.close()

    cmd = [
        "nikto",
        "-host", ip,
        "-port", str(port),
        "-Format", "xml",        # XML is stable across Nikto versions
        "-output", tmp.name,     # write to temp file (Nikto doesn't support stdout)
        "-nointeractive"
    ]
    if use_ssl:
        cmd += ["-ssl"]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        with open(tmp.name, "r") as f:
            xml_output = f.read()
    finally:
        os.unlink(tmp.name)

    findings = _parse_nikto_xml(xml_output)

    if findings:
        print(f"  [!] {ip}:{port} — {len(findings)} finding(s)")
    else:
        print(f"  [+] {ip}:{port} — no findings.")

    return findings


def _parse_nikto_xml(xml_output):
    """
    Parses Nikto XML output and returns a list of finding dicts.
    Nikto XML structure:
      <niktoscan>
        <scandetails>
          <item id="..." method="GET" uri="/icons/">
            <description>Directory indexing found.</description>
          </item>
          ...
        </scandetails>
      </niktoscan>
    """
    if not xml_output.strip():
        return []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return []

    findings = []
    for item in root.iter("item"):
        desc_el = item.find("description")
        if desc_el is None or not desc_el.text:
            continue
        findings.append({
            "id":          item.get("id", "N/A"),
            "url":         item.get("uri", ""),
            "description": desc_el.text.strip(),
            "method":      item.get("method", "")
        })

    return findings


# ─────────────────────────────────────────────
# STEP 2: SCAN ALL ELIGIBLE HOSTS
# ─────────────────────────────────────────────

def scan_all_hosts(json_file, timeout=300):
    """
    Reads the scan JSON, finds ports running HTTP or HTTPS,
    runs Nikto on each, and writes web_vulns into each port entry.
    """
    with open(json_file, "r") as f:
        scan_data = json.load(f)

    hosts = scan_data.get("hosts", {})

    for ip, host_data in hosts.items():
        ports = host_data.get("ports", {})

        for port_num, port_data in ports.items():
            service = port_data.get("service", "").lower()

            is_https = (port_num in HTTPS_PORTS or service in HTTPS_SERVICES)
            is_http  = (port_num in HTTP_PORTS  or service in HTTP_SERVICES)

            if not (is_http or is_https):
                continue

            try:
                findings = run_nikto(ip, port_num, use_ssl=is_https, timeout=timeout)
                if findings:
                    port_data["web_vulns"] = findings
            except subprocess.TimeoutExpired:
                print(f"  [-] Nikto timed out for {ip}:{port_num}")
            except Exception as e:
                print(f"  [-] Nikto failed for {ip}:{port_num}: {e}")

    with open(json_file, "w") as f:
        json.dump(scan_data, f, indent=2)

    print(f"[*] Nikto results written to: {json_file}")


# ─────────────────────────────────────────────
# STANDALONE ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 nikto_scanner.py <scan_results/scan_YYYY-MM-DD_HH-MM.json>")
        sys.exit(1)
    scan_all_hosts(sys.argv[1])
