import json
import os
import socket

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

IOT_VENDORS = [
    "tuya", "espressif", "shenzhen bilian", "raspberry pi foundation",
    "raspberry pi", "ring", "nest", "google home", "tp-link", "wyze",
    "hikvision", "dahua", "ubiquiti", "sonos", "ecobee", "chamberlain",
    "myq", "reolink", "amcrest", "axis", "hanwha", "pelco",
    "bosch security", "vivotek", "foscam", "arlo", "eufy", "ezviz",
    "lorex", "zmodo",
    # Broader OUI coverage for portless hosts
    "shenzhen",      # catch-all for Shenzhen* OUIs (iComm, MTC, Bilian, etc.)
    "d-link",
    "belkin",
    "wemo",
    "smartthings",
    "particle",
    "seeed",
    "arduino",
]

# Maps port → (device_hint, issue_label, severity, description)
# None entries are HTTP ports flagged only when vendor_match is True
IOT_PORTS = {
    23:    ("Unknown IoT Device", "Telnet Open",           "CRITICAL", "Telnet enabled — plaintext remote access."),
    2323:  ("Unknown IoT Device", "Telnet Open (alt)",     "CRITICAL", "Telnet on alt port — plaintext remote access."),
    37777: ("IP Camera (Dahua)", "Dahua DVR Port Open",   "CRITICAL", "Dahua DVR management port exposed."),
    34567: ("DVR/NVR",           "Generic DVR Port Open", "CRITICAL", "Generic DVR management port exposed."),
    1883:  ("IoT Hub/Broker",    "MQTT Unencrypted",      "HIGH",     "MQTT broker on unencrypted port 1883."),
    554:   ("IP Camera",         "RTSP Exposed",          "HIGH",     "RTSP stream exposed — may allow unauthenticated video access."),
    8554:  ("IP Camera",         "RTSP Exposed (alt)",    "HIGH",     "RTSP stream on alt port exposed."),
    2020:  ("IP Camera (ONVIF)", "ONVIF Port Open",       "HIGH",     "ONVIF device management port (2020) exposed — camera/NVR management access."),
    8080:  ("IP Camera (ONVIF)", "ONVIF HTTP Interface",  "MEDIUM",   "ONVIF HTTP management interface open — check for unauthenticated access."),
    6668:  ("Smart Plug/Tuya",   "Tuya Protocol Exposed", "MEDIUM",   "Tuya local control protocol port open."),
    5353:  ("Unknown IoT Device","mDNS Active",           "MEDIUM",   "mDNS (port 5353) active — device advertises local services."),
    1900:  ("Unknown IoT Device","UPnP SSDP Active",      "MEDIUM",   "UPnP SSDP port open — device broadcasts presence."),
    80:    None,
}

# Ports for raw HTTP banner grab (443 excluded — needs TLS)
HTTP_PORTS = {80, 8080}

# Keywords in HTTP banners that hint at IoT device types
BANNER_HINTS = {
    "hikvision": "IP Camera (Hikvision)",
    "dahua":     "IP Camera (Dahua)",
    "dvr":       "DVR/NVR",
    "nvr":       "DVR/NVR",
    "camera":    "IP Camera",
    "rtsp":      "IP Camera",
    "ipcam":     "IP Camera",
    "tuya":      "Smart Plug/Tuya",
    "tp-link":   "Smart Switch/TP-Link",
    "tplink":    "Smart Switch/TP-Link",
    "wyze":      "Wyze Camera",
    "ring":      "Ring Doorbell/Camera",
    "nest":      "Nest Device",
    "sonos":     "Sonos Speaker",
    "ecobee":    "Ecobee Thermostat",
    "ubiquiti":  "Ubiquiti Device",
    "unifi":     "Ubiquiti Device",
    "foscam":    "IP Camera (Foscam)",
    "reolink":   "IP Camera (Reolink)",
    "amcrest":   "IP Camera (Amcrest)",
}


# ─────────────────────────────────────────────
# BAD VENDOR DATABASE
# ─────────────────────────────────────────────

def _load_bad_vendors(yaml_path=None):
    """
    Load bad_vendors.yaml and return a list of vendor dicts.
    Falls back to the same directory as this script if no path given.
    Returns empty list if file missing or unparseable.
    """
    if yaml_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        yaml_path = os.path.join(script_dir, "bad_vendors.yaml")

    if not os.path.isfile(yaml_path):
        print(f"  [!] bad_vendors.yaml not found at {yaml_path} — skipping bad vendor checks")
        return []

    try:
        import yaml
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)
        vendors = data.get("vendors", {})
        result = []
        for key, entry in vendors.items():
            result.append({
                "key":              key,
                "display_name":     entry.get("display_name", key),
                "tier":             entry.get("tier", "medium"),
                "reasons":          entry.get("reasons", []),
                "mac_prefixes":     [p.upper() for p in entry.get("mac_prefixes", [])],
                "name_patterns":    [p.lower() for p in entry.get("name_patterns", [])],
                "banner_patterns":  [p.lower() for p in entry.get("banner_patterns", [])],
            })
        print(f"  [*] Loaded {len(result)} bad vendor(s) from {yaml_path}")
        return result
    except ImportError:
        print("  [!] PyYAML not installed — run: pip3 install pyyaml")
        return []
    except Exception as e:
        print(f"  [!] Failed to parse bad_vendors.yaml: {e}")
        return []


def _check_bad_vendor(mac, vendor, http_banners, upnp_text, bad_vendors):
    """
    Check a host against the bad vendor database.

    Matching signals:
      - mac_prefixes:    first 3 octets of MAC (e.g. "88:B5:FF")
      - name_patterns:   substring match against vendor string + UPnP text
      - banner_patterns: substring match against HTTP banner text

    Returns None if no match, otherwise a dict:
      {
        "vendor_key":    "hikvision",
        "display_name":  "Hikvision",
        "tier":          "critical",
        "reasons":       [...],
        "confidence":    "high" | "low",
        "matched_signals": ["mac_prefix", "name_pattern", ...]
      }
    """
    mac_upper = (mac or "").upper()
    # First 3 octets → "AA:BB:CC" (8 chars)
    mac_prefix = mac_upper[:8] if len(mac_upper) >= 8 else ""

    vendor_lower = (vendor or "").lower()
    upnp_lower = (upnp_text or "").lower()

    # Combine all banner text for pattern matching
    all_banners = " ".join(http_banners.values()).lower() if http_banners else ""

    for entry in bad_vendors:
        signals = []

        # MAC prefix match
        if mac_prefix and mac_prefix in entry["mac_prefixes"]:
            signals.append("mac_prefix")

        # Name pattern match (check vendor string AND UPnP text)
        for pattern in entry["name_patterns"]:
            if pattern in vendor_lower or pattern in upnp_lower:
                signals.append("name_pattern")
                break

        # Banner pattern match
        for pattern in entry["banner_patterns"]:
            if pattern in all_banners:
                signals.append("banner_pattern")
                break

        if signals:
            return {
                "vendor_key":       entry["key"],
                "display_name":     entry["display_name"],
                "tier":             entry["tier"],
                "reasons":          entry["reasons"],
                "confidence":       "high" if len(signals) >= 2 else "low",
                "matched_signals":  signals,
            }

    return None


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _grab_http_banner(ip, port, timeout=5):
    """Open a raw TCP socket, send a basic HTTP GET, return the first 512 bytes."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        banner = sock.recv(512).decode("utf-8", errors="ignore")
        sock.close()
        return banner
    except Exception:
        return None


def _send_ssdp(timeout=3):
    """
    Broadcast an SSDP M-SEARCH and collect responses.
    Returns dict[source_ip → response_text] — keyed by source IP to avoid
    substring false-matches when checking per-host later.
    """
    responses = {}
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(msg, ("239.255.255.250", 1900))
        while True:
            try:
                data, (src_ip, _) = sock.recvfrom(1024)
                responses[src_ip] = data.decode("utf-8", errors="ignore")
            except socket.timeout:
                break
        sock.close()
    except Exception:
        pass
    return responses


# ─────────────────────────────────────────────
# CLASSIFICATION
# ─────────────────────────────────────────────

def _classify_host(ip, host_data, ssdp_responses, http_timeout, bad_vendors):
    """Classify a single host and return its iot_classification dict."""
    vendor = (host_data.get("vendor") or "").lower()
    mac    = host_data.get("mac", "")
    open_ports = {int(p) for p in host_data.get("ports", {}).keys()}

    vendor_match = any(v in vendor for v in IOT_VENDORS)

    security_flags = []
    device_type_hints = []   # ordered: first non-None wins
    http_banners = {}
    upnp = None

    # ── Port fingerprinting ──────────────────────────────
    for port in open_ports:
        entry = IOT_PORTS.get(port)
        if entry is None:
            # HTTP port — flag only for vendor-matched devices
            if port in HTTP_PORTS and vendor_match:
                security_flags.append({
                    "port": port,
                    "issue": "Default HTTP Interface",
                    "severity": "MEDIUM",
                    "description": "HTTP management interface open on IoT device — check for missing auth.",
                })
        else:
            hint, issue, severity, description = entry
            device_type_hints.append(hint)
            security_flags.append({
                "port": port,
                "issue": issue,
                "severity": severity,
                "description": description,
            })

    # ── HTTP banner grab ─────────────────────────────────
    banner_device_type = None
    for port in open_ports & HTTP_PORTS:
        banner = _grab_http_banner(ip, port, http_timeout)
        if banner:
            snippet = banner[:512]
            http_banners[str(port)] = snippet
            lower_banner = snippet.lower()
            for keyword, dtype in BANNER_HINTS.items():
                if keyword in lower_banner:
                    banner_device_type = dtype
                    break

    # ── SSDP / UPnP ─────────────────────────────────────
    ssdp_text = ssdp_responses.get(ip)
    if ssdp_text:
        upnp = ssdp_text
        security_flags.append({
            "port": 1900,
            "issue": "UPnP Enabled",
            "severity": "MEDIUM",
            "description": "Device responded to UPnP SSDP discovery — network presence broadcast.",
        })

    # ── Bad vendor check ─────────────────────────────────
    bad_vendor_result = None
    if bad_vendors:
        bad_vendor_result = _check_bad_vendor(
            mac, vendor, http_banners, upnp, bad_vendors
        )
        if bad_vendor_result:
            tier = bad_vendor_result["tier"]
            name = bad_vendor_result["display_name"]
            reasons_str = "; ".join(bad_vendor_result["reasons"][:2])

            # Map tier → severity for the security flag
            tier_to_severity = {
                "critical": "CRITICAL",
                "high":     "HIGH",
                "medium":   "MEDIUM",
            }
            severity = tier_to_severity.get(tier, "MEDIUM")

            security_flags.append({
                "port": "N/A",
                "issue": f"Bad Vendor: {name}",
                "severity": severity,
                "description": f"Known-bad vendor ({tier} tier). {reasons_str}.",
            })
            print(f"  [!] {ip} — Bad vendor match: {name} [{tier}] "
                  f"(confidence: {bad_vendor_result['confidence']}, "
                  f"signals: {', '.join(bad_vendor_result['matched_signals'])})")

    # ── Confidence ───────────────────────────────────────
    iot_port_count = len([f for f in security_flags
                          if f["issue"] not in ("Default HTTP Interface",
                                                "UPnP Enabled")
                          and not str(f["issue"]).startswith("Bad Vendor")])

    if vendor_match and (iot_port_count > 0 or banner_device_type):
        confidence = "high"
    elif vendor_match or iot_port_count >= 2 or banner_device_type:
        confidence = "medium"
    elif iot_port_count == 1:
        confidence = "low"
    else:
        confidence = "low"

    is_iot = confidence in ("high", "medium")

    # ── Device type ──────────────────────────────────────
    if banner_device_type:
        device_type = banner_device_type
    elif device_type_hints:
        device_type = device_type_hints[0]
    elif is_iot:
        device_type = "Unknown IoT Device"
    else:
        device_type = "Not IoT"

    # ── Flag counts ──────────────────────────────────────
    critical_flags = sum(1 for f in security_flags if f["severity"] == "CRITICAL")
    high_flags     = sum(1 for f in security_flags if f["severity"] == "HIGH")

    return {
        "is_iot":         is_iot,
        "device_type":    device_type,
        "confidence":     confidence,
        "security_flags": security_flags,
        "flag_count":     len(security_flags),
        "critical_flags": critical_flags,
        "high_flags":     high_flags,
        "upnp":           upnp,
        "http_banners":   http_banners,
        "bad_vendor":     bad_vendor_result,   # None or the match dict
    }


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────

def scan_all_hosts(json_file, http_timeout=5, ssdp_timeout=3, bad_vendors_path=None):
    with open(json_file, "r") as f:
        scan_data = json.load(f)

    hosts = scan_data.get("hosts", {})
    print(f"[*] IoT classification — {len(hosts)} host(s)")

    # Load bad vendor database
    bad_vendors = _load_bad_vendors(bad_vendors_path)

    ssdp_responses = _send_ssdp(timeout=ssdp_timeout)
    if ssdp_responses:
        print(f"  [*] SSDP: {len(ssdp_responses)} device(s) responded to UPnP discovery")

    iot_ips = []
    flagged_ips = []
    total_flags = 0
    critical_total = 0
    high_total = 0
    unknown_count = 0
    bad_vendor_ips = []

    for ip, host_data in hosts.items():
        print(f"  [*] Classifying {ip} ...")
        classification = _classify_host(ip, host_data, ssdp_responses,
                                        http_timeout, bad_vendors)
        host_data["iot_classification"] = classification

        if classification["is_iot"]:
            iot_ips.append(ip)
            if classification["device_type"] == "Unknown IoT Device":
                unknown_count += 1
            print(f"  [+] {ip} → {classification['device_type']} ({classification['confidence']} confidence)")

        if classification["bad_vendor"]:
            bad_vendor_ips.append(ip)

        if classification["flag_count"] > 0:
            flagged_ips.append(ip)
            total_flags    += classification["flag_count"]
            critical_total += classification["critical_flags"]
            high_total     += classification["high_flags"]
            for flag in classification["security_flags"]:
                sev = flag["severity"]
                marker = "!" if sev == "CRITICAL" else "+"
                print(f"  [{marker}] {ip}:{flag['port']} — {flag['issue']} [{sev}]")

    scan_data["iot_summary"] = {
        "total_hosts":          len(hosts),
        "iot_device_count":     len(iot_ips),
        "unknown_device_count": unknown_count,
        "flagged_device_count": len(flagged_ips),
        "total_security_flags": total_flags,
        "critical_flags":       critical_total,
        "high_flags":           high_total,
        "iot_device_ips":       iot_ips,
        "bad_vendor_count":     len(bad_vendor_ips),
        "bad_vendor_ips":       bad_vendor_ips,
    }

    with open(json_file, "w") as f:
        json.dump(scan_data, f, indent=2)

    print(f"[*] IoT scan complete — {len(iot_ips)} IoT device(s), "
          f"{total_flags} flag(s) ({critical_total} critical), "
          f"{len(bad_vendor_ips)} bad vendor(s)")


# ─────────────────────────────────────────────
# STANDALONE
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 iot_scanner.py <scan_file.json> [http_timeout] [ssdp_timeout]")
        sys.exit(1)
    _http_timeout  = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    _ssdp_timeout  = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    scan_all_hosts(sys.argv[1], http_timeout=_http_timeout, ssdp_timeout=_ssdp_timeout)
