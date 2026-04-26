import subprocess
import json
import re
from datetime import datetime, timezone


# ─────────────────────────────────────────────
# PORTS THAT COMMONLY USE TLS
# ─────────────────────────────────────────────

TLS_PORTS = {"443", "8443", "993", "465", "636"}

# Protocols considered weak
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

# Cipher substrings considered weak
WEAK_CIPHER_PATTERNS = ["RC4", "DES", "NULL", "EXPORT", "anon", "MD5"]


# ─────────────────────────────────────────────
# STEP 1: CHECK ONE HOST/PORT WITH OPENSSL
# ─────────────────────────────────────────────

def check_tls(ip, port, timeout=15):
    """
    Runs openssl s_client against a single host:port and extracts:
    - Certificate expiry date
    - Days until expiry (negative = already expired)
    - Whether cert is self-signed
    - Negotiated protocol version
    - Negotiated cipher suite

    Returns a dict of TLS findings, or None if the host doesn't speak TLS.
    """
    print(f"[*] TLS check {ip}:{port}...")

    result = subprocess.run(
        ["openssl", "s_client", "-connect", f"{ip}:{port}",
         "-servername", ip],
        input="",
        capture_output=True,
        text=True,
        timeout=timeout
    )

    output = result.stdout + result.stderr

    # If we got no certificate info at all, port isn't TLS
    if "CONNECTED" not in output and "Certificate chain" not in output and "subject=" not in output:
        print(f"  [-] {ip}:{port} does not appear to use TLS.")
        return None

    tls_data = {}

    # ── Certificate expiry ────────────────────
    expiry_match = re.search(r"notAfter=(.+)", output)
    if expiry_match:
        expiry_str = expiry_match.group(1).strip()
        try:
            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry_dt - now).days
            tls_data["cert_expiry"]        = expiry_dt.strftime("%Y-%m-%d")
            tls_data["days_until_expiry"]  = days_left
            tls_data["is_expired"]         = days_left < 0
        except ValueError:
            tls_data["cert_expiry"]       = expiry_str
            tls_data["days_until_expiry"] = None
            tls_data["is_expired"]        = None
    else:
        tls_data["cert_expiry"]       = None
        tls_data["days_until_expiry"] = None
        tls_data["is_expired"]        = None

    # ── Self-signed detection ─────────────────
    # Self-signed: issuer == subject
    subject_match = re.search(r"subject=(.+)", output)
    issuer_match  = re.search(r"issuer=(.+)",  output)
    if subject_match and issuer_match:
        tls_data["self_signed"] = subject_match.group(1).strip() == issuer_match.group(1).strip()
    else:
        tls_data["self_signed"] = None

    # ── Negotiated protocol ───────────────────
    proto_match = re.search(r"Protocol\s*:\s*(\S+)", output)
    if proto_match:
        proto = proto_match.group(1)
        tls_data["protocol"]      = proto
        tls_data["weak_protocol"] = proto in WEAK_PROTOCOLS
    else:
        tls_data["protocol"]      = None
        tls_data["weak_protocol"] = None

    # ── Negotiated cipher ─────────────────────
    cipher_match = re.search(r"Cipher\s*:\s*(\S+)", output)
    if cipher_match:
        cipher = cipher_match.group(1)
        tls_data["cipher"]      = cipher
        tls_data["weak_cipher"] = any(p in cipher for p in WEAK_CIPHER_PATTERNS)
    else:
        tls_data["cipher"]      = None
        tls_data["weak_cipher"] = None

    status_parts = []
    if tls_data.get("is_expired"):
        status_parts.append("EXPIRED")
    if tls_data.get("self_signed"):
        status_parts.append("SELF-SIGNED")
    if tls_data.get("weak_protocol"):
        status_parts.append(f"WEAK-PROTO({tls_data['protocol']})")
    if tls_data.get("weak_cipher"):
        status_parts.append(f"WEAK-CIPHER({tls_data['cipher']})")

    if status_parts:
        print(f"  [!] {ip}:{port} TLS issues: {', '.join(status_parts)}")
    else:
        print(f"  [+] {ip}:{port} TLS looks healthy.")

    return tls_data


# ─────────────────────────────────────────────
# STEP 2: SCAN ALL ELIGIBLE HOSTS
# ─────────────────────────────────────────────

def scan_all_hosts(json_file, timeout=15):
    """
    Reads the scan JSON, finds ports that use TLS (by port number or
    service name), runs openssl s_client, and writes tls results
    into each eligible port entry.
    """
    with open(json_file, "r") as f:
        scan_data = json.load(f)

    hosts = scan_data.get("hosts", {})

    for ip, host_data in hosts.items():
        ports = host_data.get("ports", {})

        for port_num, port_data in ports.items():
            service = port_data.get("service", "").lower()

            is_tls_port    = port_num in TLS_PORTS
            is_tls_service = service in ("https", "ssl", "tls", "imaps", "smtps", "ldaps")

            if not (is_tls_port or is_tls_service):
                continue

            try:
                tls_result = check_tls(ip, port_num, timeout)
                if tls_result is not None:
                    port_data["tls"] = tls_result
            except subprocess.TimeoutExpired:
                print(f"  [-] TLS check timed out for {ip}:{port_num}")
            except Exception as e:
                print(f"  [-] TLS check failed for {ip}:{port_num}: {e}")

    with open(json_file, "w") as f:
        json.dump(scan_data, f, indent=2)

    print(f"[*] TLS scan results written to: {json_file}")


# ─────────────────────────────────────────────
# STANDALONE ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 tls_scanner.py <scan_results/scan_YYYY-MM-DD_HH-MM.json>")
        sys.exit(1)
    scan_all_hosts(sys.argv[1])
