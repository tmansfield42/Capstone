import subprocess
import json
import tempfile
import os


# ─────────────────────────────────────────────
# SERVICES ELIGIBLE FOR CREDENTIAL TESTING
# Maps service name (from Nmap) → Hydra service module
# ─────────────────────────────────────────────

TESTABLE_SERVICES = {
    "ssh":    "ssh",
    "ftp":    "ftp",
    "telnet": "telnet",
    "http":   "http-get",
    "https":  "https-get",
}


# ─────────────────────────────────────────────
# STEP 1: RESOLVE WORDLIST
# ─────────────────────────────────────────────

def _resolve_wordlist(wordlist):
    """
    If wordlist is a file path that exists, use it directly.
    Otherwise treat it as a single password to test (e.g. "testing").
    Returns (path, is_temp) — caller must delete temp file if is_temp=True.
    """
    if os.path.isfile(wordlist):
        return wordlist, False

    # Treat as a literal password — write a tiny temp file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write(f"{wordlist}\n")
    tmp.close()
    return tmp.name, True


# ─────────────────────────────────────────────
# STEP 2: RUN HYDRA AGAINST ONE HOST/SERVICE
# ─────────────────────────────────────────────

def run_hydra(ip, port, hydra_service, wordlist_path, timeout=120):
    """
    Runs Hydra against a single host/service combo.
    Uses the wordlist for both usernames and passwords.

    Returns list of dicts: [{"username": ..., "password": ...}, ...]
    Returns [] if no weak credentials found or Hydra fails.
    """
    print(f"[*] Credential testing {ip}:{port} ({hydra_service})...")

    result = subprocess.run(
        [
            "hydra",
            "-L", wordlist_path,   # username list
            "-P", wordlist_path,   # password list
            "-s", str(port),
            "-t", "4",             # 4 parallel tasks (conservative)
            ip,
            hydra_service
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    found = []
    for line in result.stdout.splitlines():
        # Hydra success lines look like:
        # [22][ssh] host: 192.168.1.10   login: admin   password: admin
        if "login:" in line and "password:" in line:
            try:
                parts = line.split()
                login_idx = parts.index("login:") + 1
                pass_idx  = parts.index("password:") + 1
                found.append({
                    "username": parts[login_idx],
                    "password": parts[pass_idx]
                })
            except (ValueError, IndexError):
                pass

    if found:
        print(f"  [!] Weak credentials found on {ip}:{port} — {len(found)} pair(s)")
    else:
        print(f"  [-] No weak credentials found on {ip}:{port}")

    return found


# ─────────────────────────────────────────────
# STEP 3: TEST ALL ELIGIBLE HOSTS
# ─────────────────────────────────────────────

def test_all_hosts(json_file, wordlist="testing", timeout=120):
    """
    Reads the scan JSON, finds hosts with testable services,
    runs Hydra, and writes credential_test results into each port entry.
    """
    with open(json_file, "r") as f:
        scan_data = json.load(f)

    hosts = scan_data.get("hosts", {})

    wordlist_path, is_temp = _resolve_wordlist(wordlist)

    try:
        for ip, host_data in hosts.items():
            ports = host_data.get("ports", {})

            for port_num, port_data in ports.items():
                service = port_data.get("service", "").lower()

                if service not in TESTABLE_SERVICES:
                    continue

                hydra_service = TESTABLE_SERVICES[service]

                try:
                    pairs = run_hydra(ip, port_num, hydra_service, wordlist_path, timeout)
                    port_data["credential_test"] = {
                        "tested": True,
                        "weak_creds_found": len(pairs) > 0,
                        "pairs": pairs
                    }
                except subprocess.TimeoutExpired:
                    print(f"  [-] Hydra timed out for {ip}:{port_num}")
                except Exception as e:
                    print(f"  [-] Hydra failed for {ip}:{port_num}: {e}")

    finally:
        if is_temp:
            os.unlink(wordlist_path)

    with open(json_file, "w") as f:
        json.dump(scan_data, f, indent=2)

    print(f"[*] Credential test results written to: {json_file}")


# ─────────────────────────────────────────────
# STANDALONE ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 credential_tester.py <scan_results/scan_YYYY-MM-DD_HH-MM.json> [wordlist]")
        sys.exit(1)
    wl = sys.argv[2] if len(sys.argv) > 2 else "testing"
    test_all_hosts(sys.argv[1], wordlist=wl)
