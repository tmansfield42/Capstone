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
}

# Ports that indicate an HTTP server for CeWL wordlist generation
HTTP_PORTS = {"80", "443"}


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
# STEP 1.5: GENERATE CEWL WORDLIST FOR HTTP HOSTS
# ─────────────────────────────────────────────

def _host_has_http(ports):
    """Check if any open port is 80 or 443."""
    for port_num, port_data in ports.items():
        if str(port_num) in HTTP_PORTS and port_data.get("state", "").lower() == "open":
            return True
    return False


def _generate_cewl_wordlist(ip, ports):
    """
    Runs generate_wordlist.sh against an HTTP host.
    Expects generate_wordlist.sh and stopwords.txt in the current
    working directory (wherever the scanner is run from).

    Returns path to generated wordlist, or None on failure.
    """
    if not os.path.isfile("generate_wordlist.sh"):
        print("  [!] generate_wordlist.sh not found in current directory")
        return None

    if not os.path.isfile("stopwords.txt"):
        print("  [!] stopwords.txt not found in current directory")
        return None

    # Build URL — use http:// for either port
    url = f"http://{ip}"

    print(f"  [*] Generating CeWL wordlist from {url}...")

    try:
        result = subprocess.run(
            ["sudo", "bash", "generate_wordlist.sh", url],
            capture_output=True,
            text=True,
            timeout=600
        )

        if result.returncode != 0:
            print(f"  [!] Wordlist generation failed: {result.stderr[:200]}")
            return None

        if os.path.isfile("final_wordlist.txt") and os.path.getsize("final_wordlist.txt") > 0:
            count = sum(1 for _ in open("final_wordlist.txt"))
            print(f"  [+] CeWL wordlist generated: {count} entries")
            return os.path.abspath("final_wordlist.txt")
        else:
            print("  [!] Wordlist script ran but produced no output")
            return None

    except subprocess.TimeoutExpired:
        print("  [!] Wordlist generation timed out (600s)")
        return None
    except Exception as e:
        print(f"  [!] Wordlist generation error: {e}")
        return None


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
            "-f",                  # stop after first valid credential found
            ip,
            hydra_service
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    # Hydra exits 0 only when it finds valid credentials.
    # Any non-zero exit means nothing was found — skip parsing entirely.
    if result.returncode != 0:
        return []

    found = []
    for line in result.stdout.splitlines():
        # Hydra success lines look like:
        # [22][ssh] host: 192.168.1.10   login: admin   password: admin
        # Require line starts with "[" to avoid matching verbose/informational output.
        if line.startswith("[") and "login:" in line and "password:" in line:
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

    If a host has port 80 or 443 open, generates a CeWL-based wordlist
    from the web server and uses that instead of the default wordlist.
    """
    with open(json_file, "r") as f:
        scan_data = json.load(f)

    hosts = scan_data.get("hosts", {})

    # Resolve the default/fallback wordlist once
    default_path, default_is_temp = _resolve_wordlist(wordlist)

    try:
        for ip, host_data in hosts.items():
            ports = host_data.get("ports", {})

            # Decide wordlist: CeWL if HTTP is present, else default
            cewl_path = None
            if _host_has_http(ports):
                cewl_path = _generate_cewl_wordlist(ip, ports)

            if cewl_path:
                active_wordlist = cewl_path
                print(f"  [*] Using CeWL wordlist for {ip}")
            else:
                active_wordlist = default_path
                if _host_has_http(ports):
                    print(f"  [*] CeWL failed for {ip}, falling back to default wordlist")

            for port_num, port_data in ports.items():
                service = port_data.get("service", "").lower()

                if service not in TESTABLE_SERVICES:
                    continue

                hydra_service = TESTABLE_SERVICES[service]

                try:
                    pairs = run_hydra(ip, port_num, hydra_service, active_wordlist, timeout)
                    port_data["credential_test"] = {
                        "tested": True,
                        "weak_creds_found": len(pairs) > 0,
                        "wordlist_source": "cewl" if cewl_path and active_wordlist == cewl_path else "default",
                        "pairs": pairs
                    }
                except subprocess.TimeoutExpired:
                    print(f"  [-] Hydra timed out for {ip}:{port_num}")
                except Exception as e:
                    print(f"  [-] Hydra failed for {ip}:{port_num}: {e}")

    finally:
        if default_is_temp:
            os.unlink(default_path)

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
