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

# Master wordlist aggregated from all hosts' CeWL runs
MASTER_WORDLIST_NAME = "cewl_master.txt"


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
# STEP 1.5: GENERATE CEWL WORDS FOR HTTP HOSTS
# ─────────────────────────────────────────────

def _host_has_http(ports):
    """Check if any open port is 80 or 443."""
    for port_num, port_data in ports.items():
        if str(port_num) in HTTP_PORTS and port_data.get("state", "").lower() == "open":
            return True
    return False


def _generate_cewl_words(ip, ports):
    """
    Runs generate_wordlist.sh against an HTTP host.
    Returns a list of words (strings), or [] on failure.

    Paths are resolved relative to this file's directory so the script
    works regardless of the working directory it is launched from.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist_script = os.path.join(script_dir, "generate_wordlist.sh")
    stopwords_path  = os.path.join(script_dir, "stopwords.txt")
    final_wordlist  = os.path.join(script_dir, "final_wordlist.txt")

    if not os.path.isfile(wordlist_script):
        print(f"  [!] generate_wordlist.sh not found at {wordlist_script}")
        return []

    if not os.path.isfile(stopwords_path):
        print(f"  [!] stopwords.txt not found at {stopwords_path}")
        return []

    # Build URL — use http:// for either port
    url = f"http://{ip}"

    print(f"  [*] Generating CeWL wordlist from {url}...")

    try:
        result = subprocess.run(
            ["sudo", "bash", wordlist_script, url],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=script_dir,
        )

        if result.returncode != 0:
            print(f"  [!] Wordlist generation failed: {result.stderr[:200]}")
            return []

        if os.path.isfile(final_wordlist) and os.path.getsize(final_wordlist) > 0:
            with open(final_wordlist, "r") as f:
                words = [line.strip() for line in f if line.strip()]
            print(f"  [+] CeWL wordlist generated: {len(words)} entries from {ip}")
            return words
        else:
            print("  [!] Wordlist script ran but produced no output")
            return []

    except subprocess.TimeoutExpired:
        print("  [!] Wordlist generation timed out (600s)")
        return []
    except Exception as e:
        print(f"  [!] Wordlist generation error: {e}")
        return []


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

    Two-pass approach:
      Pass 1 — Run CeWL against every HTTP host and aggregate all words
               into a single master wordlist (wordlists/cewl_master.txt).
               Deduplicate the master in place.
      Pass 2 — Run Hydra across all targets using the master wordlist
               (or the default wordlist if CeWL produced nothing).
    """
    with open(json_file, "r") as f:
        scan_data = json.load(f)

    hosts = scan_data.get("hosts", {})

    # Resolve the default/fallback wordlist once
    default_path, default_is_temp = _resolve_wordlist(wordlist)

    # ── Pass 1: Build CeWL master wordlist ───────────────────────────────────
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    master_path = os.path.join(script_dir, "wordlists", MASTER_WORDLIST_NAME)
    os.makedirs(os.path.dirname(master_path), exist_ok=True)

    # Clear any previous master so we don't carry over stale words
    open(master_path, "w").close()

    used_cewl = False
    for ip, host_data in hosts.items():
        ports = host_data.get("ports", {})
        if _host_has_http(ports):
            words = _generate_cewl_words(ip, ports)
            if words:
                with open(master_path, "a") as f:
                    f.write("\n".join(words) + "\n")
                used_cewl = True

    # Deduplicate master wordlist in place (preserve first-occurrence order)
    if used_cewl and os.path.getsize(master_path) > 0:
        with open(master_path, "r") as f:
            unique_words = list(dict.fromkeys(line.strip() for line in f if line.strip()))
        with open(master_path, "w") as f:
            f.write("\n".join(unique_words) + "\n")
        active_wordlist = master_path
        print(f"  [*] CeWL master wordlist: {len(unique_words)} unique entries")
    else:
        active_wordlist = default_path
        if used_cewl:
            print("  [*] CeWL ran but produced no words — falling back to default wordlist")

    # ── Pass 2: Run Hydra across all targets ─────────────────────────────────
    try:
        for ip, host_data in hosts.items():
            ports = host_data.get("ports", {})

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
                        "wordlist_source": "cewl_master" if used_cewl else "default",
                        "pairs": pairs,
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
