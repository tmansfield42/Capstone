import json
import os
import glob


# ─────────────────────────────────────────────
# COLLECT SCAN FILE
# ─────────────────────────────────────────────

def collect(scan_file):
    """
    Loads a specific scan JSON file and returns the payload dict
    ready for upload.

    Raises FileNotFoundError if the file does not exist.
    """
    print(f"[*] Collecting scan data from: {scan_file}")

    with open(scan_file, "r") as f:
        payload = json.load(f)

    hosts_found = len(payload.get("hosts", {}))
    print(f"[*] Payload ready — {hosts_found} host(s), file: {os.path.basename(scan_file)}")

    return payload


# ─────────────────────────────────────────────
# STANDALONE ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan_file = sys.argv[1]
    else:
        # Find the most recently modified scan file in the default directory
        files = glob.glob(os.path.join("scan_results", "scan_*.json"))
        if not files:
            print("No scan files found in 'scan_results'. Run the scanner first.")
            sys.exit(1)
        scan_file = max(files, key=os.path.getmtime)
    payload = collect(scan_file)
    print(json.dumps(payload, indent=2))
