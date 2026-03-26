import json
import time
import urllib.request
import urllib.error


# ─────────────────────────────────────────────
# UPLOAD PAYLOAD TO AWS
# ─────────────────────────────────────────────

def upload(payload, endpoint, api_key, retry_attempts=3, retry_delay=10):
    """
    POSTs the scan payload as JSON to the AWS endpoint.

    Headers:
      Content-Type:  application/json
      Authorization: Bearer <api_key>

    Retries up to retry_attempts times on failure,
    waiting retry_delay seconds between each attempt.

    Returns True on success, False if all attempts fail.
    """
    body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url=endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type":  "application/json",
            "x-api-key": api_key
        }
    )

    for attempt in range(1, retry_attempts + 1):
        print(f"[*] Uploading to AWS (attempt {attempt}/{retry_attempts})...")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status = resp.status
                body_resp = resp.read().decode("utf-8", errors="replace")
                print(f"[+] Upload successful — HTTP {status}")
                if body_resp:
                    print(f"[+] Server response: {body_resp[:200]}")
                return True

        except urllib.error.HTTPError as e:
            print(f"[-] HTTP {e.code} from server: {e.reason}")
        except urllib.error.URLError as e:
            print(f"[-] Connection error: {e.reason}")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")

        if attempt < retry_attempts:
            print(f"[*] Retrying in {retry_delay}s...")
            time.sleep(retry_delay)

    print(f"[!] Upload failed after {retry_attempts} attempt(s).")
    return False


# ─────────────────────────────────────────────
# STANDALONE ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 uploader.py <scan_file.json> <endpoint> [api_key]")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        payload = json.load(f)

    endpoint = sys.argv[2]
    api_key  = sys.argv[3] if len(sys.argv) > 3 else ""

    success = upload(payload, endpoint, api_key)
    sys.exit(0 if success else 1)


