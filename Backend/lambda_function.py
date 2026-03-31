import json
import os
import time
import logging
import urllib.request
import urllib.parse
import urllib.error

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
NVD_API_KEY  = os.environ["NVD_API_KEY"]
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_SLEEP   = 0.7  # seconds between NVD requests (~50 req/30s with key)

# ── Product → (vendor, cpe_product) map ──────────────────────────────────────
PRODUCT_MAPPING: dict[str, dict[str, str]] = {
    "apache":                        {"vendor": "apache",            "product": "http_server"},
    "http_server":                   {"vendor": "apache",            "product": "http_server"},
    "httpd":                         {"vendor": "apache",            "product": "http_server"},
    "apache2":                       {"vendor": "apache",            "product": "http_server"},
    "apache_http_server":            {"vendor": "apache",            "product": "http_server"},
    "iis":                           {"vendor": "microsoft",         "product": "internet_information_services"},
    "internet_information_services": {"vendor": "microsoft",         "product": "internet_information_services"},
    "microsoft_httpapi_httpd":       {"vendor": "microsoft",         "product": "internet_information_services"},
    "nodejs":                        {"vendor": "nodejs",            "product": "node.js"},
    "node":                          {"vendor": "nodejs",            "product": "node.js"},
    "node.js":                       {"vendor": "nodejs",            "product": "node.js"},
    "filezilla":                     {"vendor": "filezilla-project", "product": "filezilla_server"},
    "filezilla_server":              {"vendor": "filezilla-project", "product": "filezilla_server"},
    "jre":                           {"vendor": "oracle",            "product": "jre"},
    "java":                          {"vendor": "oracle",            "product": "jre"},
    "jdk":                           {"vendor": "oracle",            "product": "jdk"},
    "openjdk":                       {"vendor": "openjdk",           "product": "openjdk"},
    "mysql":                         {"vendor": "oracle",            "product": "mysql"},
    "postgresql":                    {"vendor": "postgresql",        "product": "postgresql"},
    "postgres":                      {"vendor": "postgresql",        "product": "postgresql"},
    "nginx":                         {"vendor": "f5",                "product": "nginx"},
    "php":                           {"vendor": "php",               "product": "php"},
    "tomcat":                        {"vendor": "apache",            "product": "tomcat"},
    "apache_tomcat":                 {"vendor": "apache",            "product": "tomcat"},
    "mongodb":                       {"vendor": "mongodb",           "product": "mongodb"},
    "mongo":                         {"vendor": "mongodb",           "product": "mongodb"},
    "redis":                         {"vendor": "redis",             "product": "redis"},
    "wordpress":                     {"vendor": "wordpress",         "product": "wordpress"},
    "openssl":                       {"vendor": "openssl",           "product": "openssl"},
    "python":                        {"vendor": "python",            "product": "python"},
    "openssh":                       {"vendor": "openbsd",           "product": "openssh"},
    "ssh":                           {"vendor": "openbsd",           "product": "openssh"},
    "dropbear":                      {"vendor": "matt_johnston",     "product": "dropbear_ssh"},
    "dropbear_sshd":                 {"vendor": "matt_johnston",     "product": "dropbear_ssh"},
    "vsftpd":                        {"vendor": "vsftpd_project",    "product": "vsftpd"},
    "ftp":                           {"vendor": "vsftpd_project",    "product": "vsftpd"},
    "samba":                         {"vendor": "samba",             "product": "samba"},
    "smb":                           {"vendor": "samba",             "product": "samba"},
    "proftpd":                       {"vendor": "proftpd",           "product": "proftpd"},
    "postfix":                       {"vendor": "postfix",           "product": "postfix"},
    "smtp":                          {"vendor": "postfix",           "product": "postfix"},
    "bind":                          {"vendor": "isc",               "product": "bind"},
    "named":                         {"vendor": "isc",               "product": "bind"},
    "dns":                           {"vendor": "isc",               "product": "bind"},
    "uhttpd":                        {"vendor": "openwrt",           "product": "uhttpd"},
    "openwrt_uhttpd":                {"vendor": "openwrt",           "product": "uhttpd"},
    "vmware_authentication_daemon":  {"vendor": "vmware",            "product": "esx"},
    "vmware":                        {"vendor": "vmware",            "product": "esx"},
}


# ── Helper: severity string from CVE metrics ──────────────────────────────────
def get_severity(metrics: dict) -> str:
    if metrics.get("cvssMetricV31"):
        return metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
    if metrics.get("cvssMetricV30"):
        return metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
    if metrics.get("cvssMetricV2"):
        score = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        return "LOW"
    return "UNKNOWN"


# ── Helper: base score → risk_score (0–100) ───────────────────────────────────
def get_risk_score(metrics: dict) -> int:
    base = 0.0
    if metrics.get("cvssMetricV31"):
        base = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
    elif metrics.get("cvssMetricV30"):
        base = float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])
    elif metrics.get("cvssMetricV2"):
        base = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])
    return round(base * 10)


# ── Helper: normalize product name to a lookup key ───────────────────────────
def to_lookup_key(display: str) -> str:
    import re
    return re.sub(r"[^a-z0-9_]", "", re.sub(r"\s+", "_", display.lower()))


# ── Helper: query NVD API ─────────────────────────────────────────────────────
def query_nvd(cpe_name: str) -> dict | None:
    params  = urllib.parse.urlencode({"cpeName": cpe_name, "resultsPerPage": 50})
    url     = f"{NVD_BASE_URL}?{params}"
    request = urllib.request.Request(url, headers={"apiKey": NVD_API_KEY})
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        logger.warning(f"NVD HTTP error {e.code} for {cpe_name}")
    except Exception as e:
        logger.warning(f"NVD request failed for {cpe_name}: {e}")
    return None


# ── Core: parse Pi's POST body and enrich with NVD CVE data ──────────────────
def build_vuln_report(pi_body: dict) -> dict:
    """
    Accepts the parsed JSON body exactly as the Pi POSTs it:
      {
        "scan_meta": { ... },
        "hosts": {
          "192.168.1.x": {
            "os_guess": "...",
            "ports": {
              "22": {
                "service": "ssh",
                "product": "OpenSSH",
                "version": "10.2p1 Debian 3",
                "credential_test": { ... },   <- preserved as-is
                "tls": { ... }                <- preserved as-is
              }
            }
          }
        }
      }

    Returns an enriched body dict with NVD CVE data merged into each port,
    while keeping scan_meta, credential_test, and tls fields fully intact.
    """

    scan_meta = pi_body.get("scan_meta", {})
    hosts_raw = pi_body.get("hosts", {})

    # ── Step 1: collect unique (product, version) pairs for NVD lookup ────────
    seen_pairs: set[str] = set()
    pair_list: list[dict] = []

    for ip, host_data in hosts_raw.items():
        for port_num, port_data in host_data.get("ports", {}).items():
            # Use product field; fall back to service name if product is blank
            display = port_data.get("product", "").strip()
            if not display:
                display = port_data.get("service", "").strip()
            if not display:
                continue

            version = port_data.get("version", "").strip()

            pair_key = f"{display}|||{version}"
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                lookup     = to_lookup_key(display)
                first_word = display.lower().split()[0] if display else ""
                pair_list.append({
                    "display":    display,
                    "version":    version,
                    "lookup":     lookup,
                    "first_word": first_word,
                })

    logger.info(f"Found {len(pair_list)} unique service/version pairs to look up.")

    # ── Step 2: query NVD for each pair ───────────────────────────────────────
    # vuln_db[display_lower][version] = {"risk_score": int, "cves": [...]}
    vuln_db: dict[str, dict] = {}

    for pair in pair_list:
        display    = pair["display"]
        version    = pair["version"]
        lookup     = pair["lookup"]
        first_word = pair["first_word"]
        disp_low   = display.lower()

        resolved = (
            PRODUCT_MAPPING.get(lookup)
            or PRODUCT_MAPPING.get(first_word)
            or {"vendor": first_word, "product": lookup}
        )
        vendor  = resolved["vendor"]
        product = resolved["product"]

        if not version:
            logger.info(f"[SKIP] {display} – no version detected")
            continue

        # Strip distro suffix from version string for CPE (e.g. "10.2p1 Debian 3" → "10.2p1")
        cpe_version = version.split()[0]
        cpe_name    = f"cpe:2.3:a:{vendor}:{product}:{cpe_version}:*:*:*:*:*:*:*"
        logger.info(f"Querying NVD: {display} {version}  ({cpe_name})")

        response = query_nvd(cpe_name)
        time.sleep(RATE_SLEEP)

        if not response or response.get("totalResults", 0) == 0:
            logger.info(f"  No CVEs found for {display} {version}")
            continue

        logger.info(f"  {response['totalResults']} CVE(s) found.")

        vuln_db.setdefault(disp_low, {}).setdefault(version, {"risk_score": 0, "cves": []})

        max_risk = 0
        for vuln in response.get("vulnerabilities", []):
            cve      = vuln["cve"]
            cve_id   = cve["id"]
            metrics  = cve.get("metrics", {})
            desc     = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description available."
            )
            severity = get_severity(metrics)
            risk     = get_risk_score(metrics)
            if risk > max_risk:
                max_risk = risk

            vuln_db[disp_low][version]["cves"].append({
                "cve":         cve_id,
                "severity":    severity,
                "description": desc,
            })

        vuln_db[disp_low][version]["risk_score"] = max_risk

    # ── Step 3: merge CVE data back into the Pi's original host/port structure ─
    enriched_hosts: dict[str, dict] = {}

    for ip, host_data in hosts_raw.items():
        enriched_ports: dict[str, dict] = {}

        for port_num, port_data in host_data.get("ports", {}).items():
            display  = port_data.get("product", "").strip() or port_data.get("service", "").strip()
            version  = port_data.get("version", "").strip()
            disp_low = display.lower()

            cves       = []
            risk_score = 0
            if disp_low in vuln_db and version in vuln_db[disp_low]:
                entry      = vuln_db[disp_low][version]
                cves       = entry["cves"]
                risk_score = entry["risk_score"]

            # Spread the original port_data so credential_test, tls, etc. all survive
            enriched_ports[port_num] = {
                **port_data,
                "risk_score": risk_score,
                "cves":       cves,
            }

        enriched_hosts[ip] = {
            "status":   host_data.get("status", "up"),
            "mac":      host_data.get("mac"),
            "vendor":   host_data.get("vendor"),
            "os_guess": host_data.get("os_guess", "Unknown"),
            "ports":    enriched_ports,
        }

    # ── Final body forwarded to EmailTest ─────────────────────────────────────
    return {
        "scan_meta": scan_meta,        # timestamp, pi_id, client_id, network_range, etc.
        "hosts":     enriched_hosts,   # all original port fields + risk_score + cves
        "vuln_db":   vuln_db,          # flat CVE lookup table
    }


# ── Lambda handler ────────────────────────────────────────────────────────────
def lambda_handler(event, context):
    import boto3

    raw_body = event.get("body", "{}")
    if isinstance(raw_body, str):
        pi_body = json.loads(raw_body)
    else:
        pi_body = raw_body

    body = build_vuln_report(pi_body)

    lambda_client = boto3.client("lambda")
    lambda_client.invoke(
        FunctionName="EmailTest",
        InvocationType="Event",
        Payload=json.dumps(body).encode(),
    )

    return {
        "statusCode": 200,
        "body": json.dumps({"message": "NVD scan complete, email triggered."}),
    }
