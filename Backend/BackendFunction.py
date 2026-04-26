"""
nvd_integration.py
──────────────────────────────────────────────────────────────────────────────
Pi POST structure:
{
  "scan_meta": { "timestamp", "pi_id", "client_id", ... },
  "hosts": {
    "192.168.1.x": {
      "os_guess": "...",
      "ports": {
        "22": {
          "service": "ssh",
          "product": "OpenSSH",
          "version": "10.2p1 Debian 3",
          "credential_test": { "tested": true, "weak_creds_found": false, "pairs": [] },
          "tls": { "self_signed": true, "weak_protocol": false, ... }
        }
      },
      "iot_classification": { ... }   #  preserved through enrichment
    }
  },
  "iot_summary": { ... }             #  passed through to RiskScorer
}

Enrichment stages inside this Lambda:
    1. NVD CPE lookup per (product, version) pair    → attach CVEs to ports
    2. EPSS bulk lookup per unique CVE ID             → attach exploitation
                                                        probability to each CVE

"""

import json
import os
import time
import logging
import urllib.request
import urllib.parse
import urllib.error

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ── Config ────────────────────────────────────────────────────────────────────
NVD_API_KEY  = os.environ["NVD_API_KEY"]
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_SLEEP   = 0.7  # seconds between NVD requests (~50 req/30s with key)

# ── EPSS config ───────────────────────────────────────────────────────────────
EPSS_BASE_URL    = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE  = 100       # FIRST.org supports comma-separated bulk queries
EPSS_RATE_SLEEP  = 0.2       # gentle pacing between batches
EPSS_TIMEOUT     = 15        # per-request timeout (seconds)

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
    "orthanc":                       {"vendor": "orthanc_project",   "product": "orthanc"},
    "orthanc_server":                {"vendor": "orthanc_project",   "product": "orthanc"},
    "orthanc_dicom_server":          {"vendor": "orthanc_project",   "product": "orthanc"},
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


def fetch_full_description(cve_id: str) -> str | None:
    """
    Fetch the full description for a single CVE by ID.
    Used when the CPE-based query returns a truncated description ending with '…'.
    Returns the full English description string, or None on failure.
    """
    params  = urllib.parse.urlencode({"cveId": cve_id})
    url     = f"{NVD_BASE_URL}?{params}"
    request = urllib.request.Request(url, headers={"apiKey": NVD_API_KEY})
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            descriptions = vulns[0]["cve"].get("descriptions", [])
            return next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                None,
            )
    except Exception as e:
        logger.warning(f"Failed to fetch full description for {cve_id}: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  EPSS enrichment
# ══════════════════════════════════════════════════════════════════════════════

def query_epss_batch(cve_ids: list[str]) -> dict[str, dict[str, float]]:
    """
    Query FIRST.org EPSS API for up to EPSS_BATCH_SIZE CVEs at once.

    Returns a mapping of cve_id → {"epss": float, "percentile": float}.
    CVEs not present in EPSS (too new, reserved, or disputed) are simply
    absent from the returned map. Any network or parse failure returns {}
    — the caller must treat a missing key as "no EPSS data available",
    NOT as "EPSS = 0".
    """
    if not cve_ids:
        return {}

    params  = urllib.parse.urlencode({"cve": ",".join(cve_ids)})
    url     = f"{EPSS_BASE_URL}?{params}"
    request = urllib.request.Request(url)

    try:
        with urllib.request.urlopen(request, timeout=EPSS_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        logger.warning(f"EPSS HTTP error {e.code} for batch of {len(cve_ids)}")
        return {}
    except Exception as e:
        logger.warning(f"EPSS request failed for batch of {len(cve_ids)}: {e}")
        return {}

    result: dict[str, dict[str, float]] = {}
    for entry in body.get("data", []):
        cve_id = entry.get("cve")
        if not cve_id:
            continue
        try:
            result[cve_id] = {
                "epss":       float(entry.get("epss", 0.0)),
                "percentile": float(entry.get("percentile", 0.0)),
            }
        except (TypeError, ValueError):
            # Malformed row from the feed — skip rather than crash
            continue
    return result


def enrich_with_epss(vuln_db: dict) -> dict:
    """
    Walk every CVE in the vuln_db, collect unique CVE IDs, fetch EPSS scores
    in batches of EPSS_BATCH_SIZE, and attach epss_score / epss_percentile
    fields in-place on each CVE dict.

    Mutates and returns vuln_db for convenience. Returns the same dict even
    when EPSS lookups fail across the board — enrichment is best-effort.
    """
    # Collect unique CVE IDs across every product/version entry
    unique_cves: set[str] = set()
    for versions in vuln_db.values():
        for ver_data in versions.values():
            for cve in ver_data.get("cves", []):
                cve_id = cve.get("cve")
                if cve_id and cve_id.startswith("CVE-"):
                    unique_cves.add(cve_id)

    if not unique_cves:
        logger.info("EPSS: no CVE IDs to enrich")
        return vuln_db

    logger.info(f"EPSS: enriching {len(unique_cves)} unique CVE IDs")

    # Batch-query FIRST.org
    epss_map: dict[str, dict[str, float]] = {}
    cve_list = sorted(unique_cves)
    for i in range(0, len(cve_list), EPSS_BATCH_SIZE):
        batch = cve_list[i : i + EPSS_BATCH_SIZE]
        batch_result = query_epss_batch(batch)
        epss_map.update(batch_result)
        if i + EPSS_BATCH_SIZE < len(cve_list):
            time.sleep(EPSS_RATE_SLEEP)

    logger.info(
        f"EPSS: received scores for {len(epss_map)} of {len(unique_cves)} CVEs "
        f"({len(unique_cves) - len(epss_map)} missing from feed)"
    )

    # Attach EPSS fields to every CVE entry that has a match
    for versions in vuln_db.values():
        for ver_data in versions.values():
            for cve in ver_data.get("cves", []):
                cve_id = cve.get("cve")
                if cve_id and cve_id in epss_map:
                    cve["epss_score"]      = epss_map[cve_id]["epss"]
                    cve["epss_percentile"] = epss_map[cve_id]["percentile"]

    return vuln_db


# ══════════════════════════════════════════════════════════════════════════════
#  Core: parse Pi's POST body and enrich with NVD + EPSS
# ══════════════════════════════════════════════════════════════════════════════

def build_vuln_report(pi_body: dict) -> dict:
    """
    Accepts the parsed JSON body exactly as the Pi POSTs it.
    Returns an enriched body dict with NVD CVE data and EPSS scores merged
    into each port, while keeping scan_meta, credential_test, tls, and
    iot_classification fields fully intact.
    """

    scan_meta   = pi_body.get("scan_meta", {})
    hosts_raw   = pi_body.get("hosts", {})
    iot_summary = pi_body.get("iot_summary", {})

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
            logger.info(f"[SKIP] {display} -- no version detected")
            continue

        # Strip distro suffix from version string for CPE (e.g. "10.2p1 Debian 3" -> "10.2p1")
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
            if desc.endswith("…") or desc.endswith("..."):
                time.sleep(RATE_SLEEP)
                full = fetch_full_description(cve_id)
                if full:
                    desc = full
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

    # ──  EPSS enrichment across the whole vuln_db ─────────────────────
    enrich_with_epss(vuln_db)

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

            enriched_ports[port_num] = {
                **port_data,
                "risk_score": risk_score,
                "cves":       cves,
            }

        # Spread entire host_data to preserve iot_classification and any other keys,
        # then override ports with the enriched version
        enriched_hosts[ip] = {
            **host_data,
            "ports": enriched_ports,
        }

    # ── Final body forwarded to RiskScorer ────────────────────────────────────
    return {
        "scan_meta":   scan_meta,
        "hosts":       enriched_hosts,
        "iot_summary": iot_summary,
        "vuln_db":     vuln_db,
    }


# ── Lambda handler ────────────────────────────────────────────────────────────
def lambda_handler(event, context):
    import boto3

    # ── Fast path: called from API Gateway ───────────────────────────────────
    # API Gateway has a hard 29-second timeout. NVD + EPSS enrichment takes
    # longer than that, so we must not do the work while API Gateway is waiting.
    # Instead: immediately invoke this same function asynchronously (fire-and-
    # forget), return 200 to the NUC right away, and let the async invocation
    # carry out the full pipeline with no timeout pressure.
    #
    # API Gateway events always carry either "httpMethod" (REST API) or
    # "requestContext" with an "http" sub-key (HTTP API / payload format 2.0).
    # Direct Lambda-to-Lambda invocations set neither, so the async invocation
    # falls through to the slow path below without looping back.
    is_apigw = "httpMethod" in event or (
        "requestContext" in event and "http" in event.get("requestContext", {})
    )

    if is_apigw:
        logger.info("API Gateway trigger detected — dispatching async self-invoke and returning 200.")
        boto3.client("lambda").invoke(
            FunctionName=context.function_name,
            InvocationType="Event",          # async, no waiting for response
            Payload=json.dumps({
                "body":   event.get("body", "{}"),
                "_async": True,              # sentinel so slow path can log it
            }).encode(),
        )
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Scan received. Processing started."}),
        }

    # ── Slow path: async self-invocation or direct test invoke ────────────────
    if event.get("_async"):
        logger.info("Async processing invocation (API Gateway already responded).")

    raw_body = event.get("body", "{}")
    logger.info(f"Raw body length: {len(raw_body)} chars")

    if isinstance(raw_body, str):
        pi_body = json.loads(raw_body)
    else:
        pi_body = raw_body

    logger.info(f"Hosts in parsed body: {list(pi_body.get('hosts', {}).keys())}")

    body = build_vuln_report(pi_body)

    # ── Forward to RiskScorer via boto3 invoke ───────────────────────────────
    lambda_client = boto3.client("lambda")
    lambda_client.invoke(
        FunctionName="RiskScorer",
        InvocationType="Event",
        Payload=json.dumps(body).encode(),
    )

    logger.info("Payload forwarded to RiskScorer Lambda")
