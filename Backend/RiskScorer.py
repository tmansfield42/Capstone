"""
ProbePoint Risk Scorer Lambda
─────────────────────────────
Sits between the NVD-enrichment Lambda (lambda_function.py) and the
EmailTest Lambda.  Receives CVE-enriched scan data, calculates
per-host and overall risk scores using ProbePoint's five-category
weighted model, then forwards everything to EmailTest for delivery.

Pipeline position:
  Pi  →  lambda_function (NVD)  →  THIS  →  EmailTest  →  inbox
"""

import json
import logging
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ── Risk Model Weights ────────────────────────────────────────────────────────
WEIGHTS = {
    "ports":          0.30,
    "vulnerability":  0.25,
    "device":         0.15,
    "network_hygiene": 0.15,
    "behavioral":     0.10,
    # HIPAA modifier applied separately (±20%), hard-capped to 0–100
}

# ── Ports known to be high-risk when open ─────────────────────────────────────
HIGH_RISK_PORTS = {
    "21", "23", "25", "110", "135", "139", "445", "1433", "1434",
    "3306", "3389", "5432", "5900", "6379", "8080", "8443", "27017",
}

MODERATE_RISK_PORTS = {
    "53", "80", "443", "993", "995", "587", "8000", "8888",
}

# ── Device classifications by OS guess ────────────────────────────────────────
IOT_KEYWORDS = [
    "embedded", "openwrt", "dd-wrt", "mikrotik", "ubiquiti",
    "camera", "printer", "nas", "netgear", "linksys", "tp-link",
    "iot", "raspberry", "arduino", "esp32",
]

SERVER_KEYWORDS = [
    "windows server", "ubuntu", "debian", "centos", "red hat",
    "rhel", "freebsd", "linux",
]

# ══════════════════════════════════════════════════════════════════════════════
#  Component Scoring Functions
# ══════════════════════════════════════════════════════════════════════════════

def score_ports(ports: dict) -> dict:
    """
    Ports Risk (weight: 30%)
    ────────────────────────
    Scores based on how many ports are open and how risky they are.
    More high-risk open ports = higher risk score.
    """
    if not ports:
        return {"score": 0, "details": "No open ports detected"}

    total_ports = len(ports)
    high_risk_open = [p for p in ports if p in HIGH_RISK_PORTS]
    moderate_risk_open = [p for p in ports if p in MODERATE_RISK_PORTS]

    # Base: 5 points per open port, max contribution 40
    base = min(total_ports * 5, 40)

    # High-risk ports: 15 points each, max contribution 45
    high = min(len(high_risk_open) * 15, 45)

    # Moderate-risk ports: 5 points each, max contribution 15
    moderate = min(len(moderate_risk_open) * 5, 15)

    raw = min(base + high + moderate, 100)

    return {
        "score": raw,
        "total_open": total_ports,
        "high_risk_ports": high_risk_open,
        "moderate_risk_ports": moderate_risk_open,
        "details": f"{total_ports} open ports ({len(high_risk_open)} high-risk, {len(moderate_risk_open)} moderate)",
    }


def score_vulnerability(ports: dict) -> dict:
    """
    Vulnerability Risk (weight: 25%)
    ─────────────────────────────────
    Uses per-port risk_score (0–100, from NVD CVSS * 10) and CVE counts
    produced by the upstream NVD Lambda.
    """
    if not ports:
        return {"score": 0, "cve_count": 0, "details": "No services to evaluate"}

    max_risk = 0
    total_cves = 0
    critical_cves = 0
    high_cves = 0

    for port_num, port_data in ports.items():
        port_risk = port_data.get("risk_score", 0)
        if port_risk > max_risk:
            max_risk = port_risk

        for cve in port_data.get("cves", []):
            total_cves += 1
            sev = cve.get("severity", "").upper()
            if sev == "CRITICAL":
                critical_cves += 1
            elif sev == "HIGH":
                high_cves += 1

    # Weighted formula: worst single vuln drives 60%, breadth drives 40%
    breadth = min(total_cves * 3, 100)
    raw = int(max_risk * 0.6 + breadth * 0.4)
    raw = min(raw, 100)

    return {
        "score": raw,
        "cve_count": total_cves,
        "critical_cves": critical_cves,
        "high_cves": high_cves,
        "worst_cvss_x10": max_risk,
        "details": f"{total_cves} CVEs found ({critical_cves} critical, {high_cves} high). Worst CVSS×10 = {max_risk}",
    }


def score_device(os_guess: str, vendor: str | None) -> dict:
    """
    Device Risk (weight: 15%)
    ─────────────────────────
    IoT / embedded devices score highest risk.
    Unknown OS scores moderate risk (can't verify patch level).
    Servers/workstations with identifiable OS score lowest.
    """
    os_lower = (os_guess or "").lower()
    vendor_lower = (vendor or "").lower()
    combined = f"{os_lower} {vendor_lower}"

    if any(kw in combined for kw in IOT_KEYWORDS):
        return {"score": 85, "classification": "IoT / Embedded", "details": f"IoT/embedded device detected: {os_guess}"}

    if os_lower in ("", "unknown"):
        return {"score": 50, "classification": "Unknown", "details": "OS could not be identified — patch status unknown"}

    if any(kw in os_lower for kw in SERVER_KEYWORDS):
        return {"score": 20, "classification": "Server / Workstation", "details": f"Standard OS detected: {os_guess}"}

    return {"score": 35, "classification": "Other", "details": f"OS identified but not categorized: {os_guess}"}


def score_network_hygiene(ports: dict) -> dict:
    """
    Network Hygiene (weight: 15%)
    ─────────────────────────────
    Checks for weak credentials, expired/weak TLS, and cleartext services.
    """
    issues = []
    issue_score = 0

    for port_num, port_data in ports.items():
        service = port_data.get("service", "").lower()

        # ── Credential weakness ──
        # FIX: Pi sends weak_creds_found:true/pairs:[...], not status/cracked
        cred = port_data.get("credential_test", {})
        if isinstance(cred, dict):
            if cred.get("weak_creds_found") or cred.get("pairs"):
                issues.append(f"Port {port_num}: weak/default credentials")
                issue_score += 30

        # ── TLS weakness ──
        tls = port_data.get("tls", {})
        if isinstance(tls, dict):
            if tls.get("expired"):
                issues.append(f"Port {port_num}: expired TLS certificate")
                issue_score += 20
            if tls.get("self_signed"):
                issues.append(f"Port {port_num}: self-signed certificate")
                issue_score += 10
            weak_protos = [p for p in tls.get("protocols", [])
                           if p in ("SSLv2", "SSLv3", "TLSv1.0")]
            if weak_protos:
                issues.append(f"Port {port_num}: weak TLS protocols ({', '.join(weak_protos)})")
                issue_score += 15

        # ── Cleartext services ──
        if service in ("ftp", "telnet", "http", "smtp", "pop3", "imap"):
            if not tls:
                issues.append(f"Port {port_num}: cleartext {service}")
                issue_score += 10

    raw = min(issue_score, 100)

    return {
        "score": raw,
        "issues": issues,
        "details": f"{len(issues)} hygiene issues found" if issues else "No hygiene issues detected",
    }


def score_behavioral(scan_meta: dict, host_count: int) -> dict:
    """
    Behavioral Risk (weight: 10%)
    ─────────────────────────────
    Assesses network-level risk indicators:
    - Large number of hosts suggests flat network (no segmentation)
    - Missing scan metadata suggests monitoring gaps
    """
    score = 0
    notes = []

    if host_count > 20:
        score += 40
        notes.append(f"{host_count} hosts detected — likely flat network, no segmentation")
    elif host_count > 10:
        score += 20
        notes.append(f"{host_count} hosts detected — moderate network size")
    else:
        notes.append(f"{host_count} hosts detected — small network footprint")

    if not scan_meta:
        score += 30
        notes.append("No scan metadata — cannot verify scan completeness")
    else:
        if not scan_meta.get("network_range"):
            score += 15
            notes.append("No network range specified in scan metadata")

    raw = min(score, 100)
    return {
        "score": raw,
        "details": "; ".join(notes),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  HIPAA Compliance Modifier
# ══════════════════════════════════════════════════════════════════════════════

def detect_hipaa_indicators(hosts: dict) -> dict:
    """
    Looks for signs that the network may handle healthcare / PHI data.
    Returns a modifier between -20 and +20 and the reasons.
    """
    flags = []

    for ip, host_data in hosts.items():
        ports = host_data.get("ports", {})

        for port_num, port_data in ports.items():
            product = (port_data.get("product") or "").lower()

            if port_num in ("2575", "104", "11112"):
                flags.append(f"Port {port_num} on {ip}: healthcare protocol port (HL7/DICOM)")
            if any(kw in product for kw in ("hl7", "dicom", "epic", "cerner", "meditech", "allscripts")):
                flags.append(f"{ip}:{port_num} — healthcare software detected: {product}")

    if flags:
        modifier = min(len(flags) * 10, 20)
        return {"modifier": modifier, "flags": flags, "applicable": True}

    return {"modifier": 0, "flags": [], "applicable": False}


# ══════════════════════════════════════════════════════════════════════════════
#  Aggregation
# ══════════════════════════════════════════════════════════════════════════════

def calculate_host_risk(host_data: dict, scan_meta: dict, host_count: int) -> dict:
    """Calculate risk for a single host."""
    ports = host_data.get("ports", {})
    os_guess = host_data.get("os_guess", "Unknown")
    vendor = host_data.get("vendor")

    components = {
        "ports":           score_ports(ports),
        "vulnerability":   score_vulnerability(ports),
        "device":          score_device(os_guess, vendor),
        "network_hygiene": score_network_hygiene(ports),
        "behavioral":      score_behavioral(scan_meta, host_count),
    }

    weighted = sum(
        components[cat]["score"] * WEIGHTS[cat]
        for cat in WEIGHTS
    )

    return {
        "components": components,
        "weighted_score": round(weighted, 1),
    }


def calculate_network_risk(body: dict) -> dict:
    """
    Master function: scores every host, applies HIPAA modifier,
    and produces an overall network risk score.
    """
    scan_meta = body.get("scan_meta", {})
    hosts = body.get("hosts", {})
    host_count = len(hosts)

    host_scores = {}
    for ip, host_data in hosts.items():
        host_scores[ip] = calculate_host_risk(host_data, scan_meta, host_count)

    if host_scores:
        avg_score = sum(h["weighted_score"] for h in host_scores.values()) / len(host_scores)
    else:
        avg_score = 0.0

    hipaa = detect_hipaa_indicators(hosts)
    final_score = avg_score + hipaa["modifier"]
    final_score = max(0, min(100, round(final_score, 1)))

    if final_score >= 75:
        risk_tier = "CRITICAL"
    elif final_score >= 50:
        risk_tier = "HIGH"
    elif final_score >= 25:
        risk_tier = "MODERATE"
    else:
        risk_tier = "LOW"

    return {
        "overall_risk_score": final_score,
        "risk_tier":          risk_tier,
        "host_scores":        host_scores,
        "hipaa":              hipaa,
        "hosts_scanned":      host_count,
        "model_version":      "1.0",
        "weights":            WEIGHTS,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Lambda Handler
# ══════════════════════════════════════════════════════════════════════════════

def lambda_handler(event, context):
    """
    Receives the NVD-enriched payload from lambda_function.py,
    runs the risk model, merges results, and forwards to EmailTest.
    """
    if isinstance(event, str):
        body = json.loads(event)
    else:
        body = event

    logger.info(f"RiskScorer received scan with {len(body.get('hosts', {}))} hosts")

    risk_result = calculate_network_risk(body)

    logger.info(
        f"Risk calculation complete: score={risk_result['overall_risk_score']}, "
        f"tier={risk_result['risk_tier']}"
    )

    email_payload = {
        "scan_meta":    body.get("scan_meta", {}),
        "hosts":        body.get("hosts", {}),
        "vuln_db":      body.get("vuln_db", {}),
        "risk_summary": {
            "overall_risk_score": risk_result["overall_risk_score"],
            "risk_tier":          risk_result["risk_tier"],
            "hosts_scanned":      risk_result["hosts_scanned"],
            "hipaa":              risk_result["hipaa"],
            "model_version":      risk_result["model_version"],
            "weights":            risk_result["weights"],
        },
        "host_risk_scores": risk_result["host_scores"],
    }

    lambda_client = boto3.client("lambda")
    lambda_client.invoke(
        FunctionName="EmailTest",
        InvocationType="Event",
        Payload=json.dumps(email_payload).encode(),
    )

    logger.info("Payload forwarded to EmailTest Lambda")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message":            "Risk scoring complete, email triggered.",
            "overall_risk_score": risk_result["overall_risk_score"],
            "risk_tier":          risk_result["risk_tier"],
        }),
    }
