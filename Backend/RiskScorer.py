"""
ProbePoint Risk Scorer Lambda
─────────────────────────────
Sits between the NVD+EPSS-enrichment Lambda (lambda_function.py) and the
EmailTest Lambda.  Receives CVE-enriched scan data, calculates
per-host and overall risk scores using ProbePoint's five-category
weighted model, then forwards everything to EmailTest for delivery.

Pipeline position:
  Pi  →  lambda_function (NVD + EPSS)  →  THIS  →  EmailTest  →  inbox

"""

import json
import logging
from statistics import mean
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ── Risk Model Weights ────────────────────────────────────────────────────────
# v2.4: behavioral removed, its 10% merged into vulnerability. Vulnerability
# is now the dominant category (40%), which also amplifies EPSS's influence
# on host scoring since EPSS is a sub-component of the vulnerability score.
WEIGHTS = {
    "ports":           0.30,
    "vulnerability":   0.40,
    "device":          0.15,
    "network_hygiene": 0.15,
    # HIPAA modifier applied separately (percentage-based), hard-capped to 0–100
}

# ── Ports known to be high-risk when open ─────────────────────────────────────
HIGH_RISK_PORTS = {
    "21", "23", "25", "110", "135", "139", "445",
    "902", "912",
    "1433", "1434", "3306", "3389", "5432", "5900",
    "6379", "8080", "8443", "27017",
}

MODERATE_RISK_PORTS = {
    "22", "53", "80", "443",
    "587", "993", "995",
    "8000", "8888",
}

# ── Sensitive services for credential weighting ───────────────────────────────
# A credential hit on these ports is remote shell, hypervisor, SMB/AD,
# or direct DB access — treat as substantially worse than a hit on a
# general-purpose service. Used in score_network_hygiene.
SENSITIVE_CRED_SERVICES = {
    "22",            # SSH
    "3389",          # RDP
    "445", "139",    # SMB / NetBIOS
    "902", "912",    # VMware auth
    "5900",          # VNC
    "1433", "1434",  # MSSQL
    "3306",          # MySQL
    "5432",          # PostgreSQL
    "6379",          # Redis (often no-auth by default)
    "27017",         # MongoDB
}

# ── Device classifications by OS guess (fallback when no iot_classification) ──
IOT_KEYWORDS = [
    "openwrt", "dd-wrt", "mikrotik", "ubiquiti",
    "camera", "printer", "nas",
    "netgear", "linksys", "tp-link",
    "iot", "raspberry", "arduino", "esp32",
    "embedded", "lwip",
    "tuya", "hikvision", "dahua",
    "sonoff", "shelly", "tasmota",
    "ring", "wyze", "roku", "chromecast",
]

SERVER_KEYWORDS = [
    "windows server", "ubuntu", "debian",
    "centos", "red hat", "rhel",
    "freebsd", "linux",
]

LEGACY_WINDOWS_KEYWORDS = [
    "vista", "xp", "windows 7", "windows 8", "windows 10",
    "2003", "2008",
]

# ── IoT flag severity penalties for score_device ──────────────────────────────
IOT_FLAG_PENALTIES = {
    "CRITICAL": 15,
    "HIGH":     8,
    "MEDIUM":   4,
    "LOW":      1,
}

# ── CVE severity points for score_vulnerability ───────────────────────────────
CVE_SEVERITY_POINTS = {
    "CRITICAL": 18,
    "HIGH":     8,
    "MEDIUM":   2,
    "LOW":      0.5,
}

# ── Network aggregation threshold ─────────────────────────────────────────────
AT_RISK_THRESHOLD = 20  # hosts scoring above this are "at risk"

# ── Credential compromise floor ───────────────────────────────────────────────
# Any host with at least one confirmed weak-credential finding OR a CVE
# whose EPSS probability exceeds EPSS_HIGH_CONFIDENCE_THRESHOLD has its
# weighted score floored at this value. 50 corresponds to the HIGH tier
# boundary: a working attack path shouldn't ever land a host in LOW.
CREDENTIAL_COMPROMISE_FLOOR = 50.0

# ── EPSS thresholds ───────────────────────────────────────────────────────────
# 0.10 is FIRST.org's published convention for "weaponized" — roughly the
# top ~2% of CVEs, the threshold commonly used in exploit-aware
# prioritisation (e.g. CISA KEV research, industry SOC playbooks).

# 0.70 is the ProbePoint "high-confidence exploitation" floor: at this
# level, the CVE is empirically being exploited in the wild and the host
# is treated as having a confirmed attack path.

# 0.90 is the ProbePoint "critical exploitation" floor at this
# level, exploitation is empirically near-certain and the host is pinned
# into the CRITICAL tier regardless of other mitigating factors.
EPSS_WEAPONIZED_THRESHOLD       = 0.10
EPSS_HIGH_CONFIDENCE_THRESHOLD  = 0.70
EPSS_CRITICAL_THRESHOLD         = 0.90

# ── Vulnerability component blend weights (v2.2) ──────────────────────────────
# When EPSS data is available for at least one CVE on the host:
#     raw = count * V_W_COUNT + worst_cvss * V_W_CVSS + epss_component * V_W_EPSS
# When EPSS is entirely missing (outage or all CVEs absent from feed),
# the formula degrades to v2.1: count * 0.70 + worst_cvss * 0.30.
V_W_COUNT = 0.45
V_W_CVSS  = 0.25
V_W_EPSS  = 0.30

# EPSS component internal weights (combine into 0–100 sub-score)
EPSS_MAX_MULT            = 70.0   # max_epss (0–1) × 70 → 0–70 pts
EPSS_WEAPONIZED_PER_CVE  = 8.0    # each weaponized CVE (EPSS ≥ threshold) adds 8 pts
EPSS_TOP10_SUM_MULT      = 3.0    # sum of top-10 EPSS (0–10) × 3 → 0–30 pts

# ── Bad vendor detection (v2.3) ───────────────────────────────────────────────
# Two tiers of bad vendors, each adds a penalty to the device component
# score on top of the base score computed by score_device. 
#
# Tier 1 — NDAA Section 889 / FCC Covered List. These vendors are
# prohibited in US federal environments and flagged as foreign adversary
# equipment. An insurance carrier looking at a network running this
# equipment faces direct compliance risk (CMMC, FedRAMP, federal
# contracting exposure) in addition to the well-documented backdoor and
# C2 concerns in this equipment family. Penalty: 25 points.
#
# Tier 2 — Documented systemic security failures or no patch cadence.
# TP-Link is under active US government security review with a proposed
# federal sales ban; Tuya is a Chinese IoT cloud backend used by many
# white-label devices with limited patch cadence; generic Shenzhen-based
# manufacturers ship firmware that rarely receives patches. These are
# supply-chain risks without the compliance dimension. Penalty: 12 points.
BAD_VENDORS = {
    # Tier 1 — NDAA Section 889 / FCC Covered List (25 pts)
    "huawei": {
        "tier": "NDAA",
        "penalty": 25,
        "reason": "NDAA Section 889 / FCC Covered List prohibited vendor",
    },
    "zte": {
        "tier": "NDAA",
        "penalty": 25,
        "reason": "NDAA Section 889 / FCC Covered List prohibited vendor",
    },
    "hikvision": {
        "tier": "NDAA",
        "penalty": 25,
        "reason": "NDAA Section 889 / FCC Covered List prohibited equipment",
    },
    "dahua": {
        "tier": "NDAA",
        "penalty": 25,
        "reason": "NDAA Section 889 / FCC Covered List prohibited equipment",
    },
    "hytera": {
        "tier": "NDAA",
        "penalty": 25,
        "reason": "NDAA Section 889 / FCC Covered List prohibited vendor",
    },

    # Tier 2 — Systemic security failures / no patch cadence (12 pts)
    "tp-link": {
        "tier": "SYSTEMIC",
        "penalty": 12,
        "reason": "Under active US government security review, proposed federal sales ban",
    },
    "tuya": {
        "tier": "SYSTEMIC",
        "penalty": 12,
        "reason": "Chinese IoT cloud backend with limited patch cadence",
    },
    "shenzhen icomm": {
        "tier": "SYSTEMIC",
        "penalty": 12,
        "reason": "Generic Shenzhen-based IoT manufacturer with no documented patch cadence",
    },
    "shenzhen mtc": {
        "tier": "SYSTEMIC",
        "penalty": 12,
        "reason": "Generic Shenzhen-based IoT manufacturer with no documented patch cadence",
    },
}

# ── Bad vendor floor (v2.3) ───────────────────────────────────────────────────
# A host running prohibited or flagged equipment is a material risk even
# when no attack path is active. Applied the same way as the credential
# and EPSS floors. Floor value is 40, not 50, because vendor status is a
# supply chain concern rather than a confirmed active attack path
BAD_VENDOR_FLOOR = 40.0


# ── EPSS critical floor (v2.4) ────────────────────────────────────────────────
# A CVE with EPSS >= EPSS_CRITICAL_THRESHOLD (0.90) represents near-certain
# empirical exploitation in the wild. Any host carrying such a CVE has its
# weighted score floored at 75 — the CRITICAL tier boundary. This supersedes
# the 0.70 floor at 50; only "epss_critical" appears in floor_reason when
# both would apply.
EPSS_CRITICAL_FLOOR = 75.0

# ── Network critical floor (v2.4) ─────────────────────────────────────────────
# If any host in the network has "credential_compromise" or "epss_critical"
# in its floor_reason, the overall network score is floored at 75 (CRITICAL
# tier). Rationale: a confirmed active attack path on even a single host
# signals systemic exposure (lateral movement potential, patching hygiene
# failure, credential reuse risk) that underwriters must see as CRITICAL.
# The peak/breadth/average aggregation alone can let one severely compromised
# host be diluted by cleaner neighbours, landing the network in HIGH when it
# should be CRITICAL. This floor corrects that. Applied BEFORE the HIPAA
# modifier so HIPAA bonus stacks on top.
NETWORK_CRITICAL_FLOOR = 75.0


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers — EPSS accessors
# ══════════════════════════════════════════════════════════════════════════════

def _cve_epss(cve: dict) -> float | None:
    """
    Extract the EPSS probability from a CVE dict, or None if unavailable.
    Treats invalid / out-of-range values as None so the fallback path
    activates rather than silently producing bad scores.
    """
    if not isinstance(cve, dict):
        return None
    raw = cve.get("epss_score")
    if raw is None:
        return None
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return None
    if val < 0.0 or val > 1.0:
        return None
    return val


def _collect_host_epss(ports: dict) -> list[float]:
    """All valid EPSS probabilities across every CVE on this host."""
    scores: list[float] = []
    for port_data in ports.values():
        for cve in port_data.get("cves", []):
            val = _cve_epss(cve)
            if val is not None:
                scores.append(val)
    return scores


# ══════════════════════════════════════════════════════════════════════════════
#  Component Scoring Functions
# ══════════════════════════════════════════════════════════════════════════════

def score_ports(ports: dict) -> dict:
    """
    Ports Risk (weight: 30%)
    ────────────────────────
    Scores based on how many ports are open and how risky they are.
    No per-category caps — exposure accumulates proportionally.
    high=+20, moderate=+8, low=+2; only cap is final 0–100.
    """
    if not ports:
        return {"score": 0, "total_open": 0, "high_risk_ports": [],
                "moderate_risk_ports": [], "low_risk_ports": [],
                "details": "No open ports detected"}

    total_ports = len(ports)
    high_risk_open     = [p for p in ports if p in HIGH_RISK_PORTS]
    moderate_risk_open = [p for p in ports if p in MODERATE_RISK_PORTS]
    low_risk_open      = [p for p in ports if p not in HIGH_RISK_PORTS and p not in MODERATE_RISK_PORTS]

    raw = min(len(high_risk_open) * 20 + len(moderate_risk_open) * 8 + len(low_risk_open) * 2, 100)

    return {
        "score": raw,
        "total_open": total_ports,
        "high_risk_ports": high_risk_open,
        "moderate_risk_ports": moderate_risk_open,
        "low_risk_ports": low_risk_open,
        "details": (
            f"{total_ports} open ports "
            f"({len(high_risk_open)} high, {len(moderate_risk_open)} moderate, {len(low_risk_open)} low)"
        ),
    }


def score_vulnerability(ports: dict) -> dict:
    """
    Vulnerability Risk (weight: 30%)
    ─────────────────────────────────
    v2.2: 45/25/30 blend of count-based severity, worst CVSS, and EPSS
    exploitation probability. When no CVE on the host has EPSS data, the
    formula gracefully degrades to the v2.1 70/30 count/CVSS blend so an
    EPSS API outage does not deflate scores.

    Count component: CRITICAL×18 + HIGH×8 + MEDIUM×2 + LOW×0.5, capped 100
    CVSS component : worst_cvss × 10 (already 0–100 upstream)
    EPSS component : max_epss×70 + weaponized_count×8 + sum_top10_epss×3,
                     capped 100
    """
    if not ports:
        return {
            "score": 0, "cve_count": 0,
            "critical_cves": 0, "high_cves": 0, "medium_cves": 0, "low_cves": 0,
            "worst_cvss_x10": 0, "count_score": 0,
            "epss_available": False, "epss_component": 0,
            "max_epss": 0.0, "weaponized_cve_count": 0, "sum_epss_top10": 0.0,
            "details": "No services to evaluate",
        }

    max_risk      = 0
    total_cves    = 0
    critical_cves = high_cves = medium_cves = low_cves = 0

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
            elif sev == "MEDIUM":
                medium_cves += 1
            elif sev == "LOW":
                low_cves += 1
            # UNKNOWN severity CVEs are ignored

    count_score = min(
        critical_cves * CVE_SEVERITY_POINTS["CRITICAL"]
        + high_cves   * CVE_SEVERITY_POINTS["HIGH"]
        + medium_cves * CVE_SEVERITY_POINTS["MEDIUM"]
        + low_cves    * CVE_SEVERITY_POINTS["LOW"],
        100,
    )

    # ── EPSS sub-score ────────────────────────────────────────────────────────
    host_epss = _collect_host_epss(ports)
    epss_available = len(host_epss) > 0

    if epss_available:
        max_epss             = max(host_epss)
        weaponized_cve_count = sum(1 for s in host_epss if s >= EPSS_WEAPONIZED_THRESHOLD)
        top10                = sorted(host_epss, reverse=True)[:10]
        sum_epss_top10       = sum(top10)

        epss_component = min(
            max_epss             * EPSS_MAX_MULT
            + weaponized_cve_count * EPSS_WEAPONIZED_PER_CVE
            + sum_epss_top10     * EPSS_TOP10_SUM_MULT,
            100,
        )

        raw = int(round(min(
            count_score   * V_W_COUNT
            + max_risk    * V_W_CVSS
            + epss_component * V_W_EPSS,
            100,
        )))
    else:
      # fallback to old formual
        max_epss = 0.0
        weaponized_cve_count = 0
        sum_epss_top10 = 0.0
        epss_component = 0

        raw = int(round(min(count_score * 0.70 + max_risk * 0.30, 100)))

    return {
        "score":                raw,
        "cve_count":            total_cves,
        "critical_cves":        critical_cves,
        "high_cves":            high_cves,
        "medium_cves":          medium_cves,
        "low_cves":             low_cves,
        "count_score":          count_score,
        "worst_cvss_x10":       max_risk,
        "epss_available":       epss_available,
        "epss_component":       int(round(epss_component)),
        "max_epss":             round(max_epss, 5),
        "weaponized_cve_count": weaponized_cve_count,
        "sum_epss_top10":       round(sum_epss_top10, 5),
        "details": (
            f"{total_cves} CVEs ({critical_cves} critical, {high_cves} high, "
            f"{medium_cves} medium, {low_cves} low). "
            f"count_score={count_score}, worst_cvss_x10={max_risk}, "
            + (
                f"epss_component={int(round(epss_component))} "
                f"(max={max_epss:.3f}, weaponized={weaponized_cve_count}, "
                f"top10_sum={sum_epss_top10:.3f})"
                if epss_available
                else "epss=unavailable (v2.1 fallback formula applied)"
            )
        ),
    }


def _detect_bad_vendor(host_data: dict) -> dict | None:
    """
    Check a host's vendor and os_guess strings against BAD_VENDORS.
    Returns the matching entry (with 'keyword' added) when a flagged
    vendor is detected, or None when the host is clean.

    Matching is lowercase substring, applied to the concatenation of
    vendor + os_guess. This mirrors the IOT_KEYWORDS pattern and
    tolerates OUI strings like "Hikvision Digital Technology Co. Ltd."
    as well as OS banners that reveal the manufacturer.

    When more than one vendor keyword matches (rare — would require a
    device banner mentioning two manufacturers), the highest-penalty
    entry wins so the worst supply-chain risk dominates.
    """
    vendor   = host_data.get("vendor") or ""
    os_guess = host_data.get("os_guess") or ""
    combined = f"{vendor} {os_guess}".lower()

    best = None
    for keyword, entry in BAD_VENDORS.items():
        if keyword in combined:
            if best is None or entry["penalty"] > best["penalty"]:
                best = {**entry, "keyword": keyword}
    return best


def score_device(host_data: dict) -> dict:
    """
    Device Risk (weight: 15%)
    ─────────────────────────
    When iot_classification exists (from Pi-side iot_scanner.py Phase 2.5),
    uses it for precise scoring. Falls back to OS/vendor keyword matching
    for hosts without classification data.
    """
    iot_clf = host_data.get("iot_classification")
    bad_vendor = _detect_bad_vendor(host_data)

    # ── Path 1: IoT classification data exists ────────────────────────────────
    if iot_clf:
        if iot_clf.get("is_iot"):
            score = 65

            # Penalty per security flag by severity
            for flag in iot_clf.get("security_flags", []):
                sev = flag.get("severity", "").upper()
                score += IOT_FLAG_PENALTIES.get(sev, 0)

            # Confidence bonus
            confidence = iot_clf.get("confidence", "low")
            if confidence == "high":
                score += 10
            elif confidence == "medium":
                score += 5

            # Unknown device type penalty
            device_type = iot_clf.get("device_type", "Unknown IoT Device")
            if device_type == "Unknown IoT Device":
                score += 10

            # Bad vendor penalty (v2.3)
            if bad_vendor:
                score += bad_vendor["penalty"]

            score = min(score, 100)

            flag_count = iot_clf.get("flag_count", 0)
            result = {
                "score": score,
                "classification": device_type,
                "confidence": confidence,
                "flag_count": flag_count,
                "details": f"IoT device: {device_type} ({confidence} confidence, {flag_count} security flags)",
            }
            if bad_vendor:
                result["bad_vendor"]         = bad_vendor["reason"]
                result["bad_vendor_penalty"] = bad_vendor["penalty"]
                result["bad_vendor_tier"]    = bad_vendor["tier"]
                result["details"] += f"; flagged vendor (+{bad_vendor['penalty']} pts): {bad_vendor['reason']}"
            return result

        # is_iot is False but classification ran — fall through to keyword logic

    # ── Path 2: Fallback — OS/vendor keyword matching ─────────────────────────
    os_guess = host_data.get("os_guess", "")
    vendor = host_data.get("vendor", "")
    os_lower = (os_guess or "").lower()
    vendor_lower = (vendor or "").lower()
    combined = f"{os_lower} {vendor_lower}"

    # Evaluation order is critical — first match wins.
    # Legacy Windows must precede server check: "Windows Server 2008 R2"
    # matches both "2008" (legacy) and "windows server" (server) — legacy wins.

    # Priority 1: IoT / Embedded
    if any(kw in combined for kw in IOT_KEYWORDS):
        score, classification = 65, "IoT / Embedded"

    # Priority 2: Legacy Windows (including Windows 10, EOL Oct 2025)
    elif any(kw in os_lower for kw in LEGACY_WINDOWS_KEYWORDS):
        score, classification = 55, "Legacy Windows"

    # Priority 3: Unknown OS
    elif os_lower in ("", "unknown"):
        score, classification = 45, "Unknown"

    # Priority 4: Server / Workstation
    elif any(kw in os_lower for kw in SERVER_KEYWORDS):
        score, classification = 15, "Server / Workstation"

    # Priority 5: Other / Identified
    else:
        score, classification = 25, "Other / Identified"

    # Bad vendor penalty (v2.3) — applied on top of fallback base score
    if bad_vendor:
        score = min(score + bad_vendor["penalty"], 100)

    result = {
        "score": score,
        "classification": classification,
        "details": f"OS/vendor matched '{classification}': {os_guess or '(none)'}",
    }
    if bad_vendor:
        result["bad_vendor"]         = bad_vendor["reason"]
        result["bad_vendor_penalty"] = bad_vendor["penalty"]
        result["bad_vendor_tier"]    = bad_vendor["tier"]
        result["details"] += f"; flagged vendor (+{bad_vendor['penalty']} pts): {bad_vendor['reason']}"
    return result


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

        # ── Credential weakness ──────────────────────────────────────────────
        cred = port_data.get("credential_test") or {}
        if isinstance(cred, dict) and (cred.get("weak_creds_found") or cred.get("pairs")):
            pairs = cred.get("pairs") or []
            # Guard: weak_creds_found=True but empty pairs → treat as 1 finding
            pair_count = max(len(pairs), 1)
            service_mult = 1.5 if port_num in SENSITIVE_CRED_SERVICES else 1.0
            raw_bump = (25 + 10 * pair_count) * service_mult
            bump = min(raw_bump, 60)  # per-port cap

            plural = "s" if pair_count != 1 else ""
            tier_label = " [sensitive service]" if port_num in SENSITIVE_CRED_SERVICES else ""
            issues.append(
                f"Port {port_num} ({service}): weak/default credentials "
                f"— {pair_count} pair{plural} found{tier_label}"
            )
            issue_score += bump

        # ── TLS weakness ─────────────────────────────────────────────────────
        # Scanner emits boolean flags (weak_protocol, weak_cipher) plus
        # singular descriptor strings (protocol, cipher). An earlier
        # revision of this function looked for a plural "protocols" list
        # the scanner has never written, so the weak-protocol branch
        # silently scored 0. Fixed: read the actual boolean flags and
        # surface the descriptor strings in the issue text so the report
        # tells underwriters which protocol/cipher tripped the finding.
        tls = port_data.get("tls") or {}
        if isinstance(tls, dict):
            if tls.get("is_expired") or tls.get("expired"):
                issues.append(f"Port {port_num}: expired TLS certificate")
                issue_score += 25
            if tls.get("self_signed"):
                issues.append(f"Port {port_num}: self-signed certificate")
                issue_score += 12
            if tls.get("weak_protocol"):
                proto = tls.get("protocol") or "unknown"
                issues.append(f"Port {port_num}: weak TLS protocol ({proto})")
                issue_score += 20
            if tls.get("weak_cipher"):
                cipher = tls.get("cipher") or "unknown"
                issues.append(f"Port {port_num}: weak TLS cipher ({cipher})")
                issue_score += 15

        # ── Cleartext services ───────────────────────────────────────────────
        if service in ("ftp", "telnet", "http", "smtp", "pop3", "imap"):
            if not tls:
                issues.append(f"Port {port_num}: cleartext {service}")
                issue_score += 15

        # ── Web vulnerability findings (Nikto) — deduplicated per port per keyword ──
        web_vulns = port_data.get("web_vulns", [])
        if web_vulns:
            descs = " ".join(wv.get("description", "") for wv in web_vulns).lower()
            if "wp-config" in descs or "config.php" in descs:
                issues.append(f"Port {port_num}: credentials file exposed")
                issue_score += 40
            if "trace" in descs:
                issues.append(f"Port {port_num}: HTTP TRACE enabled")
                issue_score += 15
            if "x-frame-options" in descs:
                issues.append(f"Port {port_num}: missing X-Frame-Options header")
                issue_score += 5
            if "x-content-type" in descs:
                issues.append(f"Port {port_num}: missing X-Content-Type-Options header")
                issue_score += 5

    raw = min(issue_score, 100)

    return {
        "score": raw,
        "issues": issues,
        "details": f"{len(issues)} hygiene issues found" if issues else "No hygiene issues detected",
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
                flags.append(f"{ip}:{port_num} -- healthcare software detected: {product}")

    if flags:
        return {"modifier": 0, "flags": flags, "applicable": True, "flag_count": len(flags)}

    return {"modifier": 0, "flags": [], "applicable": False, "flag_count": 0}


# ══════════════════════════════════════════════════════════════════════════════
#  Aggregation
# ══════════════════════════════════════════════════════════════════════════════

def _host_has_credential_compromise(ports: dict) -> bool:
    """True if any port on the host has confirmed weak/default credentials."""
    for port_data in ports.values():
        cred = port_data.get("credential_test") or {}
        if isinstance(cred, dict) and (cred.get("weak_creds_found") or cred.get("pairs")):
            return True
    return False


def _host_has_weaponized_epss(ports: dict) -> bool:
    """True if any CVE on the host has EPSS ≥ EPSS_HIGH_CONFIDENCE_THRESHOLD."""
    for score in _collect_host_epss(ports):
        if score >= EPSS_HIGH_CONFIDENCE_THRESHOLD:
            return True
    return False


def _host_has_critical_epss(ports: dict) -> bool:
    """True if any CVE on the host has EPSS ≥ EPSS_CRITICAL_THRESHOLD (0.90)."""
    for score in _collect_host_epss(ports):
        if score >= EPSS_CRITICAL_THRESHOLD:
            return True
    return False


def calculate_host_risk(host_data: dict, scan_meta: dict, host_count: int) -> dict:
    """
    Calculate risk for a single host.

    v2: behavioral component removed (its 10% went to vulnerability, which
    now carries 40%). 
    
    New host-level floor: any CVE on the host with EPSS
    >= EPSS_CRITICAL_THRESHOLD (0.90) floors the weighted score at 75 —
    the CRITICAL tier boundary.
  
    """
    ports = host_data.get("ports", {})

    components = {
        "ports":           score_ports(ports),
        "vulnerability":   score_vulnerability(ports),
        "device":          score_device(host_data),
        "network_hygiene": score_network_hygiene(ports),
    }

    weighted = sum(
        components[cat]["score"] * WEIGHTS[cat]
        for cat in WEIGHTS
    )

    credential_compromise = _host_has_credential_compromise(ports)
    epss_critical         = _host_has_critical_epss(ports)
    epss_weaponized       = _host_has_weaponized_epss(ports)
    bad_vendor_detected   = bool(components["device"].get("bad_vendor"))

    floor_value   = 0.0
    floor_reasons = []

    if credential_compromise:
        floor_reasons.append("credential_compromise")
        floor_value = max(floor_value, CREDENTIAL_COMPROMISE_FLOOR)
    if epss_critical:
        # v2.4: supersedes the 0.70 epss_weaponized reason when both
        # apply — only the higher-tier reason goes into floor_reason.
        floor_reasons.append("epss_critical")
        floor_value = max(floor_value, EPSS_CRITICAL_FLOOR)
    elif epss_weaponized:
        floor_reasons.append("epss_weaponized")
        floor_value = max(floor_value, CREDENTIAL_COMPROMISE_FLOOR)
    if bad_vendor_detected:
        floor_reasons.append("bad_vendor")
        floor_value = max(floor_value, BAD_VENDOR_FLOOR)

    floor_applied = False
    if floor_reasons and weighted < floor_value:
        weighted      = floor_value
        floor_applied = True

    floor_reason = "+".join(floor_reasons) if floor_reasons else None

    # Convenience surfaces for the report generator
    vuln = components["vulnerability"]
    max_host_epss        = vuln.get("max_epss", 0.0)
    weaponized_cve_count = vuln.get("weaponized_cve_count", 0)

    return {
        "components":            components,
        "weighted_score":        round(weighted, 1),
        "credential_compromise": credential_compromise,
        "epss_critical":         epss_critical,
        "epss_weaponized":       epss_weaponized,
        "bad_vendor":            bad_vendor_detected,
        "floor_applied":         floor_applied,
        "floor_reason":          floor_reason,
        "max_host_epss":         max_host_epss,
        "weaponized_cve_count":  weaponized_cve_count,
    }


def calculate_network_risk(body: dict) -> dict:
    """
    Master function: scores every host, applies network-level floor and
    HIPAA modifier, and produces an overall network risk score.

    v2 aggregation:
        network_score = peak * 0.50 + breadth_ratio * 100 * 0.30
                                    + network_avg * 0.20
    Breadth is now decoupled from severity (it's a linear function of the
    at-risk host ratio, max 30 points). Severity is already captured by
    peak (50%) and network_avg (20%).

    v2 network floor: if any host has "credential_compromise" or
    "epss_critical" in its floor_reason, the network score is raised to
    NETWORK_CRITICAL_FLOOR (75) before the HIPAA modifier is applied.
    """
    scan_meta = body.get("scan_meta", {})
    hosts = body.get("hosts", {})
    iot_summary = body.get("iot_summary", {})
    host_count = len(hosts)

    host_scores = {}
    for ip, host_data in hosts.items():
        host_scores[ip] = calculate_host_risk(host_data, scan_meta, host_count)

    hipaa = detect_hipaa_indicators(hosts)

    # Surface compromised / weaponized / bad-vendor hosts for reporting
    compromised_hosts = [
        ip for ip, h in host_scores.items()
        if h.get("credential_compromise")
    ]
    weaponized_hosts = [
        ip for ip, h in host_scores.items()
        if h.get("weaponized_cve_count", 0) > 0
    ]
    epss_critical_hosts = [
        ip for ip, h in host_scores.items()
        if h.get("epss_critical")
    ]
    bad_vendor_hosts = [
        ip for ip, h in host_scores.items()
        if h.get("bad_vendor")
    ]

    # Network-wide weaponized count (any CVE with EPSS ≥ weaponized threshold)
    total_weaponized_cves = sum(
        h.get("weaponized_cve_count", 0) for h in host_scores.values()
    )
    # Whether EPSS enrichment produced any data at all this scan
    any_epss_available = any(
        h.get("components", {}).get("vulnerability", {}).get("epss_available", False)
        for h in host_scores.values()
    )

    # ── Aggregation ──────────────────────────────────────────────────────────
    # v2: breadth is now ratio-only (no at-risk-avg multiplier). Retain
    # at_risk_avg in the returned aggregation_detail so the report generator
    # can still surface "of the at-risk hosts, average severity was X" to
    # underwriters, but the number no longer dampens the breadth contribution.
    if host_scores:
        weighted_scores = [h["weighted_score"] for h in host_scores.values()]
        peak_score  = max(weighted_scores)
        network_avg = sum(weighted_scores) / len(weighted_scores)

        at_risk_scores = [s for s in weighted_scores if s > AT_RISK_THRESHOLD]
        if at_risk_scores:
            breadth_ratio = len(at_risk_scores) / len(weighted_scores)
            at_risk_avg   = mean(at_risk_scores)
        else:
            breadth_ratio = 0.0
            at_risk_avg   = 0.0  # guard: mean([]) raises StatisticsError

        # v2.4 decoupled breadth formula
        peak_contribution    = peak_score * 0.50
        breadth_contribution = breadth_ratio * 100 * 0.30
        avg_contribution     = network_avg * 0.20

        network_score_raw = peak_contribution + breadth_contribution + avg_contribution
    else:
        peak_score = network_avg = breadth_ratio = at_risk_avg = 0.0
        peak_contribution = breadth_contribution = avg_contribution = 0.0
        network_score_raw = 0.0

    # ── Network critical floor (v2.4) ────────────────────────────────────────
    # Applied BEFORE HIPAA so HIPAA bonus stacks on top of a floored score.
    network_floor_reasons = []
    if compromised_hosts:
        network_floor_reasons.append("credential_compromise")
    if epss_critical_hosts:
        network_floor_reasons.append("epss_critical")

    network_floor_applied = False
    if network_floor_reasons and network_score_raw < NETWORK_CRITICAL_FLOOR:
        network_score         = NETWORK_CRITICAL_FLOOR
        network_floor_applied = True
    else:
        network_score = network_score_raw

    network_floor_reason = "+".join(network_floor_reasons) if network_floor_reasons else None

    # ── HIPAA modifier (applied after network floor) ─────────────────────────
    flag_count       = hipaa.get("flag_count", 0)
    hipaa_percentage = min(flag_count * 0.10, 0.20)
    modifier_points  = max(0, min(network_score * hipaa_percentage, 20))
    if hipaa["applicable"]:
        hipaa["modifier"] = round(modifier_points, 1)

    final_score = max(0, min(100, round(network_score + modifier_points, 1)))

    if final_score >= 75:
        risk_tier = "CRITICAL"
    elif final_score >= 50:
        risk_tier = "HIGH"
    elif final_score >= 25:
        risk_tier = "MODERATE"
    else:
        risk_tier = "LOW"

    # Aggregation detail for the report generator — pre-floor and pre-HIPAA
    # values so the breakdown table can show each contribution transparently.
    aggregation_detail = {
        "peak_score":            round(peak_score, 1),
        "peak_contribution":     round(peak_contribution, 1),
        "breadth_ratio":         round(breadth_ratio, 3),
        "breadth_contribution":  round(breadth_contribution, 1),
        "at_risk_count":         0,  # recomputed below once host_scores is in scope
        "at_risk_avg":           round(at_risk_avg, 1),
        "network_avg":           round(network_avg, 1),
        "avg_contribution":      round(avg_contribution, 1),
        "network_score_raw":     round(network_score_raw, 1),
        "network_floor_applied": network_floor_applied,
        "network_floor_reason":  network_floor_reason,
        "network_floor_value":   NETWORK_CRITICAL_FLOOR if network_floor_applied else None,
    }
    if host_scores:
        aggregation_detail["at_risk_count"] = sum(
            1 for s in [h["weighted_score"] for h in host_scores.values()]
            if s > AT_RISK_THRESHOLD
        )

    return {
        "overall_risk_score":      final_score,
        "risk_tier":               risk_tier,
        "host_scores":             host_scores,
        "hipaa":                   hipaa,
        "iot_summary":             iot_summary,
        "hosts_scanned":           host_count,
        "compromised_hosts":       compromised_hosts,
        "compromised_count":       len(compromised_hosts),
        "weaponized_hosts":        weaponized_hosts,
        "weaponized_host_count":   len(weaponized_hosts),
        "weaponized_cve_count":    total_weaponized_cves,
        "epss_critical_hosts":     epss_critical_hosts,
        "epss_critical_count":     len(epss_critical_hosts),
        "bad_vendor_hosts":        bad_vendor_hosts,
        "bad_vendor_count":        len(bad_vendor_hosts),
        "epss_available":          any_epss_available,
        "network_floor_applied":   network_floor_applied,
        "network_floor_reason":    network_floor_reason,
        "aggregation_detail":      aggregation_detail,
        "model_version":           "2.4",
        "weights":                 WEIGHTS,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Lambda Handler
# ══════════════════════════════════════════════════════════════════════════════

def lambda_handler(event, context):
    """
    Receives the NVD+EPSS-enriched payload from lambda_function.py,
    runs the risk model, merges results, and forwards to EmailTest
    via boto3 invoke.
    """
    if isinstance(event, str):
        body = json.loads(event)
    elif isinstance(event.get("body"), str):
        body = json.loads(event["body"])
    else:
        body = event

    logger.info(f"RiskScorer received scan with {len(body.get('hosts', {}))} hosts")

    risk_result = calculate_network_risk(body)

    logger.info(
        f"Risk calculation complete: score={risk_result['overall_risk_score']}, "
        f"tier={risk_result['risk_tier']}, "
        f"compromised_hosts={risk_result['compromised_count']}, "
        f"weaponized_hosts={risk_result['weaponized_host_count']}, "
        f"weaponized_cves={risk_result['weaponized_cve_count']}, "
        f"epss_critical_hosts={risk_result['epss_critical_count']}, "
        f"bad_vendor_hosts={risk_result['bad_vendor_count']}, "
        f"network_floor_applied={risk_result['network_floor_applied']}, "
        f"epss_available={risk_result['epss_available']}"
    )

    email_payload = {
        "scan_meta":        body.get("scan_meta", {}),
        "hosts":            body.get("hosts", {}),
        "iot_summary":      body.get("iot_summary", {}),
        "risk_summary": {
            "overall_risk_score":    risk_result["overall_risk_score"],
            "risk_tier":             risk_result["risk_tier"],
            "hosts_scanned":         risk_result["hosts_scanned"],
            "hipaa":                 risk_result["hipaa"],
            "iot_summary":           risk_result["iot_summary"],
            "compromised_hosts":     risk_result["compromised_hosts"],
            "compromised_count":     risk_result["compromised_count"],
            "weaponized_hosts":      risk_result["weaponized_hosts"],
            "weaponized_host_count": risk_result["weaponized_host_count"],
            "weaponized_cve_count":  risk_result["weaponized_cve_count"],
            "epss_critical_hosts":   risk_result["epss_critical_hosts"],
            "epss_critical_count":   risk_result["epss_critical_count"],
            "bad_vendor_hosts":      risk_result["bad_vendor_hosts"],
            "bad_vendor_count":      risk_result["bad_vendor_count"],
            "epss_available":        risk_result["epss_available"],
            "network_floor_applied": risk_result["network_floor_applied"],
            "network_floor_reason":  risk_result["network_floor_reason"],
            "aggregation_detail":    risk_result["aggregation_detail"],
            "model_version":         risk_result["model_version"],
            "weights":               risk_result["weights"],
        },
        "host_risk_scores": risk_result["host_scores"],
    }

    # ── Forward to EmailTest via boto3 invoke ────────────────────────────────
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
            "message":               "Risk scoring complete, email triggered.",
            "overall_risk_score":    risk_result["overall_risk_score"],
            "risk_tier":             risk_result["risk_tier"],
            "compromised_count":     risk_result["compromised_count"],
            "weaponized_host_count": risk_result["weaponized_host_count"],
            "weaponized_cve_count":  risk_result["weaponized_cve_count"],
            "epss_critical_count":   risk_result["epss_critical_count"],
            "bad_vendor_count":      risk_result["bad_vendor_count"],
            "network_floor_applied": risk_result["network_floor_applied"],
        }),
    }
