"""
ProbePoint PDF Report Generator
────────────────────────────────
Generates a professional, insurance-ready PDF from a RiskScorer payload.

AI features (both via raw httpx — no pydantic/groq-SDK dependency):
  • Executive Summary "Summary" block  — plain-English overview for
    non-technical readers (underwriters, CEOs, board members).
  • Recommendations "AI Remediation Steps" block — grouped, prioritised
    action steps for technical staff.
Both blocks are silently omitted when GROQ_API_KEY is unset or the API errors.

EPSS additions:
  - Executive Summary gains a "Weaponized CVEs" metric row, shown only
    when the scan produced at least one EPSS-weaponized CVE.
  - Detailed Findings renders an [EPSS n%] badge next to each CVE when
    EPSS data is available; colour-coded red / orange / grey by tier.
  - Recommendations are re-sorted by EPSS descending first, then by
    severity/IP/port — so an EPSS-weaponized HIGH outranks a CRITICAL
    with near-zero exploitation probability.
  - Risk Score Breakdown gains a "Top Weaponized CVEs" mini-table.
  - Groq prompts receive EPSS context so AI guidance prioritises
    empirically-exploited CVEs over theoretically-severe ones.
"""

import html
import logging
import os
import uuid
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Palette ───────────────────────────────────────────────────────────────────
NAVY       = HexColor("#1B2A4A")
GREEN      = HexColor("#16A34A")
YELLOW     = HexColor("#CA8A04")
ORANGE     = HexColor("#EA580C")
RED        = HexColor("#DC2626")
WHITE      = colors.white
LIGHT_GRAY = HexColor("#F3F4F6")
DARK_GRAY  = HexColor("#374151")
MID_GRAY   = HexColor("#6B7280")

# Credential compromise callout — red accents for Executive Summary
COMPROMISE_BG     = HexColor("#FCEBEB")
COMPROMISE_BORDER = HexColor("#A32D2D")
COMPROMISE_TITLE  = HexColor("#501313")
COMPROMISE_BODY   = HexColor("#791F1F")

_SEV_HEX = {
    "CRITICAL": "#DC2626",
    "HIGH":     "#EA580C",
    "MEDIUM":   "#CA8A04",
    "LOW":      "#16A34A",
    "UNKNOWN":  "#6B7280",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# ── EPSS thresholds (kept in sync with RiskScorer.py) ─────────────────────────
EPSS_WEAPONIZED_THRESHOLD      = 0.10   # FIRST.org "actively exploited" convention
EPSS_HIGH_CONFIDENCE_THRESHOLD = 0.70   # host-level compromise floor trigger

# EPSS badge colours — red for high-confidence, orange for weaponized,
# grey for present-but-low. Absent EPSS = no badge.
_EPSS_HIGH_HEX = "#DC2626"
_EPSS_MID_HEX  = "#EA580C"
_EPSS_LOW_HEX  = "#6B7280"

TIER_RECOMMENDATIONS = {
    "LOW":      "Network posture is acceptable; continue routine monitoring and patch management.",
    "MODERATE": "Moderate risk identified; remediate flagged issues within 30 days to maintain insurability.",
    "HIGH":     "Elevated risk may affect coverage eligibility; critical findings require immediate remediation.",
    "CRITICAL": "Network posture presents unacceptable risk; coverage denial or significantly increased premiums are likely without immediate action.",
}

IOT_KEYWORDS = [
    "openwrt","dd-wrt","mikrotik","ubiquiti","camera","printer","nas",
    "netgear","linksys","tp-link","iot","raspberry","arduino","esp32",
    "embedded","lwip","tuya","hikvision","dahua","sonoff","shelly",
    "tasmota","ring","wyze","roku","chromecast",
]
SERVER_KEYWORDS = [
    "windows server","ubuntu","debian","centos","red hat","rhel","freebsd","linux",
]
LEGACY_WINDOWS_KEYWORDS = [
    "vista","xp","windows 7","windows 8","windows 10","2003","2008",
]

COMPONENT_LABELS = {
    "ports":           "Open Port Risk",
    "vulnerability":   "Vulnerability Risk",
    "device":          "Device Classification",
    "network_hygiene": "Network Hygiene",
}

MAX_AI_FINDINGS = 20


# ── Small helpers ─────────────────────────────────────────────────────────────

def _score_color(score) -> HexColor:
    s = float(score)
    if s >= 75: return RED
    if s >= 50: return ORANGE
    if s >= 25: return YELLOW
    return GREEN

def _score_hex(score) -> str:
    return "#" + _score_color(score).hexval()[2:]

def _sev_hex(severity: str) -> str:
    return _SEV_HEX.get(severity.upper(), "#6B7280")

def _cve_epss(cve: dict) -> float | None:
    """Safely extract the EPSS probability from a CVE dict (0-1), or None."""
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

def _epss_hex(epss: float) -> str:
    """Colour for EPSS badges: red high-confidence, orange weaponized, grey low."""
    if epss >= EPSS_HIGH_CONFIDENCE_THRESHOLD:
        return _EPSS_HIGH_HEX
    if epss >= EPSS_WEAPONIZED_THRESHOLD:
        return _EPSS_MID_HEX
    return _EPSS_LOW_HEX

def _epss_badge_html(cve: dict) -> str:
    """
    Inline HTML badge string for an EPSS-scored CVE, e.g. '[EPSS 94.7%]'.
    Returns empty string when EPSS data is absent — caller can concatenate
    unconditionally.
    """
    epss = _cve_epss(cve)
    if epss is None:
        return ""
    colour = _epss_hex(epss)
    pct    = epss * 100
    return f' <font color="{colour}"><b>[EPSS {pct:.1f}%]</b></font>'

def _count_weaponized_cves(hosts: dict) -> int:
    """Network-wide count of CVEs whose EPSS ≥ weaponized threshold."""
    n = 0
    for hd in hosts.values():
        for pd in hd.get("ports", {}).values():
            for cve in pd.get("cves", []):
                epss = _cve_epss(cve)
                if epss is not None and epss >= EPSS_WEAPONIZED_THRESHOLD:
                    n += 1
    return n

def _any_epss_available(hosts: dict) -> bool:
    """True if any CVE in the scan has EPSS enrichment data."""
    for hd in hosts.values():
        for pd in hd.get("ports", {}).values():
            for cve in pd.get("cves", []):
                if _cve_epss(cve) is not None:
                    return True
    return False

def _collect_top_epss_findings(hosts: dict, n: int = 10) -> list:
    """
    Top-N CVE findings across the whole network, ranked by EPSS desc.
    Returns [{"ip", "port", "cve", "severity", "epss"}, ...].
    Only includes findings with EPSS data present.
    """
    rows = []
    for ip, hd in hosts.items():
        for pnum, pd in hd.get("ports", {}).items():
            for cve in pd.get("cves", []):
                epss = _cve_epss(cve)
                if epss is None:
                    continue
                rows.append({
                    "ip":       ip,
                    "port":     str(pnum),
                    "cve":      cve.get("cve", "N/A"),
                    "severity": (cve.get("severity") or "UNKNOWN").upper(),
                    "epss":     epss,
                })
    rows.sort(key=lambda r: r["epss"], reverse=True)
    return rows[:n]

def _risk_tier_label(tier: str) -> str:
    return {"LOW":"Low Risk","MODERATE":"Moderate Risk","HIGH":"High Risk","CRITICAL":"Critical Risk"}.get((tier or "").upper(), tier)

def _infer_device_type(host_data: dict) -> str:
    iot_clf = host_data.get("iot_classification") or {}
    if iot_clf.get("is_iot"):
        dt = iot_clf.get("device_type") or ""
        return dt if dt and dt != "Unknown IoT Device" else "IoT / Embedded"
    os_guess   = host_data.get("os_guess") or ""
    vendor     = host_data.get("vendor") or ""
    if not os_guess and not vendor:
        return "Unknown"
    os_low     = os_guess.lower()
    combined   = f"{os_low} {vendor.lower()}"
    for kw in IOT_KEYWORDS:
        if kw in combined: return "IoT / Embedded"
    for kw in LEGACY_WINDOWS_KEYWORDS:
        if kw in os_low: return "Legacy Windows"
    for kw in SERVER_KEYWORDS:
        if kw in os_low: return "Server / Workstation"
    return "Other / Identified"

def _worst_severity(cves: list) -> str:
    if not cves: return ""
    return sorted(cves, key=lambda c: SEVERITY_ORDER.get(c.get("severity","UNKNOWN").upper(), 4))[0].get("severity","").upper()

def _count_findings(host_data: dict) -> tuple:
    critical = high = 0
    for pd in host_data.get("ports", {}).values():
        for cve in pd.get("cves", []):
            sev = cve.get("severity","").upper()
            if sev == "CRITICAL": critical += 1
            elif sev == "HIGH":   high += 1
    return critical, high

def _has_high_severity_findings(hosts: dict) -> bool:
    """True if any CVE in the scan is CRITICAL or HIGH severity."""
    for hd in hosts.values():
        for pd in hd.get("ports", {}).values():
            for cve in pd.get("cves", []):
                if cve.get("severity", "").upper() in ("CRITICAL", "HIGH"):
                    return True
    return False

def _count_weak_creds(hosts: dict) -> int:
    return sum(1 for hd in hosts.values() for pd in hd.get("ports",{}).values()
               if pd.get("credential_test",{}).get("weak_creds_found"))

def _count_iot_devices(hosts: dict) -> int:
    return sum(1 for hd in hosts.values() if (hd.get("iot_classification") or {}).get("is_iot"))

def _any_iot_classification(hosts: dict) -> bool:
    return any("iot_classification" in hd for hd in hosts.values())

def _count_bad_vendors(hosts: dict) -> int:
    return sum(1 for hd in hosts.values()
               if (hd.get("iot_classification") or {}).get("bad_vendor"))

def _count_tls_issues(hosts: dict) -> int:
    # Counts any port with at least one TLS finding the scanner emits.
    # weak_cipher was previously omitted, so executive-summary TLS counts
    # under-reported on hosts running modern protocols with weak ciphers
    # (RC4, 3DES, export-grade). Mirrors the flag set in score_network_hygiene.
    return sum(
        1 for hd in hosts.values() for pd in hd.get("ports",{}).values()
        if pd.get("tls") and (pd["tls"].get("is_expired") or pd["tls"].get("expired")
                              or pd["tls"].get("self_signed") or pd["tls"].get("weak_protocol")
                              or pd["tls"].get("weak_cipher"))
    )

def _collect_compromised_hosts(hosts: dict) -> list:
    """Per-host list of ports with confirmed weak creds. Empty list if none."""
    result = []
    for ip, hd in hosts.items():
        findings = []
        for pnum, pd in hd.get("ports", {}).items():
            cred = pd.get("credential_test") or {}
            if not isinstance(cred, dict): continue
            if not (cred.get("weak_creds_found") or cred.get("pairs")): continue
            pairs = cred.get("pairs") or []
            findings.append({
                "port":       str(pnum),
                "service":    pd.get("service") or "unknown",
                "pair_count": max(len(pairs), 1),
            })
        if findings:
            result.append({"ip": ip, "findings": findings})
    return result


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict:
    cover_gray  = HexColor("#CBD5E1")
    light_slate = HexColor("#94A3B8")
    return {
        "title":      ParagraphStyle("pp_title",    fontSize=38, textColor=WHITE,      fontName="Helvetica-Bold",   leading=46),
        "subtitle":   ParagraphStyle("pp_subtitle", fontSize=18, textColor=cover_gray, fontName="Helvetica",        leading=24),
        "tagline":    ParagraphStyle("pp_tagline",  fontSize=12, textColor=light_slate,fontName="Helvetica-Oblique",leading=16),
        "cover_meta": ParagraphStyle("pp_cmeta",    fontSize=13, textColor=WHITE,      fontName="Helvetica",        leading=20),
        "h1":         ParagraphStyle("pp_h1",       fontSize=20, textColor=NAVY,       fontName="Helvetica-Bold",   leading=26, spaceBefore=10),
        "h2":         ParagraphStyle("pp_h2",       fontSize=14, textColor=NAVY,       fontName="Helvetica-Bold",   leading=18, spaceBefore=8),
        "h3":         ParagraphStyle("pp_h3",       fontSize=11, textColor=DARK_GRAY,  fontName="Helvetica-Bold",   leading=15, spaceBefore=4),
        "body":       ParagraphStyle("pp_body",     fontSize=10, textColor=DARK_GRAY,  fontName="Helvetica",        leading=14),
        "small":      ParagraphStyle("pp_small",    fontSize=9,  textColor=MID_GRAY,   fontName="Helvetica",        leading=12),
        "mono":       ParagraphStyle("pp_mono",     fontSize=9,  textColor=DARK_GRAY,  fontName="Courier",          leading=13),
        "disclaimer": ParagraphStyle("pp_disc",     fontSize=9,  textColor=MID_GRAY,   fontName="Helvetica-Oblique",leading=13),
    }


# ── Canvas callbacks ──────────────────────────────────────────────────────────

def _on_first_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
    canvas.restoreState()

def _on_later_pages(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(MID_GRAY)
    canvas.drawRightString(letter[0] - 0.5*inch, 0.4*inch,
                           f"Page {doc.page}  |  ProbePoint Security Assessment — CONFIDENTIAL")
    canvas.restoreState()


# ── AI helpers (httpx — no pydantic / groq-SDK) ───────────────────────────────

def _collect_ai_findings(hosts: dict) -> list:
    """Flatten Critical/High CVEs, weak creds, TLS issues into prompt lines.

    EPSS note: when a CVE has EPSS data, the probability is appended in
    parentheses so the LLM can prioritise empirically-exploited findings
    over theoretically-severe ones. Findings are pre-sorted by EPSS desc
    so the top of the prompt is always the most urgent work.
    """
    lines = []
    cve_entries = []   # collected first so we can sort by EPSS
    other_entries = [] # weak creds / TLS — appended after CVE lines

    for ip, hd in hosts.items():
        for pnum, pd in hd.get("ports", {}).items():
            service = pd.get("service", "unknown")
            for cve in pd.get("cves", []):
                sev = cve.get("severity", "UNKNOWN").upper()
                if sev not in ("CRITICAL", "HIGH"):
                    continue
                epss = _cve_epss(cve)
                epss_tag = f" (EPSS {epss*100:.1f}%)" if epss is not None else ""
                cve_entries.append((
                    epss if epss is not None else -1.0,  # sort key
                    f"{ip} port {pnum} ({service}): {cve.get('cve','N/A')} [{sev}]{epss_tag}",
                ))
            cred = pd.get("credential_test") or {}
            if cred.get("weak_creds_found"):
                other_entries.append(f"{ip} port {pnum}: weak credentials found")
            tls = pd.get("tls") or {}
            tls_flags = []
            if tls.get("is_expired") or tls.get("expired"):
                tls_flags.append("expired certificate")
            if tls.get("self_signed"):
                tls_flags.append("self-signed certificate")
            if tls.get("weak_protocol"):
                tls_flags.append(f"weak protocol ({tls.get('protocol','')})")
            if tls.get("weak_cipher"):
                tls_flags.append(f"weak cipher ({tls.get('cipher','')})")
            if tls_flags:
                other_entries.append(f"{ip} port {pnum}: {', '.join(tls_flags)}")

    cve_entries.sort(key=lambda e: e[0], reverse=True)
    lines.extend(line for _, line in cve_entries)
    lines.extend(other_entries)
    return lines[:MAX_AI_FINDINGS]


def _groq_post(system_prompt: str, user_prompt: str, max_tokens: int) -> str | None:
    """Single reusable httpx call to Groq's OpenAI-compatible endpoint.
    Returns the response text or None on any failure.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        logging.warning("[Groq] GROQ_API_KEY not set")
        return None
    try:
        import httpx
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":      "llama-3.3-70b-versatile",
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
        }
        with httpx.Client(timeout=60) as client:
            resp = client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            result = resp.json()["choices"][0]["message"]["content"]
        print(f"[Groq] Response: {len(result)} chars")
        return result
    except Exception as exc:
        print(f"[Groq] Call failed: {type(exc).__name__}: {exc}")
        logging.error("[Groq] Call failed: %s: %s", type(exc).__name__, exc)
        return None


def _get_ai_overview(hosts: dict, risk_summary: dict) -> str | None:
    """2–3 paragraph plain-English overview for non-technical readers.
    Appears on the Executive Summary page under the stats table.
    """
    print(f"[Groq] Overview — API key present: {bool(os.environ.get('GROQ_API_KEY'))}")
    lines = _collect_ai_findings(hosts)
    if not lines:
        return None

    score = risk_summary.get("overall_risk_score", "N/A")
    tier  = (risk_summary.get("risk_tier") or "UNKNOWN").upper()

    system = (
        "You are writing a short executive overview for a business owner, CEO, or "
        "underwriter who has just received a cyber insurance risk report. The reader "
        "is NOT technical. Write 2 to 3 short paragraphs of plain prose that explain "
        "the most important problems on their network and why those problems matter for "
        "their business — for example: risk of data theft, ransomware, downtime, "
        "regulatory fines, or loss of customer trust. "
        "When the findings below include EPSS percentages, those indicate the "
        "real-world probability that the vulnerability will be exploited in the next "
        "30 days based on empirical attack data. Treat high-EPSS findings as the "
        "most urgent concerns, even if the CVSS severity is only HIGH rather than "
        "CRITICAL. Do not mention EPSS or CVSS by name — translate these into "
        "plain-English concern language. "
        "Do NOT use bullet points, numbered lists, or headings. "
        "Do NOT mention CVE IDs, port numbers, or software version numbers by name. "
        "Do NOT include remediation steps — those appear later in the report. "
        "Keep the total response under 200 words."
    )
    user = (
        f"Overall risk score: {score}/100 ({tier} tier)\n\n"
        f"Technical findings summary:\n" + "\n".join(lines)
    )
    return _groq_post(system, user, max_tokens=500)


def _get_ai_remediation(hosts: dict) -> str | None:
    """Grouped, prioritised remediation steps for technical staff.
    Sole content of the Recommendations page — the boilerplate per-CVE
    list was removed in v2.4 because the Detailed Findings section
    already enumerates every finding.
    """
    print(f"[Groq] Remediation — API key present: {bool(os.environ.get('GROQ_API_KEY'))}")
    lines = _collect_ai_findings(hosts)
    if not lines:
        return None

    system = (
        "You are a cybersecurity consultant writing remediation guidance for the IT "
        "team of a small or mid-size business. Translate the findings below into a "
        "short set of clear, prioritised action steps that a sysadmin or IT manager "
        "can actually follow. "
        "Findings with EPSS percentages shown have documented exploitation activity in "
        "the wild; prioritise these above findings without EPSS data or with low EPSS, "
        "even if the CVSS severity is only HIGH. Group findings that share the same "
        "fix (e.g. multiple Apache CVEs resolved by one version upgrade). Use numbered "
        "steps. Be specific and technical — you can name software, services, and "
        "configuration settings. Every Critical and High finding in the scan should "
        "be covered by at least one of your steps, either individually or via a group. "
        "Keep the entire response under 500 words."
    )
    user = "Provide remediation steps for these findings:\n\n" + "\n".join(lines)
    return _groq_post(system, user, max_tokens=1000)


# ── Page 1: Cover ─────────────────────────────────────────────────────────────

def _build_cover(data: dict, S: dict) -> list:
    meta        = data.get("scan_meta", {})
    client_name = meta.get("client_name", "Unknown Organization")
    network     = meta.get("network_range", "N/A")
    report_id   = meta.get("pi_id", str(uuid.uuid4())[:8].upper())
    raw_ts      = meta.get("timestamp", "")
    try:
        scan_date = datetime.fromisoformat(raw_ts).strftime("%B %d, %Y")
    except Exception:
        scan_date = raw_ts or "N/A"

    return [
        Spacer(1, 2.0*inch),
        Paragraph("ProbePoint", S["title"]),
        Spacer(1, 0.15*inch),
        Paragraph("Network Security Risk Assessment", S["subtitle"]),
        Spacer(1, 0.7*inch),
        Paragraph(f"Organization:&nbsp;&nbsp; {client_name}", S["cover_meta"]),
        Spacer(1, 0.08*inch),
        Paragraph(f"Network Scanned: {network}", S["cover_meta"]),
        Spacer(1, 0.08*inch),
        Paragraph(f"Scan Date:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; {scan_date}", S["cover_meta"]),
        Spacer(1, 0.08*inch),
        Paragraph(f"Report ID:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; {report_id}", S["cover_meta"]),
        Spacer(1, 1.4*inch),
        Paragraph("Pinpoint your vulnerabilities before attackers do.", S["tagline"]),
        PageBreak(),
    ]


# ── Page 2: Executive Summary ─────────────────────────────────────────────────

def _build_compromise_callout(hosts: dict, S: dict) -> list:
    """Red-accented callout for hosts with confirmed weak creds. [] if none."""
    compromised = _collect_compromised_hosts(hosts)
    if not compromised: return []

    host_count = len(compromised)
    plural     = "s" if host_count != 1 else ""

    title_style = ParagraphStyle("compromise_title", fontSize=12, fontName="Helvetica-Bold",
                                 textColor=COMPROMISE_TITLE, leading=15)
    body_style  = ParagraphStyle("compromise_body",  fontSize=10, fontName="Helvetica",
                                 textColor=COMPROMISE_BODY,  leading=14)
    note_style  = ParagraphStyle("compromise_note",  fontSize=9,  fontName="Helvetica-Oblique",
                                 textColor=COMPROMISE_BODY,  leading=12)

    inner = [
        Paragraph(f"Confirmed credential compromise &mdash; {host_count} host{plural}", title_style),
        Spacer(1, 0.06*inch),
    ]
    for entry in compromised:
        parts = []
        for f in entry["findings"]:
            pp = "s" if f["pair_count"] != 1 else ""
            parts.append(f"port {f['port']} ({html.escape(f['service'])}) &mdash; {f['pair_count']} pair{pp}")
        inner.append(Paragraph(
            f'<font face="Courier-Bold" color="#501313">{html.escape(entry["ip"])}</font>'
            f' &nbsp;&middot;&nbsp; {", ".join(parts)}',
            body_style,
        ))
    inner += [
        Spacer(1, 0.06*inch),
        Paragraph(
            "A working authentication bypass was observed. These hosts are treated as "
            "compromised for scoring purposes regardless of other findings.", note_style),
    ]

    callout = Table([[inner]], colWidths=[5.5*inch])
    callout.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), COMPROMISE_BG),
        ("LINEBEFORE",    (0,0),(0, -1), 4, COMPROMISE_BORDER),
        ("LEFTPADDING",   (0,0),(-1,-1), 14),
        ("RIGHTPADDING",  (0,0),(-1,-1), 12),
        ("TOPPADDING",    (0,0),(-1,-1), 10),
        ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
    ]))
    return [KeepTogether(callout), Spacer(1, 0.2*inch)]


def _build_executive_summary(data: dict, S: dict) -> list:
    risk_summary   = data.get("risk_summary", {})
    hosts          = data.get("hosts", {})
    score          = risk_summary.get("overall_risk_score")
    tier           = (risk_summary.get("risk_tier") or "").upper()
    hosts_scanned  = risk_summary.get("hosts_scanned", len(hosts))
    hipaa          = risk_summary.get("hipaa", {})

    total_critical = total_high = 0
    for hd in hosts.values():
        c, h = _count_findings(hd)
        total_critical += c
        total_high     += h

    weak_creds     = _count_weak_creds(hosts)
    tls_issues     = _count_tls_issues(hosts)
    recommendation = TIER_RECOMMENDATIONS.get(tier, "Review findings and remediate as appropriate.")

    items = [
        Paragraph("Executive Summary", S["h1"]),
        HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=12),
    ]

    if score is None:
        items += [Paragraph("Risk Score: <b>Pending</b>", S["h2"]), Spacer(1, 0.2*inch)]
    else:
        score_int = int(round(float(score)))
        sc_hex    = _score_hex(score_int)
        items += [
            Paragraph(
                f'<font color="{sc_hex}" size="64"><b>{score_int}</b></font>'
                f'<font color="#6B7280" size="18"> / 100</font>',
                ParagraphStyle("score_line", fontSize=64, leading=72, fontName="Helvetica-Bold"),
            ),
            Spacer(1, 0.05*inch),
            Paragraph(
                f'<font color="{sc_hex}"><b>{_risk_tier_label(tier)}</b></font>',
                ParagraphStyle("tier_line", fontSize=20, leading=26, fontName="Helvetica-Bold"),
            ),
            Spacer(1, 0.2*inch),
        ]

    # Credential-compromise callout (no-op when no confirmed weak creds)
    items += _build_compromise_callout(hosts, S)

    stats_rows = [
        ["Metric", "Value"],
        ["Hosts Scanned",             str(hosts_scanned)],
        ["Critical Findings",         str(total_critical)],
        ["High Findings",             str(total_high)],
        ["Default Credentials Found", str(weak_creds)],
        ["TLS / Certificate Issues",  str(tls_issues)],
    ]
    # EPSS weaponized count — shown when any EPSS data was enriched this scan.
    # A zero value is still informative (it tells the underwriter "we checked
    # exploit data and found no weaponized CVEs"), so show it whenever EPSS ran.
    if _any_epss_available(hosts):
        stats_rows.append(["Weaponized CVEs (EPSS \u2265 10%)",
                           str(_count_weaponized_cves(hosts))])
    if _any_iot_classification(hosts):
        stats_rows.append(["IoT Devices Identified", str(_count_iot_devices(hosts))])
    bad_vendor_count = _count_bad_vendors(hosts)
    if bad_vendor_count:
        stats_rows.append(["Bad Vendor Devices", str(bad_vendor_count)])
    if hipaa.get("applicable"):
        stats_rows.append(["HIPAA Modifier Applied", f"+{hipaa.get('modifier',0)} pts"])

    stats_tbl = Table(stats_rows, colWidths=[3.0*inch, 2.5*inch])
    stats_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1, 0), NAVY),
        ("TEXTCOLOR",      (0,0),(-1, 0), WHITE),
        ("FONTNAME",       (0,0),(-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0),(-1,-1), 10),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID",           (0,0),(-1,-1), 0.5, HexColor("#D1D5DB")),
        ("LEFTPADDING",    (0,0),(-1,-1), 8),
        ("RIGHTPADDING",   (0,0),(-1,-1), 8),
        ("TOPPADDING",     (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 6),
    ]))

    items += [stats_tbl, Spacer(1, 0.25*inch)]

    # ── AI plain-English overview (non-technical readers) ─────────────────────
    ai_overview = _get_ai_overview(hosts, risk_summary)
    if ai_overview:
        items.append(Paragraph("What This Means For Your Business", S["h2"]))
        items.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=8))
        items.append(Spacer(1, 0.06*inch))
        for para in ai_overview.split("\n"):
            para = para.strip()
            if para:
                items.append(Paragraph(html.escape(para), S["body"]))
                items.append(Spacer(1, 0.07*inch))
        items.append(Spacer(1, 0.15*inch))

    items += [
        Paragraph("Underwriting Recommendation", S["h2"]),
        Paragraph(recommendation, S["body"]),
        PageBreak(),
    ]
    return items


# ── Page 3: Network Overview ──────────────────────────────────────────────────

def _build_network_overview(hosts: dict, S: dict) -> list:
    items = [
        Paragraph("Network Overview", S["h1"]),
        HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=10),
        Paragraph("All hosts discovered during the scan are summarised below.", S["body"]),
        Spacer(1, 0.15*inch),
    ]

    cell_wrap = ParagraphStyle("pp_overview_cell", fontSize=9, textColor=DARK_GRAY,
                               fontName="Helvetica", leading=11)

    rows = [["IP Address","OS / Platform","Device Type","Ports","Critical","High"]]
    for ip, hd in hosts.items():
        os_guess    = hd.get("os_guess") or "Unknown"
        device_type = _infer_device_type(hd)
        port_count  = len(hd.get("ports", {}))
        c, h        = _count_findings(hd)
        rows.append([
            ip,
            Paragraph(html.escape(os_guess), cell_wrap),
            Paragraph(html.escape(device_type), cell_wrap),
            str(port_count), str(c), str(h),
        ])

    col_w = [1.15*inch, 2.4*inch, 1.25*inch, 0.65*inch, 0.65*inch, 0.65*inch]
    tbl   = Table(rows, colWidths=col_w, repeatRows=1)
    style = [
        ("BACKGROUND",     (0,0),(-1, 0), NAVY),
        ("TEXTCOLOR",      (0,0),(-1, 0), WHITE),
        ("FONTNAME",       (0,0),(-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0),(-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID",           (0,0),(-1,-1), 0.5, HexColor("#D1D5DB")),
        ("LEFTPADDING",    (0,0),(-1,-1), 6),
        ("RIGHTPADDING",   (0,0),(-1,-1), 6),
        ("TOPPADDING",     (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 5),
        ("ALIGN",          (3,0),(-1,-1), "CENTER"),
        ("VALIGN",         (0,0),(-1,-1), "MIDDLE"),
    ]
    for i, row in enumerate(rows[1:], start=1):
        if int(row[4]) > 0:
            style += [("TEXTCOLOR",(4,i),(4,i),RED),   ("FONTNAME",(4,i),(4,i),"Helvetica-Bold")]
        if int(row[5]) > 0:
            style += [("TEXTCOLOR",(5,i),(5,i),ORANGE),("FONTNAME",(5,i),(5,i),"Helvetica-Bold")]
    tbl.setStyle(TableStyle(style))
    items += [tbl, PageBreak()]
    return items


# ── Pages 4+: Detailed Findings ───────────────────────────────────────────────

def _build_detailed_findings(hosts: dict, S: dict) -> list:
    items = [
        Paragraph("Detailed Findings", S["h1"]),
        HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=10),
    ]

    for ip, hd in hosts.items():
        block = [
            Paragraph(f"Host: {ip}", S["h2"]),
            Paragraph(
                f"OS: {hd.get('os_guess') or 'Unknown'} &nbsp;|&nbsp; "
                f"Vendor: {hd.get('vendor') or 'Unknown'} &nbsp;|&nbsp; "
                f"MAC: {hd.get('mac') or 'N/A'}",
                S["small"],
            ),
            Spacer(1, 0.1*inch),
        ]

        ports = hd.get("ports", {})
        if not ports:
            block.append(Paragraph("No open ports found.", S["body"]))
            block.append(Spacer(1, 0.08*inch))
            # Fall through — IoT / bad vendor sections still render below

        if ports:
            # Ports table
            port_rows = [["Port","Service","Product / Version","Worst Severity"]]
            for pnum, pd in sorted(ports.items(), key=lambda x: int(x[0])):
                cves    = pd.get("cves", [])
                worst   = _worst_severity(cves)
                product = (pd.get("product") or "").strip()
                version = (pd.get("version") or "").strip()
                pv      = f"{product} {version}".strip()
                port_rows.append([pnum, pd.get("service",""), (pv[:36]+"…") if len(pv)>36 else pv, worst])

            pt_tbl = Table(port_rows, colWidths=[0.6*inch,1.0*inch,3.1*inch,1.0*inch], repeatRows=1)
            pt_sty = [
                ("BACKGROUND",     (0,0),(-1, 0), NAVY),
                ("TEXTCOLOR",      (0,0),(-1, 0), WHITE),
                ("FONTNAME",       (0,0),(-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",       (0,0),(-1,-1), 9),
                ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, LIGHT_GRAY]),
                ("GRID",           (0,0),(-1,-1), 0.5, HexColor("#D1D5DB")),
                ("LEFTPADDING",    (0,0),(-1,-1), 5),
                ("RIGHTPADDING",   (0,0),(-1,-1), 5),
                ("TOPPADDING",     (0,0),(-1,-1), 4),
                ("BOTTOMPADDING",  (0,0),(-1,-1), 4),
            ]
            for i, row in enumerate(port_rows[1:], start=1):
                sev = row[3].upper()
                if sev in _SEV_HEX:
                    pt_sty += [("TEXTCOLOR",(3,i),(3,i),HexColor(_SEV_HEX[sev])),
                                ("FONTNAME", (3,i),(3,i),"Helvetica-Bold")]
            pt_tbl.setStyle(TableStyle(pt_sty))
            block += [pt_tbl, Spacer(1, 0.12*inch)]

            # CVEs per port — sort by EPSS desc first, then by severity.
            for pnum, pd in sorted(ports.items(), key=lambda x: int(x[0])):
                cves = sorted(
                    pd.get("cves", []),
                    key=lambda c: (
                        -(_cve_epss(c) or -1.0),
                        SEVERITY_ORDER.get(c.get("severity","UNKNOWN").upper(), 4),
                    ),
                )
                if not cves: continue
                block.append(Paragraph(f"Port {pnum} — Vulnerabilities", S["h3"]))
                for cve in cves:
                    sev    = cve.get("severity","UNKNOWN").upper()
                    cve_id = cve.get("cve","N/A")
                    desc   = cve.get("description","")
                    epss_badge = _epss_badge_html(cve)
                    block.append(Paragraph(
                        f'<font color="{_sev_hex(sev)}"><b>[{sev}]</b></font>'
                        f'{epss_badge} '
                        f'<b>{cve_id}</b> — {desc}', S["body"]))
                    block.append(Spacer(1, 0.06*inch))

            # Credentials
            cred_lines = [
                f"Port {pnum}: {pair.get('username')}:{pair.get('password')}"
                for pnum, pd in ports.items()
                for pair in pd.get("credential_test",{}).get("pairs",[])
                if pd.get("credential_test",{}).get("weak_creds_found")
            ]
            block.append(Paragraph("Credential Testing", S["h3"]))
            if cred_lines:
                for line in cred_lines:
                    block.append(Paragraph(f'<font color="#DC2626">\u26a0 {line}</font>', S["body"]))
            else:
                block.append(Paragraph('<font color="#16A34A">No credentials compromised.</font>', S["body"]))
            block.append(Spacer(1, 0.08*inch))

            # TLS
            tls_lines = []
            for pnum, pd in ports.items():
                tls = pd.get("tls") or {}
                flags = []
                if tls.get("is_expired"):   flags.append("certificate expired")
                if tls.get("self_signed"):  flags.append("self-signed certificate")
                if tls.get("weak_protocol"):flags.append(f"weak protocol ({tls.get('protocol','?')})")
                if tls.get("weak_cipher"):  flags.append(f"weak cipher ({tls.get('cipher','?')})")
                if flags: tls_lines.append(f"Port {pnum}: {', '.join(flags)}")
            if tls_lines:
                block.append(Paragraph("TLS / Certificate Issues", S["h3"]))
                for line in tls_lines:
                    block.append(Paragraph(f'<font color="#EA580C">\u26a0 {line}</font>', S["body"]))
                block.append(Spacer(1, 0.08*inch))

            # Web vulns
            web_vulns_flat = [(pnum, wv.get("description",""))
                              for pnum, pd in ports.items()
                              for wv in pd.get("web_vulns",[])]
            if web_vulns_flat:
                block.append(Paragraph("Web Vulnerabilities", S["h3"]))
                for pnum, wv_desc in web_vulns_flat:
                    block.append(Paragraph(f'\u2022 <b>Port {pnum}:</b> {html.escape(wv_desc)}', S["small"]))
                block.append(Spacer(1, 0.08*inch))

        # ── IoT Classification (renders even for portless hosts) ─────────
        iot_clf = hd.get("iot_classification") or {}
        if iot_clf.get("is_iot"):
            block.append(Paragraph("IoT Classification", S["h3"]))
            device_type = iot_clf.get("device_type","Unknown IoT Device")
            confidence  = (iot_clf.get("confidence","low") or "low").title()
            flag_count  = iot_clf.get("flag_count", len(iot_clf.get("security_flags",[])))
            methods     = iot_clf.get("classification_methods") or iot_clf.get("methods") or []
            summary_bits = [
                f"<b>Device Type:</b> {html.escape(str(device_type))}",
                f"<b>Confidence:</b> {html.escape(confidence)}",
                f"<b>Security Flags:</b> {flag_count}",
            ]
            if methods:
                summary_bits.append(f"<b>Detected via:</b> {html.escape(', '.join(methods))}")
            block.append(Paragraph(" &nbsp;|&nbsp; ".join(summary_bits), S["body"]))
            for flag in iot_clf.get("security_flags",[]):
                sev  = (flag.get("severity") or "UNKNOWN").upper()
                desc = flag.get("description","") or flag.get("flag","")
                block.append(Paragraph(
                    f'\u2022 <font color="{_sev_hex(sev)}"><b>[{sev}]</b></font> {html.escape(str(desc))}',
                    S["small"]))
            block.append(Spacer(1, 0.08*inch))

        # ── Bad Vendor Alert (prominent callout) ─────────────────────────
        bv_flags = [f for f in iot_clf.get("security_flags", [])
                     if str(f.get("issue", "")).startswith("Bad Vendor")]
        bv_info  = iot_clf.get("bad_vendor")
        if bv_info or bv_flags:
            bv_name    = (bv_info or {}).get("display_name", "")
            bv_tier    = (bv_info or {}).get("tier", "unknown").upper()
            bv_reasons = (bv_info or {}).get("reasons", [])
            if not bv_name and bv_flags:
                issue_str = bv_flags[0].get("issue", "")
                bv_name = issue_str.replace("Bad Vendor: ", "")
                bv_tier = bv_flags[0].get("severity", "HIGH")

            tier_colors = {
                "CRITICAL": ("#FCEBEB", "#A32D2D", "#501313"),
                "HIGH":     ("#FEF3C7", "#B45309", "#78350F"),
                "MEDIUM":   ("#FEF9C3", "#A16207", "#713F12"),
            }
            bg_hex, border_hex, text_hex = tier_colors.get(bv_tier, tier_colors["HIGH"])

            bv_alert_rows = [[
                Paragraph(
                    f'<font color="{text_hex}"><b>\u26a0 Bad Vendor: {html.escape(bv_name)}</b></font>'
                    f'<br/>'
                    f'<font color="{text_hex}">Tier: <b>{bv_tier}</b></font>',
                    S["body"])
            ]]
            if bv_reasons:
                reason_text = " ".join(f"\u2022 {html.escape(r)}" for r in bv_reasons[:3])
                bv_alert_rows.append([
                    Paragraph(f'<font color="{text_hex}" size="9">{reason_text}</font>', S["small"])
                ])
            bv_tbl = Table(bv_alert_rows, colWidths=[6.0*inch])
            bv_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), HexColor(bg_hex)),
                ("BOX",           (0,0),(-1,-1), 1.5, HexColor(border_hex)),
                ("LEFTPADDING",   (0,0),(-1,-1), 10),
                ("RIGHTPADDING",  (0,0),(-1,-1), 10),
                ("TOPPADDING",    (0,0),(-1,-1), 8),
                ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ]))
            block.append(bv_tbl)
            block.append(Spacer(1, 0.08*inch))

        items.append(KeepTogether(block[:5]))
        items += block[5:]
        items.append(Spacer(1, 0.15*inch))

    items.append(PageBreak())
    return items


# ── Page 5: Risk Score Breakdown ──────────────────────────────────────────────

def _build_risk_breakdown(risk_summary: dict, host_risk_scores: dict, hosts: dict, S: dict) -> list:
    weights = risk_summary.get("weights", {})
    items   = [
        Paragraph("Risk Score Breakdown", S["h1"]),
        HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=10),
        Paragraph(
            "The overall network score uses a peak/breadth/average formula. "
            "The highest-risk host drives half the score, the proportion of "
            "at-risk hosts drives 30%, and the network-wide average contributes "
            "the remaining 20%. A network-level floor pins the score at 75 "
            "(CRITICAL) when any host shows confirmed credential compromise "
            "or empirically near-certain exploitation.",
            S["body"]),
        Spacer(1, 0.15*inch),
    ]

    # v2.4: prefer values from risk_summary.aggregation_detail when available
    # (authoritative, computed by RiskScorer). Fall back to local computation
    # for backwards compatibility with older risk_summary payloads.
    agg = risk_summary.get("aggregation_detail") or {}

    if agg:
        peak_score           = float(agg.get("peak_score", 0.0))
        peak_contribution    = float(agg.get("peak_contribution", 0.0))
        breadth_ratio        = float(agg.get("breadth_ratio", 0.0))
        breadth_contribution = float(agg.get("breadth_contribution", 0.0))
        network_avg          = float(agg.get("network_avg", 0.0))
        avg_contribution     = float(agg.get("avg_contribution", 0.0))
        network_score_raw    = float(agg.get("network_score_raw", 0.0))
        at_risk_count        = int(agg.get("at_risk_count", 0))
        network_floor_applied = bool(agg.get("network_floor_applied", False))
        network_floor_reason  = agg.get("network_floor_reason") or ""
        network_floor_value   = agg.get("network_floor_value")
    else:
        # Backwards-compat fallback (v2.3 payloads without aggregation_detail)
        AT_RISK_THRESHOLD = 20
        if host_risk_scores:
            weighted_scores = [hs.get("weighted_score",0) for hs in host_risk_scores.values()]
            peak_score  = max(weighted_scores)
            network_avg = sum(weighted_scores) / len(weighted_scores)
            at_risk_scores = [s for s in weighted_scores if s > AT_RISK_THRESHOLD]
            breadth_ratio = (len(at_risk_scores) / len(weighted_scores)) if at_risk_scores else 0.0
        else:
            peak_score = network_avg = breadth_ratio = 0.0
            at_risk_scores = []
        peak_contribution    = peak_score * 0.50
        breadth_contribution = breadth_ratio * 100 * 0.30
        avg_contribution     = network_avg * 0.20
        network_score_raw    = peak_contribution + breadth_contribution + avg_contribution
        at_risk_count        = len(at_risk_scores)
        network_floor_applied = False
        network_floor_reason  = ""
        network_floor_value   = None

    overall   = risk_summary.get("overall_risk_score", 0)
    host_count = len(host_risk_scores) if host_risk_scores else 0

    # ── Aggregation rows ─────────────────────────────────────────────────────
    agg_rows = [
        ["Aggregation Component","Value","Weight","Contribution"],
        ["Peak Host Score", f"{peak_score:.1f}", "50%", f"{peak_contribution:.1f}"],
        [f"Breadth Score ({at_risk_count} of {host_count} hosts at risk)",
         f"{int(breadth_ratio * 100)}%", "30%", f"{breadth_contribution:.1f}"],
        ["Network Average", f"{network_avg:.1f}", "20%", f"{avg_contribution:.1f}"],
    ]

    # Network critical floor row — conditional, only when triggered
    if network_floor_applied:
        # Count how many hosts triggered each condition so the underwriter
        # sees the scope at a glance. risk_summary carries these counts
        # from RiskScorer.calculate_network_risk.
        cred_count = int(risk_summary.get("compromised_count", 0))
        epss_count = int(risk_summary.get("epss_critical_count", 0))

        # Concise, non-overflowing reason text. Format per condition:
        #   cred only      → "Cred compromise on 1 host"
        #   epss only      → "Active exploit (EPSS ≥ 90%) on 2 hosts"
        #   both           → "Cred compromise + active exploit"
        if cred_count and epss_count:
            reason_text = "Cred compromise + active exploit"
        elif cred_count:
            plural = "s" if cred_count != 1 else ""
            reason_text = f"Cred compromise on {cred_count} host{plural}"
        elif epss_count:
            plural = "s" if epss_count != 1 else ""
            reason_text = f"Active exploit (EPSS \u2265 90%) on {epss_count} host{plural}"
        else:
            reason_text = "Active attack path"

        floor_val = float(network_floor_value) if network_floor_value is not None else 75.0
        # Contribution shown is the delta from the raw aggregated score up to
        # the floor value. That makes it clear to the underwriter that the
        # floor is what pushed the final number, not the weighted aggregation.
        delta = max(0.0, floor_val - network_score_raw)

        # Wrap the label in a Paragraph so the cell auto-wraps if the reason
        # text is ever longer than the column width, instead of overflowing
        # into adjacent cells. Colour matches the red highlight applied
        # below (COMPROMISE_BODY) so the row reads consistently.
        floor_label_style = ParagraphStyle(
            "pp_floor_label",
            fontSize=10,
            fontName="Helvetica-Bold",
            textColor=HexColor("#791F1F"),
            leading=12,
        )
        floor_label = Paragraph(
            f"Network Critical Floor<br/>"
            f"<font size=\"8\">({html.escape(reason_text)})</font>",
            floor_label_style,
        )
        agg_rows.append([
            floor_label,
            f"{floor_val:.0f}",
            "floor",
            f"+{delta:.1f}",
        ])

    hipaa     = risk_summary.get("hipaa", {})
    hipaa_mod = hipaa.get("modifier", 0)
    if hipaa.get("applicable") and hipaa_mod > 0:
        agg_rows.append(["HIPAA Modifier", f"+{hipaa_mod:.1f} pts", "", f"+{hipaa_mod:.1f}"])
    agg_rows.append(["Network Risk Score","","",f"{overall:.1f}"])

    n_rows  = len(agg_rows)
    agg_tbl = Table(agg_rows, colWidths=[2.8*inch,1.4*inch,0.8*inch,1.2*inch], repeatRows=1)
    agg_style = [
        ("BACKGROUND",     (0,0),(-1, 0), NAVY),
        ("TEXTCOLOR",      (0,0),(-1, 0), WHITE),
        ("FONTNAME",       (0,0),(-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0),(-1,-1), 10),
        ("ROWBACKGROUNDS", (0,1),(-1,-2), [WHITE, LIGHT_GRAY]),
        ("GRID",           (0,0),(-1,-1), 0.5, HexColor("#D1D5DB")),
        ("LEFTPADDING",    (0,0),(-1,-1), 8),
        ("RIGHTPADDING",   (0,0),(-1,-1), 8),
        ("TOPPADDING",     (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 6),
        ("ALIGN",          (1,0),(-1,-1), "CENTER"),
        ("BACKGROUND",  (0,n_rows-1),(-1,n_rows-1), NAVY),
        ("TEXTCOLOR",   (0,n_rows-1),(-1,n_rows-1), WHITE),
        ("FONTNAME",    (0,n_rows-1),(-1,n_rows-1), "Helvetica-Bold"),
    ]
    # Highlight the network floor row in red when it fires so it visually
    # stands out as an override, not a normal contribution.
    if network_floor_applied:
        # Floor row is always second-to-last before HIPAA (if HIPAA also
        # fires) or before the final Network Risk Score row. Index it by
        # counting from the end.
        floor_row_idx = n_rows - 2  # total row is n_rows-1
        if hipaa.get("applicable") and hipaa_mod > 0:
            floor_row_idx = n_rows - 3  # HIPAA row sits between floor and total
        agg_style += [
            ("BACKGROUND", (0, floor_row_idx), (-1, floor_row_idx), HexColor("#FCEBEB")),
            ("TEXTCOLOR",  (0, floor_row_idx), (-1, floor_row_idx), HexColor("#791F1F")),
            ("FONTNAME",   (0, floor_row_idx), (-1, floor_row_idx), "Helvetica-Bold"),
        ]
    agg_tbl.setStyle(TableStyle(agg_style))
    items += [agg_tbl, Spacer(1, 0.3*inch)]

    # ── Component averages ───────────────────────────────────────────────────
    items += [
        Paragraph("Component Averages Across All Hosts", S["h2"]),
        Spacer(1, 0.06*inch),
        Paragraph("Average scores per risk category across all scanned hosts. "
                  "These averages are diagnostic \u2014 the network score above is not "
                  "derived from this table.", S["small"]),
        Spacer(1, 0.1*inch),
    ]

    comp_scores = {k: [] for k in weights}
    for hs in host_risk_scores.values():
        for k in weights:
            s = hs.get("components",{}).get(k,{}).get("score")
            if s is not None: comp_scores[k].append(float(s))

    comp_rows = [["Component","Weight","Avg Score"]]
    for key, weight in weights.items():
        scores = comp_scores.get(key, [])
        avg    = sum(scores)/len(scores) if scores else 0.0
        comp_rows.append([COMPONENT_LABELS.get(key,key), f"{int(float(weight)*100)}%", f"{avg:.1f}"])

    comp_tbl = Table(comp_rows, colWidths=[2.8*inch,1.0*inch,1.0*inch], repeatRows=1)
    comp_sty = [
        ("BACKGROUND",     (0,0),(-1, 0), NAVY),
        ("TEXTCOLOR",      (0,0),(-1, 0), WHITE),
        ("FONTNAME",       (0,0),(-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0),(-1,-1), 10),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID",           (0,0),(-1,-1), 0.5, HexColor("#D1D5DB")),
        ("LEFTPADDING",    (0,0),(-1,-1), 8),("RIGHTPADDING",(0,0),(-1,-1), 8),
        ("TOPPADDING",     (0,0),(-1,-1), 6),("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("ALIGN",          (1,0),(-1,-1), "CENTER"),
    ]
    for i, row in enumerate(comp_rows[1:], start=1):
        try:
            hex_c = _score_hex(float(row[2]))
            comp_sty += [("TEXTCOLOR",(2,i),(2,i),HexColor(hex_c)),
                         ("FONTNAME", (2,i),(2,i),"Helvetica-Bold")]
        except Exception:
            pass
    comp_tbl.setStyle(TableStyle(comp_sty))
    items += [comp_tbl, Spacer(1, 0.25*inch)]

  

    # ── Top Weaponized CVEs (EPSS-ranked) ─────────────────────────────────────
    # Renders only when the scan has EPSS data. Shows the ten highest-EPSS
    # findings network-wide — directly answers "which vulnerabilities should
    # I patch first?" using empirical exploitation probability rather than
    # CVSS severity alone.
    top_epss = _collect_top_epss_findings(hosts, n=10)
    if top_epss:
        items += [
            Spacer(1, 0.3*inch),
            Paragraph("Top Weaponized CVEs (by EPSS)", S["h2"]),
            Spacer(1, 0.06*inch),
            Paragraph(
                "Vulnerabilities ranked by the probability they will be exploited "
                "within the next 30 days, based on empirical attack data from "
                "FIRST.org EPSS. These findings should be prioritised for "
                "remediation regardless of CVSS severity tier.",
                S["small"]),
            Spacer(1, 0.1*inch),
        ]
        epss_rows = [["CVE", "Host", "Port", "Severity", "EPSS"]]
        for r in top_epss:
            epss_rows.append([
                r["cve"],
                r["ip"],
                r["port"],
                r["severity"],
                f"{r['epss']*100:.1f}%",
            ])
        epss_tbl = Table(epss_rows,
                         colWidths=[1.6*inch, 1.3*inch, 0.7*inch, 1.0*inch, 0.9*inch],
                         repeatRows=1)
        epss_sty = [
            ("BACKGROUND",     (0,0),(-1, 0), NAVY),
            ("TEXTCOLOR",      (0,0),(-1, 0), WHITE),
            ("FONTNAME",       (0,0),(-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",       (0,0),(-1,-1), 9),
            ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, LIGHT_GRAY]),
            ("GRID",           (0,0),(-1,-1), 0.5, HexColor("#D1D5DB")),
            ("LEFTPADDING",    (0,0),(-1,-1), 6),("RIGHTPADDING",(0,0),(-1,-1), 6),
            ("TOPPADDING",     (0,0),(-1,-1), 4),("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("ALIGN",          (2,0),(-1,-1), "CENTER"),
        ]
        for i, r in enumerate(top_epss, start=1):
            sev_hex = _sev_hex(r["severity"])
            epss_hex = _epss_hex(r["epss"])
            epss_sty += [
                ("TEXTCOLOR", (3,i),(3,i), HexColor(sev_hex)),
                ("FONTNAME",  (3,i),(3,i), "Helvetica-Bold"),
                ("TEXTCOLOR", (4,i),(4,i), HexColor(epss_hex)),
                ("FONTNAME",  (4,i),(4,i), "Helvetica-Bold"),
            ]
        epss_tbl.setStyle(TableStyle(epss_sty))
        items.append(epss_tbl)

    items.append(PageBreak())
    return items


# ── Page 6: Recommendations ───────────────────────────────────────────────────

def _build_recommendations(hosts: dict, S: dict) -> list:
    """
    Recommendations page (v2.4 rewrite).

    The boilerplate per-CVE numbered list was removed: it was redundant with
    Detailed Findings (which enumerates every CVE with severity + EPSS badge)
    and Top Weaponized CVEs (which gives the prioritised top-ten view). The
    page now hosts AI-assisted remediation as its primary content.

    Three rendering paths:
      1. No Critical/High findings  → "No Critical or High findings identified."
      2. AI remediation succeeded  → render the AI steps as-is.
      3. AI remediation failed     → "AI recommendations unavailable. Please
                                      contact the ProbePoint team."
    """
    items = [
        Paragraph("Recommendations", S["h1"]),
        HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=10),
    ]

    if not _has_high_severity_findings(hosts):
        items.append(Paragraph("No Critical or High findings identified.", S["body"]))
        items.append(PageBreak())
        return items

    items += [
        Paragraph(
            "The following guidance groups every Critical and High severity "
            "finding into prioritised action steps for your IT team.",
            S["body"]),
        Spacer(1, 0.15*inch),
    ]

    ai_text = _get_ai_remediation(hosts)
    if ai_text:
        for para in ai_text.split("\n"):
            para = para.strip()
            if para:
                items.append(Paragraph(html.escape(para), S["body"]))
                items.append(Spacer(1, 0.07*inch))
    else:
        # Graceful fallback — surface the failure clearly rather than leaving
        # the page empty. Underwriters know who to contact.
        fallback_style = ParagraphStyle(
            "pp_ai_fallback",
            parent=S["body"],
            textColor=HexColor("#791F1F"),
            fontName="Helvetica-Bold",
        )
        items.append(Paragraph(
            "AI recommendations unavailable. Please contact the ProbePoint team.",
            fallback_style))

    items.append(PageBreak())
    return items


# ── Page 7: Appendix ─────────────────────────────────────────────────────────

def _build_appendix(scan_meta: dict, S: dict) -> list:
    items = [
        Paragraph("Appendix — Scan Metadata", S["h1"]),
        HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=10),
    ]
    meta_rows = [["Field","Value"]] + [
        [k.replace("_"," ").title(), str(v) if v is not None else "N/A"]
        for k, v in scan_meta.items()
    ]
    tbl = Table(meta_rows, colWidths=[2.0*inch, 4.0*inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1, 0), NAVY),
        ("TEXTCOLOR",      (0,0),(-1, 0), WHITE),
        ("FONTNAME",       (0,0),(-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0),(-1,-1), 10),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID",           (0,0),(-1,-1), 0.5, HexColor("#D1D5DB")),
        ("LEFTPADDING",    (0,0),(-1,-1), 8),("RIGHTPADDING",(0,0),(-1,-1), 8),
        ("TOPPADDING",     (0,0),(-1,-1), 6),("BOTTOMPADDING",(0,0),(-1,-1), 6),
    ]))
    items += [
        tbl,
        Spacer(1, 0.4*inch),
        Paragraph("Disclaimer", S["h2"]),
        Paragraph(
            "This report represents a point-in-time assessment of the network environment as of the "
            "scan date indicated above. Network conditions, software versions, and vulnerability "
            "exposure may change at any time. ProbePoint makes no warranty regarding the completeness "
            "of this assessment and recommends periodic rescanning to maintain an accurate risk profile. "
            "This report is intended for use by the named organisation and its authorised insurers only.",
            S["disclaimer"]),
    ]
    return items


# ── Public API ────────────────────────────────────────────────────────────────

def generate_report(data: dict, output_path: str) -> None:
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch,  bottomMargin=0.65*inch,
    )

    S                = _styles()
    hosts            = data.get("hosts", {})
    risk_summary     = data.get("risk_summary") or {}
    host_risk_scores = data.get("host_risk_scores") or {}
    scan_meta        = data.get("scan_meta") or {}

    story  = []
    story += _build_cover(data, S)
    story += _build_executive_summary(data, S)
    story += _build_network_overview(hosts, S)
    story += _build_detailed_findings(hosts, S)
    if risk_summary:
        story += _build_risk_breakdown(risk_summary, host_risk_scores, hosts, S)
    story += _build_recommendations(hosts, S)
    story += _build_appendix(scan_meta, S)

    doc.build(story, onFirstPage=_on_first_page, onLaterPages=_on_later_pages)
