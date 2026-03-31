
import json
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# ── Severity sort order ───────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# ── Build plain-text email body ───────────────────────────────────────────────
def format_report(event: dict) -> tuple[str, str]:
    """
    Returns (subject, body) as plain text strings.
    """
    scan_meta    = event.get("scan_meta", {})
    hosts        = event.get("hosts", {})

    client_name  = scan_meta.get("client_name", "Unknown Client")
    network      = scan_meta.get("network_range", "Unknown Range")
    pi_id        = scan_meta.get("pi_id", "Unknown Pi")
    timestamp    = scan_meta.get("timestamp", "Unknown Time")
    hosts_found  = scan_meta.get("hosts_found", len(hosts))

    # ── Collect summary stats ─────────────────────────────────────────────────
    total_cves         = 0
    total_weak_creds   = 0
    total_tls_issues   = 0
    severity_counts    = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for host_data in hosts.values():
        for port_data in host_data.get("ports", {}).values():
            cves = port_data.get("cves", [])
            total_cves += len(cves)
            for cve in cves:
                sev = cve.get("severity", "UNKNOWN")
                if sev in severity_counts:
                    severity_counts[sev] += 1

            cred = port_data.get("credential_test", {})
            if cred.get("weak_creds_found"):
                total_weak_creds += 1

            tls = port_data.get("tls", {})
            if tls:
                if tls.get("self_signed") or tls.get("weak_protocol") or tls.get("weak_cipher") or tls.get("is_expired"):
                    total_tls_issues += 1

    # ── Subject line ──────────────────────────────────────────────────────────
    if severity_counts["CRITICAL"] > 0:
        risk_label = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        risk_label = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        risk_label = "MEDIUM"
    else:
        risk_label = "LOW"

    subject = f"[{risk_label}] Vulnerability Scan Report — {client_name} — {timestamp[:10]}"

    # ── Build body ────────────────────────────────────────────────────────────
    lines = []

    lines.append("=" * 70)
    lines.append("  NETWORK VULNERABILITY SCAN REPORT")
    lines.append("=" * 70)
    lines.append(f"  Client      : {client_name}")
    lines.append(f"  Network     : {network}")
    lines.append(f"  Scan Time   : {timestamp}")
    lines.append(f"  Pi ID       : {pi_id}")
    lines.append(f"  Hosts Found : {hosts_found}")
    lines.append("")

    # ── Executive summary ─────────────────────────────────────────────────────
    lines.append("  EXECUTIVE SUMMARY")
    lines.append("-" * 70)
    lines.append(f"  Total CVEs Found    : {total_cves}")
    lines.append(f"    Critical          : {severity_counts['CRITICAL']}")
    lines.append(f"    High              : {severity_counts['HIGH']}")
    lines.append(f"    Medium            : {severity_counts['MEDIUM']}")
    lines.append(f"    Low               : {severity_counts['LOW']}")
    lines.append(f"  Weak Credentials    : {total_weak_creds} port(s)")
    lines.append(f"  TLS Issues          : {total_tls_issues} port(s)")
    lines.append("")

    # ── Weak credentials callout ──────────────────────────────────────────────
    weak_cred_ports = []
    for ip, host_data in hosts.items():
        for port_num, port_data in host_data.get("ports", {}).items():
            cred = port_data.get("credential_test", {})
            if cred.get("weak_creds_found"):
                pairs = cred.get("pairs", [])
                for pair in pairs:
                    weak_cred_ports.append(
                        f"  {ip}:{port_num} ({port_data.get('service','')}) "
                        f"— user: {pair.get('username','')}  pass: {pair.get('password','')}"
                    )

    if weak_cred_ports:
        lines.append("  !! WEAK CREDENTIALS DETECTED !!")
        lines.append("-" * 70)
        for entry in weak_cred_ports:
            lines.append(entry)
        lines.append("")

    # ── Per-host detail ───────────────────────────────────────────────────────
    lines.append("  HOST DETAILS")
    lines.append("=" * 70)

    for ip, host_data in sorted(hosts.items()):
        os_guess = host_data.get("os_guess", "Unknown")
        vendor   = host_data.get("vendor") or "Unknown"
        mac      = host_data.get("mac") or "Unknown"

        lines.append(f"\n  Host    : {ip}")
        lines.append(f"  OS      : {os_guess}")
        lines.append(f"  Vendor  : {vendor}")
        lines.append(f"  MAC     : {mac}")
        lines.append("")

        ports = host_data.get("ports", {})
        if not ports:
            lines.append("    No open ports detected.")
            continue

        for port_num, port_data in sorted(ports.items(), key=lambda x: int(x[0])):
            service  = port_data.get("service", "")
            product  = port_data.get("product", "") or service
            version  = port_data.get("version", "") or "unknown version"
            risk     = port_data.get("risk_score", 0)
            cves     = port_data.get("cves", [])
            state    = port_data.get("state", "open")
            protocol = port_data.get("protocol", "tcp")

            lines.append(f"  Port {port_num}/{protocol} — {state}")
            lines.append(f"    Service    : {product} {version}".rstrip())
            lines.append(f"    Risk Score : {risk}/100")

            # TLS info
            tls = port_data.get("tls")
            if tls:
                tls_flags = []
                if tls.get("self_signed"):
                    tls_flags.append("self-signed cert")
                if tls.get("weak_protocol"):
                    tls_flags.append(f"weak protocol ({tls.get('protocol','')})")
                if tls.get("weak_cipher"):
                    tls_flags.append(f"weak cipher ({tls.get('cipher','')})")
                if tls.get("is_expired"):
                    tls_flags.append("EXPIRED cert")
                expiry = tls.get("days_until_expiry")
                if expiry is not None:
                    tls_flags.append(f"{expiry}d until expiry")

                if tls_flags:
                    lines.append(f"    TLS        : {', '.join(tls_flags)}")
                else:
                    lines.append(f"    TLS        : OK ({tls.get('protocol','')} / {tls.get('cipher','')})")

            # Credential test info
            cred = port_data.get("credential_test")
            if cred and cred.get("tested"):
                if cred.get("weak_creds_found"):
                    pairs = cred.get("pairs", [])
                    pair_str = ", ".join(f"{p['username']}:{p['password']}" for p in pairs)
                    lines.append(f"    Creds      : !! WEAK — {pair_str}")
                else:
                    lines.append(f"    Creds      : Tested, none found")

            # CVEs
            if cves:
                sorted_cves = sorted(cves, key=lambda c: SEVERITY_ORDER.get(c.get("severity", "UNKNOWN"), 9))
                lines.append(f"    CVEs ({len(cves)}):")
                for cve in sorted_cves:
                    cve_id = cve.get("cve", "")
                    sev    = cve.get("severity", "UNKNOWN")
                    desc   = cve.get("description", "No description.")
                    # Truncate long descriptions
                    if len(desc) > 120:
                        desc = desc[:117] + "..."
                    lines.append(f"      [{sev}] {cve_id}")
                    lines.append(f"        {desc}")
            else:
                lines.append("    CVEs       : None found")

            lines.append("")

    # ── Footer ────────────────────────────────────────────────────────────────
    lines.append("=" * 70)
    lines.append("  Generated by ProbePoint automated scan system.")
    lines.append("=" * 70)

    return subject, "\n".join(lines)


# ── Lambda handler ────────────────────────────────────────────────────────────
def lambda_handler(event, context):
    gmail_address    = os.environ["GMAIL_ADDRESS"]
    gmail_password   = os.environ["GMAIL_APP_PASSWORD"]
    recipient        = os.environ["RECIPIENT_EMAIL"]

    subject, body = format_report(event)

    msg = MIMEMultipart()
    msg["From"]    = gmail_address
    msg["To"]      = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(gmail_address, gmail_password)
            server.sendmail(gmail_address, recipient, msg.as_string())

        return {
            "statusCode": 200,
            "body": json.dumps({"message": f"Report sent to {recipient}"})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
