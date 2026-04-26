"""
ProbePoint EmailTest Lambda
───────────────────────────
Receives a fully-scored payload from RiskScorer.py, generates the PDF report via
report_generator.generate_report(), and emails it over Gmail SMTP.

Pipeline position:
  Pi → lambda_function (NVD + EPSS) → RiskScorer → THIS → inbox

Environment variables required:
  GMAIL_ADDRESS       — Gmail account the report is sent FROM
  GMAIL_APP_PASSWORD  — Gmail App Password (NOT the regular password;
                        see https://support.google.com/accounts/answer/185833).
                        Strip any spaces the Google UI shows — the value
                        should be 16 characters with no whitespace.
  RECIPIENT_EMAIL     — Where the report is delivered TO

  GROQ_API_KEY        — AI-generated executive overview and
                        remediation sections appear in the PDF. When
                        unset or errored, those blocks are silently
                        omitted; the rest of the report is unaffected.

Deployment notes:
  • This Lambda shares a deployment package with report_generator.py;
    both files must sit at the zip root.
  • ReportLab is provided via a Lambda Layer — not bundled in this zip.
  • Hitting this Lambda directly via the Test button with a bare {}
    payload will fail (no scan data) — that's expected. The Lambda
    is invoked asynchronously from RiskScorer with a full payload.
"""

import json
import logging
import os
import smtplib
import uuid
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from report_generator import generate_report

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Required env vars — checked at handler entry so any misconfiguration
# surfaces with a clear error before we start building anything.
REQUIRED_ENV = ("GMAIL_ADDRESS", "GMAIL_APP_PASSWORD", "RECIPIENT_EMAIL")

# SMTP timeout in seconds. Gmail normally responds in under 2s; if it takes
# longer something is wrong and we'd rather fail fast than hold the Lambda
# open until it hits its max execution time.
SMTP_TIMEOUT = 30


def _parse_event(event):
    """
    Normalise the event payload into a dict.

    RiskScorer forwards via lambda_client.invoke(InvocationType="Event",
    Payload=json.dumps(...)) — Lambda delivers that as an already-parsed
    dict.

    IMPORTANT
    We still handle the string and API-Gateway-wrapped variants so
    manual Test invocations and any future HTTP-fronted routing work
    without changes here.
    """
    if isinstance(event, str):
        return json.loads(event)
    if isinstance(event, dict) and isinstance(event.get("body"), str):
        return json.loads(event["body"])
    return event or {}


def _check_env():
    """Raise early with a clear message if a required env var is missing."""
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            f"Set these in Lambda → Configuration → Environment variables."
        )


def _send_email(pdf_path, client_name, gmail_address, gmail_password, recipient_email):
    """Build the multipart email with PDF attachment and send via Gmail SMTP."""
    now_str     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    filename_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")

    msg = MIMEMultipart()
    msg["From"]    = gmail_address
    msg["To"]      = recipient_email
    msg["Subject"] = f"[ProbePoint] Report Created: {now_str}"

    body = (
        f"ProbePoint scan report generated successfully.\n\n"
        f"Client:     {client_name}\n"
        f"Generated:  {now_str}\n\n"
        f"The full PDF report is attached to this email."
    )
    msg.attach(MIMEText(body, "plain"))

    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    attachment = MIMEApplication(pdf_data, _subtype="pdf")
    attachment.add_header(
        "Content-Disposition",
        "attachment",
        filename=f"probepoint_report_{filename_ts}.pdf",
    )
    msg.attach(attachment)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=SMTP_TIMEOUT) as server:
        server.login(gmail_address, gmail_password)
        server.sendmail(gmail_address, recipient_email, msg.as_string())

    return now_str


def lambda_handler(event, context):
    """
    AWS Lambda entry point.
      1. Validate env vars
      2. Parse the forwarded payload
      3. Generate PDF to a unique /tmp path
      4. Email PDF via Gmail SMTP
      5. Clean up the /tmp file

    Each stage logs its own failure cleanly so CloudWatch shows exactly
    where things broke.
    """
    _check_env()

    gmail_address   = os.environ["GMAIL_ADDRESS"]
    gmail_password  = os.environ["GMAIL_APP_PASSWORD"]
    recipient_email = os.environ["RECIPIENT_EMAIL"]

    data = _parse_event(event)

    client_name = (data.get("scan_meta") or {}).get("client_name", "Unknown Organization")
    host_count  = len(data.get("hosts") or {})
    logger.info(
        "EmailTest received payload: client=%s, hosts=%d",
        client_name, host_count,
    )

    # Unique PDF path per invocation — Lambda can serve concurrent
    # invocations on the same container, and a shared fixed path would
    # race. uuid is cheap and collision-free.
    pdf_path = f"/tmp/probepoint_report_{uuid.uuid4().hex}.pdf"

    try:
        try:
            generate_report(data, pdf_path)
            logger.info("PDF generated at %s", pdf_path)
        except Exception:
            logger.exception("PDF generation failed")
            raise

        try:
            sent_at = _send_email(
                pdf_path, client_name,
                gmail_address, gmail_password, recipient_email,
            )
            logger.info("Email delivered to %s at %s", recipient_email, sent_at)
        except smtplib.SMTPAuthenticationError:
            logger.exception(
                "Gmail SMTP auth failed — check GMAIL_APP_PASSWORD "
                "(must be a Google App Password, not the regular account "
                "password; any spaces shown by Google must be stripped)."
            )
            raise
        except Exception:
            logger.exception("SMTP send failed")
            raise
    finally:
        # Best-effort cleanup so the /tmp workspace doesn't fill up if
        # the execution environment is reused. Ignored on failure.
        try:
            os.remove(pdf_path)
        except OSError:
            pass

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message":     f"Report emailed successfully at {sent_at}",
            "client_name": client_name,
            "recipient":   recipient_email,
            "host_count":  host_count,
        }),
    }
