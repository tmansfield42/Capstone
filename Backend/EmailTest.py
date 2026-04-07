import json
import os
import smtplib
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from report_generator import generate_report

PDF_TMP_PATH = "/tmp/probepoint_report.pdf"


def lambda_handler(event, context):
    gmail_address   = os.environ["GMAIL_ADDRESS"]
    gmail_password  = os.environ["GMAIL_APP_PASSWORD"]
    recipient_email = os.environ["RECIPIENT_EMAIL"]

    if isinstance(event, str):
        event = json.loads(event)

    # ── Generate PDF ──────────────────────────────────────────────────────────
    generate_report(event, PDF_TMP_PATH)

    # ── Build email ───────────────────────────────────────────────────────────
    client_name = event.get("scan_meta", {}).get("client_name", "Unknown Organization")
    now_str     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    msg             = MIMEMultipart()
    msg["From"]     = gmail_address
    msg["To"]       = recipient_email
    msg["Subject"]  = f"[ProbePoint] Report Created: {now_str}"

    body = (
        f"ProbePoint scan report generated successfully.\n\n"
        f"Client:     {client_name}\n"
        f"Generated:  {now_str}\n\n"
        f"The full PDF report is attached to this email."
    )
    msg.attach(MIMEText(body, "plain"))

    # ── Attach PDF ────────────────────────────────────────────────────────────
    with open(PDF_TMP_PATH, "rb") as f:
        pdf_data = f.read()

    attachment = MIMEApplication(pdf_data, _subtype="pdf")
    attachment.add_header(
        "Content-Disposition",
        "attachment",
        filename=f"probepoint_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.pdf",
    )
    msg.attach(attachment)

    # ── Send ──────────────────────────────────────────────────────────────────
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(gmail_address, gmail_password)
        server.sendmail(gmail_address, recipient_email, msg.as_string())

    return {
        "statusCode": 200,
        "body": json.dumps({"message": f"Report emailed successfully at {now_str}"}),
    }
