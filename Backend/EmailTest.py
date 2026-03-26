import json
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def lambda_handler(event, context):
    to      = os.environ["GMAIL_ADDRESS"]
    subject = "ProbePoint Scan Results"
    body    = json.dumps(event, indent=2)

    msg = MIMEMultipart()
    msg["From"]    = os.environ["GMAIL_ADDRESS"]
    msg["To"]      = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(os.environ["GMAIL_ADDRESS"], os.environ["GMAIL_APP_PASSWORD"])
            server.sendmail(os.environ["GMAIL_ADDRESS"], to, msg.as_string())

        return {"statusCode": 200, "body": json.dumps({"message": f"Email sent to {to}"})}
    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
