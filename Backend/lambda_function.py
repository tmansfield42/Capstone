import json
import os
import boto3
from botocore.exceptions import BotoCoreError, ClientError

def lambda_handler(event, context):
    # Parse body
    try:
        payload = json.loads(event.get("body") or "")
    except (json.JSONDecodeError, ValueError):
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Request body is not valid JSON"})
        }

    # Invoke EmailTest
    target = os.environ.get("TARGET_LAMBDA_NAME", "EmailTest")
    lam = boto3.client("lambda")
    try:
        lam.invoke(
            FunctionName=target,
            InvocationType="Event",
            Payload=json.dumps(payload).encode("utf-8")
        )
    except (BotoCoreError, ClientError) as e:
        print(f"[ERROR] Lambda invoke failed: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Failed to invoke EmailTest"})
        }

    scan_meta = payload.get("scan_meta", {})
    print(f"[OK] Invoked {target} for scan from {scan_meta.get('pi_id')} at {scan_meta.get('timestamp')}")
    return {
        "statusCode": 200,
        "body": json.dumps({"status": "ok", "message": "Scan received"})
    }