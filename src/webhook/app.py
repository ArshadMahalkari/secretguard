import base64
import hashlib
import hmac
import json
import os
import uuid

import boto3


secrets = boto3.client("secretsmanager")
events = boto3.client("events")
credentials = json.loads(
    secrets.get_secret_value(SecretId=os.environ["SECRET_ARN"])["SecretString"]
)
webhook_secret = credentials["webhook_secret"]
event_bus_name = os.environ["EVENT_BUS_NAME"]


def verify_signature(body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    digest = hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", signature)


def lambda_handler(event, context):
    raw_body = event.get("body") or ""
    body = (
        base64.b64decode(raw_body)
        if event.get("isBase64Encoded")
        else raw_body.encode()
    )
    headers = {
        key.lower(): value
        for key, value in (event.get("headers") or {}).items()
    }
    if not verify_signature(body, headers.get("x-hub-signature-256")):
        return {"statusCode": 401, "body": json.dumps({"error": "Invalid webhook signature"})}

    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"statusCode": 400, "body": json.dumps({"error": "Invalid JSON payload"})}

    if headers.get("x-github-event") != "push":
        return {"statusCode": 200, "body": json.dumps({"message": "Event ignored"})}
    if payload.get("deleted") or payload.get("after") == "0" * 40:
        return {"statusCode": 200, "body": json.dumps({"message": "Branch deletion ignored"})}

    scan_id = str(uuid.uuid4())
    events.put_events(
        Entries=[
            {
                "EventBusName": event_bus_name,
                "Source": "secretguard.github",
                "DetailType": "RepositoryPush",
                "Detail": json.dumps(
                    {
                        "scan_id": scan_id,
                        "repository": payload["repository"]["full_name"],
                        "commits": [
                            {"sha": commit["id"]}
                            for commit in payload.get("commits", [])[:20]
                        ],
                    }
                ),
            }
        ]
    )
    return {"statusCode": 200, "body": json.dumps({"message": "Push received", "scan_id": scan_id})}
