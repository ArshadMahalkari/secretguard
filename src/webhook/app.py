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
    secrets.get_secret_value(
        SecretId=os.environ["SECRET_ARN"]
    )["SecretString"]
)

webhook_secret = credentials["webhook_secret"]
event_bus_name = os.environ["EVENT_BUS_NAME"]


def verify_signature(body: bytes, signature: str | None) -> bool:
    if not signature:
        return False

    digest = hmac.new(
        webhook_secret.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

    expected_signature = f"sha256={digest}"

    return hmac.compare_digest(
        expected_signature,
        signature
    )


def lambda_handler(event, context):

    # -----------------------------------------
    # 1. Decode request body
    # -----------------------------------------

    raw_body = event.get("body") or ""

    try:
        body = (
            base64.b64decode(raw_body)
            if event.get("isBase64Encoded")
            else raw_body.encode()
        )
    except Exception:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": "Invalid request body"
            })
        }

    # -----------------------------------------
    # 2. Normalize headers
    # -----------------------------------------

    headers = {
        key.lower(): value
        for key, value in (event.get("headers") or {}).items()
    }

    signature = headers.get("x-hub-signature-256")

    # -----------------------------------------
    # 3. Verify GitHub HMAC
    # -----------------------------------------

    if not verify_signature(body, signature):
        return {
            "statusCode": 401,
            "body": json.dumps({
                "error": "Invalid webhook signature"
            })
        }

    # -----------------------------------------
    # 4. Parse JSON
    # -----------------------------------------

    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": "Invalid JSON payload"
            })
        }

    # -----------------------------------------
    # 5. Accept only push events
    # -----------------------------------------

    if headers.get("x-github-event") != "push":
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Event ignored"
            })
        }

    # -----------------------------------------
    # 6. Ignore branch deletion
    # -----------------------------------------

    if (
        payload.get("deleted")
        or payload.get("after") == "0" * 40
    ):
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Branch deletion ignored"
            })
        }

    # -----------------------------------------
    # 7. Validate repository
    # -----------------------------------------

    repository = (
        payload.get("repository", {})
        .get("full_name")
    )

    if not repository:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": "Missing repository information"
            })
        }

    # -----------------------------------------
    # 8. Collect commits
    # -----------------------------------------

    commits = [
        {
            "sha": commit["id"]
        }
        for commit in payload.get("commits", [])[:20]
        if commit.get("id")
    ]

    scan_id = str(uuid.uuid4())

    # -----------------------------------------
    # 9. Publish to EventBridge
    # -----------------------------------------

    response = events.put_events(
        Entries=[
            {
                "EventBusName": event_bus_name,
                "Source": "secretguard.github",
                "DetailType": "RepositoryPush",
                "Detail": json.dumps({
                    "scan_id": scan_id,
                    "repository": repository,
                    "commits": commits
                })
            }
        ]
    )

    # -----------------------------------------
    # 10. Check EventBridge result
    # -----------------------------------------

    if response.get("FailedEntryCount", 0) > 0:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Failed to publish security event"
            })
        }

    # -----------------------------------------
    # 11. Success
    # -----------------------------------------

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Push received",
            "scan_id": scan_id
        })
    }