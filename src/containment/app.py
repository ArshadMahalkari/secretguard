import json
import os
import time

import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    finding = event["detail"]
    table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
    events = boto3.client("events")
    action = "NOT_APPLICABLE"

    if finding["secret_type"] == "AWS_ACCESS_KEY":
        iam = boto3.client("iam")
        try:
            owner = iam.get_access_key_last_used(
                AccessKeyId=finding["access_key_id"]
            ).get("UserName")
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                owner = None
                action = "NOT_OURS"
            else:
                raise
        if owner:
            protected = {
                user.strip()
                for user in os.environ.get("PROTECTED_USERS", "").split(",")
                if user.strip()
            }
            user = iam.get_user(UserName=owner)["User"]
            if owner in protected:
                action = "PROTECTED"
            elif "/user/secretguard-managed/" not in user["Arn"]:
                action = "NOT_MANAGED"
            else:
                iam.update_access_key(
                    UserName=owner,
                    AccessKeyId=finding["access_key_id"],
                    Status="Inactive",
                )
                action = "DISABLED"

    seconds_to_contain = max(0, int(time.time()) - finding["created_at"])
    status = "CONTAINED" if action == "DISABLED" else "OPEN"
    table.update_item(
        Key={"finding_id": finding["finding_id"]},
        UpdateExpression="SET #status = :status, containment = :containment, seconds_to_contain = :seconds",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": status,
            ":containment": action,
            ":seconds": seconds_to_contain,
        },
    )
    events.put_events(
        Entries=[
            {
                "EventBusName": os.environ["EVENT_BUS_NAME"],
                "Source": "secretguard.containment",
                "DetailType": "ContainmentCompleted",
                "Detail": json.dumps(
                    {
                        "finding_id": finding["finding_id"],
                        "repository": finding["repository"],
                        "file": finding["file"],
                        "secret_type": finding["secret_type"],
                        "containment": action,
                        "seconds_to_contain": seconds_to_contain,
                        "status": status,
                    }
                ),
            }
        ]
    )
    return {"statusCode": 200, "containment": action, "seconds_to_contain": seconds_to_contain}
