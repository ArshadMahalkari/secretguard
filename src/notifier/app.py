import json
import os

import boto3


# ---------------------------------------------------------
# AWS CLIENT
# ---------------------------------------------------------

sns = boto3.client("sns")


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

REMEDIATION = {
    "AWS_ACCESS_KEY": (
        "The AWS access key was exposed. "
        "SecretGuard will attempt to disable it if it belongs "
        "to a SecretGuard-managed IAM user. "
        "Rotate the credential immediately and remove it from "
        "Git history. Prefer IAM roles or OIDC instead of "
        "long-lived access keys."
    ),

    "AWS_SECRET_KEY": (
        "Rotate the exposed AWS secret immediately. "
        "Remove the credential from Git history and prefer "
        "IAM roles or OIDC instead of long-lived access keys."
    ),

    "DATABASE_PASSWORD": (
        "Rotate the database password. "
        "Store the replacement in AWS Secrets Manager "
        "and remove the credential from source control."
    ),

    "API_KEY": (
        "Revoke and regenerate the API key. "
        "Store the replacement in AWS Secrets Manager "
        "and remove it from source control."
    ),
}


# ---------------------------------------------------------
# LAMBDA HANDLER
# ---------------------------------------------------------

def lambda_handler(event, context):

    detail = event.get("detail", {})

    event_type = event.get(
        "detail-type",
        ""
    )

    # -----------------------------------------------------
    # FINDING CREATED
    # -----------------------------------------------------

    if event_type == "FindingCreated":

        secret_type = detail.get(
            "secret_type",
            "UNKNOWN"
        )

        remediation = REMEDIATION.get(
            secret_type,
            "Review the detected secret, rotate it if necessary, "
            "and remove it from source control."
        )

        message = {
            "alert": "Secret detected",
            "finding_id": detail.get("finding_id"),
            "repository": detail.get("repository"),
            "file": detail.get("file"),
            "commit": detail.get("commit"),
            "secret_type": secret_type,
            "severity": detail.get("severity"),
            "masked_secret": detail.get("masked_secret"),
            "status": detail.get("status"),
            "remediation": remediation,
        }

        subject = (
            f"SecretGuard finding: {secret_type}"
        )

    # -----------------------------------------------------
    # CONTAINMENT COMPLETED
    # -----------------------------------------------------

    elif event_type == "ContainmentCompleted":

        containment = detail.get(
            "containment",
            "UNKNOWN"
        )

        status = detail.get(
            "status",
            "UNKNOWN"
        )

        if containment == "DISABLED":
            alert = "AWS credential automatically disabled"
        elif containment == "PROTECTED":
            alert = "AWS credential requires manual review"
        elif containment == "NOT_MANAGED":
            alert = "AWS credential detected but not automatically disabled"
        elif containment == "NOT_FOUND":
            alert = "AWS credential could not be found"
        elif containment == "ERROR":
            alert = "AWS credential containment failed"
        else:
            alert = "SecretGuard containment completed"

        message = {
            "alert": alert,
            "finding_id": detail.get("finding_id"),
            "repository": detail.get("repository"),
            "file": detail.get("file"),
            "commit": detail.get("commit"),
            "secret_type": detail.get("secret_type"),
            "containment": containment,
            "status": status,
            "seconds_to_contain": detail.get(
                "seconds_to_contain"
            ),
        }

        subject = (
            f"SecretGuard containment: {containment}"
        )

    # -----------------------------------------------------
    # UNKNOWN EVENT
    # -----------------------------------------------------

    else:

        print(
            json.dumps(
                {
                    "message": "Unknown notification event",
                    "event_type": event_type,
                }
            )
        )

        return {
            "statusCode": 200,
            "message": "Event ignored",
        }

    # -----------------------------------------------------
    # SNS
    # -----------------------------------------------------

    response = sns.publish(
        TopicArn=os.environ[
            "REMEDIATION_TOPIC_ARN"
        ],
        Subject=subject[:100],
        Message=json.dumps(
            message,
            indent=2
        ),
    )

    print(
        json.dumps(
            {
                "message": "Notification sent",
                "event_type": event_type,
                "sns_message_id": response.get(
                    "MessageId"
                ),
            }
        )
    )

    return {
        "statusCode": 200,
        "message": "Notification sent",
    }