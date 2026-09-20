import json
import os

import boto3


REMEDIATION = {
    "AWS_ACCESS_KEY": "Rotate the exposed AWS credential immediately. Prefer IAM roles or OIDC instead of long-lived access keys. Remove the credential from Git history.",
    "AWS_SECRET_KEY": "Rotate the AWS secret immediately and remove the credential from Git history.",
    "DATABASE_PASSWORD": "Rotate the database password. Store the replacement in AWS Secrets Manager. Remove the credential from source control.",
    "API_KEY": "Revoke and regenerate the API key. Store the replacement in AWS Secrets Manager. Remove it from source control.",
}


def lambda_handler(event, context):
    detail = event["detail"]
    event_type = event.get("detail-type", "")
    if event_type == "FindingCreated":
        message = {
            "repository": detail["repository"],
            "file": detail["file"],
            "commit": detail["commit"],
            "secret_type": detail["secret_type"],
            "remediation": REMEDIATION[detail["secret_type"]],
        }
        subject = f"SecretGuard finding: {detail['secret_type']}"
    else:
        message = {
            "finding_id": detail["finding_id"],
            "repository": detail["repository"],
            "file": detail["file"],
            "secret_type": detail["secret_type"],
            "containment": detail["containment"],
            "status": detail["status"],
            "seconds_to_contain": detail["seconds_to_contain"],
        }
        subject = f"SecretGuard containment: {detail['containment']}"

    boto3.client("sns").publish(
        TopicArn=os.environ["REMEDIATION_TOPIC_ARN"],
        Subject=subject,
        Message=json.dumps(message),
    )
    return {"statusCode": 200}
