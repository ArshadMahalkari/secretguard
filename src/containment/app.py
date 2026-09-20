import json
import os
import time

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------
# AWS CLIENTS
# ---------------------------------------------------------

iam = boto3.client("iam")
dynamodb = boto3.resource("dynamodb")
events = boto3.client("events")


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

FINDINGS_TABLE = os.environ["FINDINGS_TABLE"]
EVENT_BUS_NAME = os.environ["EVENT_BUS_NAME"]

PROTECTED_USERS = {
    user.strip()
    for user in os.environ.get("PROTECTED_USERS", "").split(",")
    if user.strip()
}


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def update_finding(
    table,
    finding_id,
    status,
    containment,
    seconds_to_contain,
):
    table.update_item(
        Key={
            "finding_id": finding_id
        },
        UpdateExpression=(
            "SET #status = :status, "
            "containment = :containment, "
            "seconds_to_contain = :seconds"
        ),
        ExpressionAttributeNames={
            "#status": "status"
        },
        ExpressionAttributeValues={
            ":status": status,
            ":containment": containment,
            ":seconds": seconds_to_contain,
        },
    )


def publish_containment_event(
    finding,
    action,
    status,
    seconds_to_contain,
):
    response = events.put_events(
        Entries=[
            {
                "EventBusName": EVENT_BUS_NAME,
                "Source": "secretguard.containment",
                "DetailType": "ContainmentCompleted",
                "Detail": json.dumps(
                    {
                        "finding_id": finding["finding_id"],
                        "repository": finding["repository"],
                        "commit": finding.get("commit"),
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

    if response.get("FailedEntryCount", 0) > 0:
        raise RuntimeError(
            "Failed to publish ContainmentCompleted event"
        )


# ---------------------------------------------------------
# LAMBDA HANDLER
# ---------------------------------------------------------

def lambda_handler(event, context):

    table = dynamodb.Table(FINDINGS_TABLE)

    finding = event.get("detail", {})

    finding_id = finding.get("finding_id")

    if not finding_id:
        raise ValueError(
            "Missing finding_id in FindingCreated event"
        )

    created_at = finding.get(
        "created_at",
        int(time.time())
    )

    seconds_to_contain = max(
        0,
        int(time.time()) - int(created_at)
    )

    action = "NOT_APPLICABLE"
    status = "OPEN"

    # -----------------------------------------------------
    # ONLY AWS ACCESS KEYS CAN BE AUTOMATICALLY DISABLED
    # -----------------------------------------------------

    if finding.get("secret_type") != "AWS_ACCESS_KEY":

        action = "NOT_APPLICABLE"
        status = "OPEN"

    else:

        access_key_id = finding.get("access_key_id")

        if not access_key_id:

            action = "MISSING_ACCESS_KEY_ID"
            status = "ERROR"

        else:

            try:

                # -------------------------------------------------
                # IDENTIFY IAM USER
                # -------------------------------------------------

                response = iam.get_access_key_last_used(
                    AccessKeyId=access_key_id
                )

                owner = response.get("UserName")

                if not owner:

                    action = "OWNER_NOT_FOUND"
                    status = "OPEN"

                # -------------------------------------------------
                # PROTECTED USER CHECK
                # -------------------------------------------------

                elif owner in PROTECTED_USERS:

                    action = "PROTECTED"
                    status = "OPEN"

                else:

                    # -------------------------------------------------
                    # GET IAM USER
                    # -------------------------------------------------

                    user_response = iam.get_user(
                        UserName=owner
                    )

                    user = user_response["User"]

                    user_arn = user["Arn"]

                    # -------------------------------------------------
                    # SAFETY CHECK
                    #
                    # SecretGuard can ONLY disable keys belonging
                    # to users under:
                    #
                    # secretguard-managed/*
                    # -------------------------------------------------

                    if "/user/secretguard-managed/" not in user_arn:

                        action = "NOT_MANAGED"
                        status = "OPEN"

                    else:

                        # -------------------------------------------------
                        # DISABLE ACCESS KEY
                        # -------------------------------------------------

                        iam.update_access_key(
                            UserName=owner,
                            AccessKeyId=access_key_id,
                            Status="Inactive",
                        )

                        action = "DISABLED"
                        status = "CONTAINED"

                        print(
                            json.dumps(
                                {
                                    "message": "AWS access key disabled",
                                    "finding_id": finding_id,
                                    "access_key_id": access_key_id,
                                    "user": owner,
                                }
                            )
                        )

            except ClientError as error:

                error_code = error.response.get(
                    "Error",
                    {}
                ).get(
                    "Code",
                    "Unknown"
                )

                if error_code == "NoSuchEntity":

                    action = "NOT_FOUND"
                    status = "OPEN"

                else:

                    print(
                        json.dumps(
                            {
                                "message": "IAM containment failed",
                                "finding_id": finding_id,
                                "error": str(error),
                            }
                        )
                    )

                    action = "ERROR"
                    status = "ERROR"

    # -----------------------------------------------------
    # UPDATE DYNAMODB FINDING
    # -----------------------------------------------------

    update_finding(
        table=table,
        finding_id=finding_id,
        status=status,
        containment=action,
        seconds_to_contain=seconds_to_contain,
    )

    # -----------------------------------------------------
    # PUBLISH CONTAINMENT RESULT
    # -----------------------------------------------------

    publish_containment_event(
        finding=finding,
        action=action,
        status=status,
        seconds_to_contain=seconds_to_contain,
    )

    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    return {
        "statusCode": 200,
        "finding_id": finding_id,
        "containment": action,
        "status": status,
        "seconds_to_contain": seconds_to_contain,
    }