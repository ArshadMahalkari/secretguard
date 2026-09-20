import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import boto3


# ---------------------------------------------------------
# AWS CLIENTS
# ---------------------------------------------------------

secrets_client = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")
events_client = boto3.client("events")


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

credentials = json.loads(
    secrets_client.get_secret_value(
        SecretId=os.environ["SECRET_ARN"]
    )["SecretString"]
)

GITHUB_TOKEN = credentials["github_token"]
FINDINGS_TABLE = os.environ["FINDINGS_TABLE"]
EVENT_BUS_NAME = os.environ["EVENT_BUS_NAME"]


# ---------------------------------------------------------
# SECRET DETECTION RULES
# ---------------------------------------------------------

RULES = {
    "AWS_ACCESS_KEY": re.compile(
        r"\b(AKIA[0-9A-Z]{16})\b"
    ),

    "AWS_SECRET_KEY": re.compile(
        r"(?i)"
        r"(aws_secret_access_key|aws_secret_key)"
        r"\s*[:=]\s*[\"']?"
        r"([A-Za-z0-9/+=]{30,})"
    ),

    "DATABASE_PASSWORD": re.compile(
        r"(?i)"
        r"(password|db_password|database_password)"
        r"\s*[:=]\s*[\"']"
        r"([^\"']{8,})"
        r"[\"']"
    ),

    "API_KEY": re.compile(
        r"(?i)"
        r"(api_key|apikey|api-secret)"
        r"\s*[:=]\s*[\"']"
        r"([^\"']{12,})"
        r"[\"']"
    ),
}


# ---------------------------------------------------------
# SEVERITY
# ---------------------------------------------------------

SEVERITY = {
    "AWS_ACCESS_KEY": "CRITICAL",
    "AWS_SECRET_KEY": "CRITICAL",
    "DATABASE_PASSWORD": "HIGH",
    "API_KEY": "HIGH",
}


# ---------------------------------------------------------
# SECRET MASKING
# ---------------------------------------------------------

def mask_secret(secret: str) -> str:
    """
    Never expose the complete secret.

    Example:
        abcdefghijklmnop
        ************mnop
    """

    if len(secret) <= 8:
        return "*" * len(secret)

    return "*" * (len(secret) - 4) + secret[-4:]


# ---------------------------------------------------------
# SCAN TEXT
# ---------------------------------------------------------

def scan_text(text: str):
    findings = []

    if not text:
        return findings

    for secret_type, pattern in RULES.items():

        for match in pattern.finditer(text):

            # AWS access key has only one capture group.
            # Other rules have the secret as group 2.
            if secret_type == "AWS_ACCESS_KEY":
                capture = match.group(1)
            else:
                capture = match.group(2)

            # Ignore GitHub's documented example AWS key.
            if capture == "AKIAIOSFODNN7EXAMPLE":
                continue

            finding = {
                "secret_type": secret_type,
                "masked_secret": mask_secret(capture),
                "start": match.start(),
                "end": match.end(),
            }

            # The access key ID is an identifier, not the secret
            # access key. We need it later for containment.
            if secret_type == "AWS_ACCESS_KEY":
                finding["access_key_id"] = capture

                # Do not expose the complete access key in
                # masked_secret either.
                finding["masked_secret"] = "*" * len(capture)

            findings.append(finding)

    return findings


# ---------------------------------------------------------
# GITHUB API
# ---------------------------------------------------------

def github_request(repository: str, path: str, token: str):
    """
    Make an authenticated GitHub API request.
    """

    url = (
        f"https://api.github.com/repos/"
        f"{repository}/{path}"
    )

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "SecretGuard",
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=15
        ) as response:

            return json.load(response)

    except urllib.error.HTTPError as error:

        # GitHub rate limit
        if error.code == 403:

            raise RuntimeError(
                "GitHub API rate limit or permission error"
            ) from error

        if error.code == 404:

            raise RuntimeError(
                f"GitHub repository/commit not found: {repository}"
            ) from error

        raise RuntimeError(
            f"GitHub API error: {error.code} {error.reason}"
        ) from error

    except urllib.error.URLError as error:

        raise RuntimeError(
            f"GitHub connection error: {error.reason}"
        ) from error


# ---------------------------------------------------------
# SCAN ONE COMMIT
# ---------------------------------------------------------

def scan_commit(
    repository: str,
    commit_sha: str,
    token: str
):
    """
    Fetch a commit from GitHub and scan only added lines.
    """

    commit = github_request(
        repository,
        f"commits/{urllib.parse.quote(commit_sha)}",
        token,
    )

    findings = []

    for file_info in commit.get("files", []):

        filename = file_info.get("filename")

        if not filename:
            continue

        # GitHub may not provide a patch for binary files
        # or certain large/unavailable diffs.
        patch = file_info.get("patch") or ""

        if not patch:
            continue

        # Only scan newly added lines.
        #
        # "+"  -> added line
        # "+++" -> diff header, ignore
        added_lines = "\n".join(
            line[1:]
            for line in patch.splitlines()
            if line.startswith("+")
            and not line.startswith("+++")
        )

        if not added_lines:
            continue

        text_findings = scan_text(added_lines)

        for finding in text_findings:

            findings.append(
                {
                    **finding,
                    "file": filename,
                    "commit": commit_sha,
                }
            )

    return findings


# ---------------------------------------------------------
# CREATE EVENT
# ---------------------------------------------------------

def publish_finding(item: dict):
    """
    Publish FindingCreated event to EventBridge.
    """

    response = events_client.put_events(
        Entries=[
            {
                "EventBusName": EVENT_BUS_NAME,
                "Source": "secretguard.scanner",
                "DetailType": "FindingCreated",
                "Detail": json.dumps(item),
            }
        ]
    )

    if response.get("FailedEntryCount", 0) > 0:

        raise RuntimeError(
            "Failed to publish FindingCreated event"
        )


# ---------------------------------------------------------
# LAMBDA HANDLER
# ---------------------------------------------------------

def lambda_handler(event, context):

    print(
        json.dumps(
            {
                "message": "SecretGuard scanner started",
                "event_id": event.get("id"),
            }
        )
    )

    table = dynamodb.Table(FINDINGS_TABLE)

    detail = event.get("detail", {})

    repository = detail.get("repository")

    if not repository:

        raise ValueError(
            "Missing repository in RepositoryPush event"
        )

    commits = detail.get("commits", [])

    if not commits:

        print(
            json.dumps(
                {
                    "message": "No commits to scan",
                    "repository": repository,
                }
            )
        )

        return {
            "statusCode": 200,
            "findings": 0,
        }

    total_findings = 0
    failed_commits = 0

    # -----------------------------------------------------
    # SCAN COMMITS
    # -----------------------------------------------------

    for commit in commits:

        commit_sha = commit.get("sha")

        if not commit_sha:
            continue

        try:

            findings = scan_commit(
                repository,
                commit_sha,
                GITHUB_TOKEN,
            )

        except Exception as error:

            failed_commits += 1

            print(
                json.dumps(
                    {
                        "message": "Commit scan failed",
                        "repository": repository,
                        "commit": commit_sha,
                        "error": str(error),
                    }
                )
            )

            # Continue scanning remaining commits.
            continue

        # -------------------------------------------------
        # STORE FINDINGS
        # -------------------------------------------------

        for finding in findings:

            finding_id = str(uuid.uuid4())

            item = {
                "finding_id": finding_id,
                "repository": repository,
                "commit": finding["commit"],
                "file": finding["file"],
                "secret_type": finding["secret_type"],
                "masked_secret": finding["masked_secret"],
                "severity": SEVERITY[
                    finding["secret_type"]
                ],
                "status": "OPEN",
                "created_at": int(time.time()),
            }

            # -------------------------------------------------
            # AWS ACCESS KEY
            # -------------------------------------------------
            #
            # Store ONLY the access key ID.
            #
            # NEVER store the AWS secret access key.
            # The containment Lambda uses the access key ID
            # to identify and disable the affected IAM key.

            if "access_key_id" in finding:

                item["access_key_id"] = (
                    finding["access_key_id"]
                )

            # -------------------------------------------------
            # DYNAMODB
            # -------------------------------------------------

            table.put_item(
                Item=item
            )

            # -------------------------------------------------
            # EVENTBRIDGE
            # -------------------------------------------------

            publish_finding(item)

            total_findings += 1

            print(
                json.dumps(
                    {
                        "message": "Secret detected",
                        "finding_id": finding_id,
                        "repository": repository,
                        "commit": finding["commit"],
                        "file": finding["file"],
                        "secret_type": finding["secret_type"],
                        "severity": item["severity"],
                    }
                )
            )

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    result = {
        "statusCode": 200,
        "findings": total_findings,
        "failed_commits": failed_commits,
    }

    print(
        json.dumps(
            {
                "message": "SecretGuard scanner completed",
                **result,
            }
        )
    )

    return result