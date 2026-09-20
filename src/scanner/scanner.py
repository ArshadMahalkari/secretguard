import json
import os
import re
import time
import urllib.parse
import urllib.request
import uuid

import boto3


credentials = json.loads(
    boto3.client("secretsmanager").get_secret_value(
        SecretId=os.environ["SECRET_ARN"]
    )["SecretString"]
)


RULES = {
    "AWS_ACCESS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "AWS_SECRET_KEY": re.compile(
        r"(?i)(aws_secret_access_key|aws_secret_key)"
        r"\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{30,})"
    ),
    "DATABASE_PASSWORD": re.compile(
        r"(?i)(password|db_password|database_password)"
        r"\s*[:=]\s*[\"']([^\"']{8,})[\"']"
    ),
    "API_KEY": re.compile(
        r"(?i)(api_key|apikey|api-secret)"
        r"\s*[:=]\s*[\"']([^\"']{12,})[\"']"
    ),
}

SEVERITY = {
    "AWS_ACCESS_KEY": "CRITICAL",
    "AWS_SECRET_KEY": "CRITICAL",
    "DATABASE_PASSWORD": "HIGH",
    "API_KEY": "HIGH",
}


def mask_secret(secret: str) -> str:
    return "*" * len(secret) if len(secret) <= 8 else "*" * (len(secret) - 4) + secret[-4:]


def scan_text(text: str):
    findings = []
    for secret_type, pattern in RULES.items():
        for match in pattern.finditer(text):
            capture = match.group(1) if secret_type == "AWS_ACCESS_KEY" else match.group(2)
            if capture == "AKIAIOSFODNN7EXAMPLE":
                continue
            finding = {
                "secret_type": secret_type,
                "masked_secret": mask_secret(capture),
                "start": match.start(),
                "end": match.end(),
            }
            if secret_type == "AWS_ACCESS_KEY":
                finding["access_key_id"] = capture
                finding["masked_secret"] = "*" * len(capture)
            findings.append(finding)
    return findings


def github_request(repository: str, path: str, token: str):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "SecretGuard",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def scan_commit(repository: str, commit_sha: str, token: str):
    commit = github_request(repository, f"commits/{urllib.parse.quote(commit_sha)}", token)
    findings = []
    for file_info in commit.get("files", []):
        added_lines = "\n".join(
            line[1:]
            for line in file_info.get("patch", "").splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        findings.extend(
            {**finding, "file": file_info["filename"], "commit": commit_sha}
            for finding in scan_text(added_lines)
        )
    return findings


def lambda_handler(event, context):
    table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
    events = boto3.client("events")
    detail = event["detail"]

    findings = [
        finding
        for commit in detail.get("commits", [])
        for finding in scan_commit(detail["repository"], commit["sha"], credentials["github_token"])
    ]
    for finding in findings:
        item = {
            "finding_id": str(uuid.uuid4()),
            "repository": detail["repository"],
            "commit": finding["commit"],
            "file": finding["file"],
            "secret_type": finding["secret_type"],
            "masked_secret": finding["masked_secret"],
            "severity": SEVERITY[finding["secret_type"]],
            "status": "OPEN",
            "created_at": int(time.time()),
        }
        if "access_key_id" in finding:
            item["access_key_id"] = finding["access_key_id"]
        table.put_item(Item=item)
        events.put_events(
            Entries=[
                {
                    "EventBusName": os.environ["EVENT_BUS_NAME"],
                    "Source": "secretguard.scanner",
                    "DetailType": "FindingCreated",
                    "Detail": json.dumps(item),
                }
            ]
        )
    return {"statusCode": 200, "findings": len(findings)}
