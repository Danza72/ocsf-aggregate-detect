"""Load and normalize AWS CloudTrail logs into a flat event table.

Accepts two input shapes transparently:
  1. Raw CloudTrail JSON ({"Records": [...]}) / bare list / NDJSON of
     CloudTrail records (eventName, userIdentity, ...).
  2. OCSF API Activity (class_uid 6003) NDJSON, as produced for this
     project's dataset under ocsf_out_v2/ (api.operation, actor.user, ...).

Both shapes are mapped into the same canonical schema so the rest of the
pipeline (sessionization, baseline, scoring) never needs to know which
source format a log came from.

Usage:
    python3 normalize_cloudtrail.py <input.jsonl> <output.parquet>
"""
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

import pandas as pd

from action_categories import map_action_category, is_sensitive_action

NORMALIZED_FIELDS = [
    "event_time", "event_name", "event_source", "identity_id", "identity_type",
    "source_ip", "aws_region", "user_agent", "account_id", "request_parameters",
    "resources", "error_code",
]

# OCSF S3-access-log operation names that are equivalent to CloudTrail's GetObject.
GETOBJECT_OPERATIONS = {"REST.GET.OBJECT", "GetObject"}

# Some OCSF exports omit api.service.name. Infer the service from the
# operation name so eventSource-based logic still works.
OPERATION_TO_SERVICE = {
    "s3.amazonaws.com": {
        "GetObject", "PutObject", "HeadObject", "ListObjects", "ListBuckets",
        "GetBucketPolicy", "PutBucketPolicy", "PutBucketAcl",
        "DeleteBucketPolicy", "CopyObject", "RestoreObject",
        "CompleteMultipartUpload", "DeleteObject",
    },
    "ec2.amazonaws.com": {
        "DescribeInstances", "DescribeSecurityGroups", "DescribeVolumes",
        "DescribeSnapshots", "StartInstances", "StopInstances",
        "RunInstances", "TerminateInstances", "CreateSnapshot",
        "ModifySnapshotAttribute", "AuthorizeSecurityGroupIngress",
    },
    "iam.amazonaws.com": {
        "ListUsers", "ListRoles", "ListPolicies", "CreateUser",
        "CreateAccessKey", "UpdateAccessKey", "AttachUserPolicy",
        "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreatePolicy",
        "CreatePolicyVersion", "SetDefaultPolicyVersion", "AddUserToGroup",
        "UpdateAssumeRolePolicy", "CreateLoginProfile", "ListAccessKeys",
        "GetAccountAuthorizationDetails",
    },
    "sts.amazonaws.com": {
        "AssumeRole", "AssumeRoleWithSAML", "GetSessionToken",
        "GetCallerIdentity",
    },
    "kms.amazonaws.com": {"Decrypt", "CreateGrant", "PutKeyPolicy"},
    "secretsmanager.amazonaws.com": {"GetSecretValue"},
    "ssm.amazonaws.com": {"GetParameter"},
    "cloudtrail.amazonaws.com": {"StopLogging", "DeleteTrail", "PutEventSelectors"},
}
_OPERATION_TO_SERVICE_FLAT = {
    op: service for service, ops in OPERATION_TO_SERVICE.items() for op in ops
}
S3_OPERATIONS = OPERATION_TO_SERVICE["s3.amazonaws.com"]


def load_cloudtrail(path: str) -> List[Dict[str, Any]]:
    """Load raw event records from a file, regardless of source format.

    Accepts: CloudTrail {"Records": [...]}, a bare JSON list, or
    newline-delimited JSON (CloudTrail or OCSF records).
    """
    text = Path(path).read_text().strip()
    if not text:
        return []

    if text.startswith("{") and "\n" not in text.strip():
        data = json.loads(text)
        if "Records" in data:
            return data["Records"]
        return [data]

    if text.lstrip().startswith("["):
        return json.loads(text)

    # newline-delimited JSON (covers both CloudTrail-NDJSON and OCSF NDJSON)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _is_ocsf(record: Dict[str, Any]) -> bool:
    return "class_uid" in record or "api" in record and "operation" in (record.get("api") or {})


def _identity_id_cloudtrail(user_identity: Dict[str, Any]) -> str:
    arn = user_identity.get("arn")
    if arn:
        return arn
    principal_id = user_identity.get("principalId")
    if principal_id:
        return principal_id
    return "unknown"


def _identity_id_ocsf(record: Dict[str, Any]) -> str:
    user = (record.get("actor") or {}).get("user") or {}
    uid_alt = user.get("uid_alt")
    if uid_alt and str(uid_alt).startswith("arn:"):
        return uid_alt.rsplit("/", 1)[-1]
    name = user.get("name")
    if name:
        return name
    return user.get("uid") or "unknown"


def _normalize_cloudtrail_record(record: Dict[str, Any]) -> Dict[str, Any]:
    user_identity = record.get("userIdentity") or {}
    return {
        "event_time": record.get("eventTime"),
        "event_name": record.get("eventName"),
        "event_source": record.get("eventSource"),
        "identity_id": _identity_id_cloudtrail(user_identity),
        "identity_type": user_identity.get("type"),
        "source_ip": record.get("sourceIPAddress"),
        "aws_region": record.get("awsRegion"),
        "user_agent": record.get("userAgent"),
        "account_id": user_identity.get("accountId") or record.get("recipientAccountId"),
        "request_parameters": record.get("requestParameters"),
        "resources": record.get("resources"),
        "error_code": record.get("errorCode"),
    }


def _normalize_ocsf_record(record: Dict[str, Any]) -> Dict[str, Any]:
    api = record.get("api") or {}
    operation = api.get("operation")
    event_name = "GetObject" if operation in GETOBJECT_OPERATIONS else operation

    service_name = (api.get("service") or {}).get("name") or _OPERATION_TO_SERVICE_FLAT.get(operation)

    user = (record.get("actor") or {}).get("user") or {}
    cloud = record.get("cloud") or {}

    time_ms = record.get("time")

    # status_id == 1 is "Success" in OCSF; anything else carries an error.
    status_id = record.get("status_id")
    error_code = None
    if status_id is not None and status_id != 1:
        error_code = record.get("status_detail") or record.get("status") or "Error"

    return {
        "event_time": pd.to_datetime(time_ms, unit="ms", utc=True) if time_ms else None,
        "event_name": event_name,
        "event_source": service_name,
        "identity_id": _identity_id_ocsf(record),
        "identity_type": user.get("type"),
        "source_ip": (record.get("src_endpoint") or {}).get("ip"),
        "aws_region": cloud.get("region"),
        "user_agent": (record.get("http_request") or {}).get("user_agent"),
        "account_id": (cloud.get("account") or {}).get("uid"),
        "request_parameters": record.get("unmapped"),
        "resources": record.get("resources"),
        "error_code": error_code,
    }


def _normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    if _is_ocsf(record):
        return _normalize_ocsf_record(record)
    return _normalize_cloudtrail_record(record)


def normalize_cloudtrail(records: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    """Flatten raw records (CloudTrail or OCSF) into the normalized schema
    and enrich with derived columns (action_category, is_sensitive, is_failed)."""
    rows = [_normalize_record(r) for r in records]
    df = pd.DataFrame(rows, columns=NORMALIZED_FIELDS)
    if df.empty:
        return df

    df["event_time"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")
    df = df.dropna(subset=["event_time", "identity_id", "event_name"]).copy()
    df = df.sort_values("event_time").reset_index(drop=True)

    df["action_category"] = df["event_name"].apply(map_action_category)
    df["is_sensitive"] = df["event_name"].apply(is_sensitive_action)
    df["is_failed"] = df["error_code"].notna() & (df["error_code"].astype(str).str.len() > 0)

    return df


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    in_path, out_path = sys.argv[1], sys.argv[2]

    records = load_cloudtrail(in_path)
    df = normalize_cloudtrail(records)
    df.to_parquet(out_path, index=False)
    print(f"Normalized {len(df)} events -> {out_path}")


if __name__ == "__main__":
    main()
