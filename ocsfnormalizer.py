#!/usr/bin/env python3
"""
ocsf_normalizer.py

Maps the three extracted BOTSv3 AWS log sources to OCSF-compliant JSON:

  - cloudtrail_raw.jsonl     -> OCSF API Activity      (class_uid 6003)
  - s3_accesslogs_raw.jsonl  -> OCSF API Activity      (class_uid 6003)
  - vpcflow_raw.jsonl        -> OCSF Network Activity  (class_uid 4001)

Mapping references used:
  - CloudTrail -> API Activity field layout verified against AWS's own
    published sample in aws-samples/amazon-security-lake-ocsf-validation
    (actor.user, api.operation, api.service.name, cloud.region, time).
  - VPC Flow Log -> Network Activity field layout verified against the
    OpenSearch VPC Flow OCSF mapping table (src_endpoint.port,
    dst_endpoint.port, traffic.bytes, traffic.packets,
    connection_info.protocol_num, cloud.account_uid).
  - S3 access logs -> API Activity, following the same shape as CloudTrail
    since both represent "an actor called an API against a resource".

Usage:
    python3 ocsf_normalizer.py <aws_raw_out_dir> <ocsf_out_dir>

Input directory must contain:
    cloudtrail_raw.jsonl, vpcflow_raw.jsonl, s3_accesslogs_raw.jsonl
(as produced by extract_botsv3_aws_v2.py)

Output:
    ocsf_out_dir/cloudtrail_ocsf.jsonl
    ocsf_out_dir/vpcflow_ocsf.jsonl
    ocsf_out_dir/s3_accesslogs_ocsf.jsonl
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# OCSF class UIDs
CLASS_API_ACTIVITY = 6003
CLASS_NETWORK_ACTIVITY = 4001
CATEGORY_APPLICATION_ACTIVITY = 6
CATEGORY_NETWORK_ACTIVITY = 4

# ---- Authoritative OCSF 1.4.0 enums, pulled directly from the official
#      ocsf-json-schema package (pip install ocsf-json-schema), NOT guessed.
#      See: schema['classes']['api_activity']['attributes']['activity_id']
#           schema['classes']['network_activity']['attributes']['activity_id']
#           schema['classes']['network_activity']['attributes']['disposition_id']

# API Activity (6003) activity_id enum
API_ACTIVITY_UNKNOWN = 0
API_ACTIVITY_CREATE = 1
API_ACTIVITY_READ = 2
API_ACTIVITY_UPDATE = 3
API_ACTIVITY_DELETE = 4
API_ACTIVITY_OTHER = 99

# Network Activity (4001) activity_id enum
NET_ACTIVITY_UNKNOWN = 0
NET_ACTIVITY_OPEN = 1
NET_ACTIVITY_CLOSE = 2
NET_ACTIVITY_RESET = 3
NET_ACTIVITY_FAIL = 4
NET_ACTIVITY_REFUSE = 5
NET_ACTIVITY_TRAFFIC = 6
NET_ACTIVITY_LISTEN = 7

# Network Activity disposition_id enum (security_control profile)
DISPOSITION_UNKNOWN = 0
DISPOSITION_ALLOWED = 1
DISPOSITION_BLOCKED = 2
DISPOSITION_OTHER = 99

STATUS_SUCCESS = 1
STATUS_FAILURE = 2
STATUS_UNKNOWN = 0


def iso_to_epoch_ms(iso_str: str):
    """Convert an ISO8601 timestamp (CloudTrail eventTime) to epoch millis."""
    try:
        dt = datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def s3_timestamp_to_epoch_ms(ts_str: str):
    """Convert S3 access log timestamp '20/Aug/2018:13:12:58 +0000' to epoch millis."""
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def guess_activity_id_from_event_name(event_name: str) -> int:
    """
    Rough CRUD classification from a CloudTrail/S3 eventName/operation,
    for the API Activity activity_id field. OCSF does not publish a
    per-AWS-API-call lookup table -- producers are expected to classify
    each operation themselves, so verb-prefix matching against the
    *exact* OCSF enum captions (Create/Read/Update/Delete/Other) is the
    standard, schema-compliant approach. Anything that doesn't match a
    known verb prefix is classified as Other (99), not Unknown (0), since
    we DO know an API call happened -- we just can't classify its CRUD
    type from the name alone.
    """
    if not event_name:
        return API_ACTIVITY_UNKNOWN
    name = event_name.lower()
    if name.startswith(("create", "put", "run", "attach", "add", "register")):
        return API_ACTIVITY_CREATE
    if name.startswith(("describe", "get", "list", "lookup", "head")):
        return API_ACTIVITY_READ
    if name.startswith(("update", "modify", "set")):
        return API_ACTIVITY_UPDATE
    if name.startswith(("delete", "remove", "terminate", "deactivate", "stop")):
        return API_ACTIVITY_DELETE
    return API_ACTIVITY_OTHER


import re

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*$")

# EC2 instance IDs appear as session names in STS AssumedRole ARNs when an
# EC2 instance profile calls an AWS API. Format: i- + 8 or 17 hex digits.
EC2_INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8}([0-9a-f]{9})?$")


def is_ip_address(value: str) -> bool:
    """True if value looks like an IPv4 or IPv6 address, False if it's
    something else (e.g. an AWS service hostname like
    'autoscaling.amazonaws.com', which CloudTrail's sourceIPAddress field
    can contain for AWS-service-initiated events)."""
    if not value:
        return False
    return bool(IP_RE.match(value))


# ---------------------------------------------------------------------------
# Non-human identity (NHI) classification
#
# Separating automated/service identities from human IAM users before
# behavioral baselining is a recognized practice in UEBA and identity
# governance: a service account's activity is mechanical and repetitive while
# a human's has natural variance, so mixing them produces misleading baselines
# in both directions.
#
# NOTE: "non-human identity" / NHI is a real concept in security, but the
# specific field name (unmapped.is_system_actor), the role-name allowlist
# below, and the fallback heuristics are implementation choices for this
# project -- they are NOT a mandated industry specification.
# ---------------------------------------------------------------------------

# Explicit set: every AssumedRole sessionIssuer.userName confirmed as an AWS
# managed service or automated role in this dataset (BOTSv3 v4, account
# 622676721278, 2018-08-20). Verified by inspecting all 789 AssumedRole
# events in cloudtrail_raw.jsonl with 0 missing sessionIssuer.userName.
_KNOWN_SYSTEM_ROLE_NAMES = frozenset({
    "AWSServiceRoleForAutoScaling",
    "splunk_lambda",
    "config-role-us-west-1",
    "flowlogsRole",
    "AWSServiceRoleForAmazonGuardDuty",
    "AWS_InspectorEvents_Invoke_Assessment_Template",
    "AWSServiceRoleForAmazonInspector",
})

# Fallback patterns for service roles that don't yet appear in the explicit
# set above. A role name is treated as a system actor if it starts with any
# of these prefixes OR contains any of these substrings.
_SYSTEM_ROLE_PREFIXES = ("AWSServiceRoleFor", "AWS_")
_SYSTEM_ROLE_SUBSTRINGS = ("lambda", "config-role", "flowlogsRole", "Inspector")


def _is_system_actor_cloudtrail(user_identity: dict) -> bool:
    """
    Return True if this CloudTrail userIdentity block represents an AWS
    managed service or automated role rather than a human IAM user.
    See the NHI classification note above for context and caveats.
    """
    uid_type = user_identity.get("type")
    if uid_type == "AWSService":
        return True
    if uid_type == "AssumedRole":
        sc = user_identity.get("sessionContext") or {}
        si = sc.get("sessionIssuer") or {}
        role_name = si.get("userName") or ""
        if role_name in _KNOWN_SYSTEM_ROLE_NAMES:
            return True
        if role_name.startswith(_SYSTEM_ROLE_PREFIXES) or any(
            s in role_name for s in _SYSTEM_ROLE_SUBSTRINGS
        ):
            return True
        # Session name is an EC2 instance ID (instance-profile-based calls).
        # In STS ARNs: arn:aws:sts::ACCOUNT:assumed-role/RoleName/i-xxxx
        sts_arn = user_identity.get("arn", "")
        session_name = sts_arn.rsplit("/", 1)[-1] if "/" in sts_arn else ""
        if EC2_INSTANCE_RE.match(session_name):
            return True
    return False


def _is_system_actor_s3(requester: str, user_agent: str, actor_name: str) -> bool:
    """
    Return True if this S3 access log entry's requester is an AWS managed
    service or automated role rather than a human IAM user.
    See the NHI classification note above for context and caveats.
    """
    # S3 log delivery service: uses a canonical user ID (no IAM ARN) and
    # always presents with an 'aws-internal/' user agent.
    if not requester.startswith("arn:") and (user_agent or "").startswith("aws-internal/"):
        return True
    # EC2 instance profile: the session name segment of the ARN is the instance ID.
    if EC2_INSTANCE_RE.match(actor_name or ""):
        return True
    return False


def _resolve_cloudtrail_user_name(user_identity: dict):
    """
    Return the most meaningful name for a CloudTrail userIdentity block.

    For AssumedRole events, userIdentity.userName is absent; the real role
    name lives in sessionContext.sessionIssuer.userName (always present in
    this dataset -- confirmed across 789 AssumedRole events with 0 missing).
    Falling back to the literal type string "AssumedRole" collapses all
    assumed-role sessions into one fake identity bucket, breaking per-user
    baselining.
    """
    # IAMUser / FederatedUser / SAMLUser: userName is present directly
    direct = user_identity.get("userName")
    if direct:
        return direct

    uid_type = user_identity.get("type")
    if uid_type == "AssumedRole":
        sc = user_identity.get("sessionContext") or {}
        si = sc.get("sessionIssuer") or {}
        # Primary: sessionIssuer.userName is the IAM role name (cleanest)
        if si.get("userName"):
            return si["userName"]
        # Secondary: last path segment of the IAM role ARN
        si_arn = si.get("arn", "")
        if si_arn:
            return si_arn.split("/")[-1]
        # Tertiary: role name from the STS assumed-role ARN
        # arn:aws:sts::ACCOUNT:assumed-role/RoleName/session-name
        sts_arn = user_identity.get("arn", "")
        if "assumed-role/" in sts_arn:
            return sts_arn.split("assumed-role/", 1)[1].split("/")[0]

    # AWSService, Root, etc.: type string is the best available identity
    return uid_type or None


def _extract_resources_from_cloudtrail(event: dict) -> list:
    """
    Extract OCSF resources[] from a raw CloudTrail event.

    CloudTrail embeds resource identifiers in requestParameters and
    responseElements using operation-specific schemas.  We handle the most
    common patterns found in the BOTSv3 dataset:

      S3 ops            rp.bucketName
      EC2 instance ops  rp/re.instancesSet.items[].instanceId
      EC2 tag ops       rp.resourcesSet.items[].resourceId
      STS AssumeRole    rp.roleArn  (name extracted from trailing ARN segment)
      KMS Decrypt       rp.encryptionContext values that are ARNs
      AWS Config        rp.configRuleNames[]
      RunInstances      rp.instancesSet AMI ID as proxy when instance IDs absent

    Returns [] when nothing can be extracted -- strip_nones() will drop the
    empty list from the OCSF output.
    """
    rp  = event.get("requestParameters") or {}
    re_ = event.get("responseElements") or {}
    op  = event.get("eventName") or ""

    resources: list = []

    # S3: bucket name on virtually all S3 API calls
    bucket = rp.get("bucketName")
    if bucket:
        resources.append({"name": bucket})

    # EC2: instance IDs from both requestParameters and responseElements
    for container in (rp, re_):
        for item in ((container.get("instancesSet") or {}).get("items") or []):
            if isinstance(item, dict):
                iid = item.get("instanceId")
                if iid:
                    resources.append({"name": iid})

    # EC2: resource IDs from generic resourcesSet (CreateTags and similar)
    for item in ((rp.get("resourcesSet") or {}).get("items") or []):
        if isinstance(item, dict):
            rid = item.get("resourceId")
            if rid:
                resources.append({"name": rid})

    # STS: role name from AssumeRole.requestParameters.roleArn
    role_arn = rp.get("roleArn")
    if role_arn:
        name = role_arn.split("/")[-1] if "/" in role_arn else role_arn
        resources.append({"name": name})

    # KMS: ARN values in encryptionContext (e.g. Lambda function ARNs in Decrypt)
    for v in (rp.get("encryptionContext") or {}).values():
        if isinstance(v, str) and v.startswith("arn:aws:"):
            name = v.rsplit("/", 1)[-1] if "/" in v else v.rsplit(":", 1)[-1]
            resources.append({"name": name})

    # AWS Config: rule names
    for rn in (rp.get("configRuleNames") or []):
        if isinstance(rn, str) and rn:
            resources.append({"name": rn})

    # RunInstances fallback: AMI ID when no instance IDs were captured in re
    if op == "RunInstances" and not any(
        r["name"].startswith("i-") for r in resources
    ):
        for item in ((rp.get("instancesSet") or {}).get("items") or []):
            if isinstance(item, dict) and item.get("imageId"):
                resources.append({"name": item["imageId"]})
                break  # one AMI per RunInstances call is the right granularity

    # Deduplicate by name, preserving first-seen order
    seen: set = set()
    unique: list = []
    for r in resources:
        n = r.get("name")
        if n and n not in seen:
            seen.add(n)
            unique.append(r)

    return unique


def map_cloudtrail_to_ocsf(event: dict) -> dict:
    """
    Map one raw CloudTrail JSON record to OCSF API Activity (6003).

    Field layout cross-checked against AWS's own published sample record
    (amazon-security-lake-ocsf-validation), which shows:
      actor.user.type / actor.user.name / actor.user.uid_alt
      api.operation / api.service.name / api.response.error / api.response.message
      cloud.region / cloud.provider
      src_endpoint.ip
      time
    """
    user_identity = event.get("userIdentity", {}) or {}
    error_code = event.get("errorCode")
    error_message = event.get("errorMessage")
    activity_id = guess_activity_id_from_event_name(event.get("eventName"))
    is_system = _is_system_actor_cloudtrail(user_identity)

    ocsf = {
        "category_uid": CATEGORY_APPLICATION_ACTIVITY,
        "category_name": "Application Activity",
        "class_uid": CLASS_API_ACTIVITY,
        "class_name": "API Activity",
        "activity_id": activity_id,
        "type_uid": CLASS_API_ACTIVITY * 100 + activity_id,
        "severity_id": STATUS_FAILURE if error_code else 1,
        "status_id": STATUS_FAILURE if error_code else STATUS_SUCCESS,
        "time": iso_to_epoch_ms(event.get("eventTime")),
        "metadata": {
            "product": {
                "name": "CloudTrail",
                "vendor_name": "AWS",
            },
            "version": "1.1.0",
            "event_code": event.get("eventType"),
            "uid": event.get("eventID"),
        },
        "cloud": {
            "provider": "AWS",
            "region": event.get("awsRegion"),
            "account": {
                "uid": user_identity.get("accountId") or event.get("recipientAccountId"),
            },
        },
        "actor": {
            "user": {
                "type": user_identity.get("type"),
                "name": _resolve_cloudtrail_user_name(user_identity),
                "uid": user_identity.get("principalId"),
                "uid_alt": user_identity.get("accessKeyId"),
                "account": ({
                    "uid": user_identity.get("accountId"),
                } if user_identity.get("accountId") else None),
            },
        },
        "api": {
            "operation": event.get("eventName"),
            "service": {
                "name": event.get("eventSource"),
            },
            "request": {
                "uid": event.get("requestID"),
            },
            "response": ({
                "error": error_code,
                "message": error_message,
            } if error_code else {}),
        },
        "src_endpoint": ({
            "ip": event.get("sourceIPAddress"),
        } if is_ip_address(event.get("sourceIPAddress")) else {
            # CloudTrail's sourceIPAddress can be an AWS service hostname
            # (e.g. "autoscaling.amazonaws.com") for AWS-service-initiated
            # events rather than a real IP -- OCSF's src_endpoint.ip field
            # is strictly pattern-validated as an IP address, so route
            # non-IP values to svc_name instead.
            "svc_name": event.get("sourceIPAddress"),
        }),
        "http_request": {
            "user_agent": event.get("userAgent"),
        },
        "resources": _extract_resources_from_cloudtrail(event),
        "unmapped": {
            "raw_eventVersion": event.get("eventVersion"),
            "requestParameters": event.get("requestParameters"),
            "responseElements": event.get("responseElements"),
            "additionalEventData": event.get("additionalEventData"),
            "is_system_actor": is_system,
        },
    }
    return ocsf


def map_s3_accesslog_to_ocsf(record: dict) -> dict:
    """
    Map one raw S3 access log record to OCSF API Activity (6003).

    S3 access logs represent "an actor called an API (S3 operation) against
    a resource (bucket/key)" -- the same conceptual shape as CloudTrail, so
    we reuse the API Activity class rather than inventing a new one.
    """
    operation = record.get("operation", "")
    http_status = record.get("http_status")
    is_error = http_status and not str(http_status).startswith("2")

    # requester may be a full IAM ARN or a raw canonical user ID (64-char hex).
    requester = record.get("requester", "")
    is_arn = requester.startswith("arn:")
    user_agent = record.get("user_agent") or ""

    # S3 log delivery service: canonical user ID + aws-internal/ user agent.
    # Relabeled to "s3-log-delivery" so dashboards don't show a 64-char hex
    # string; the raw canonical ID is preserved in actor.user.uid.
    is_s3_log_delivery = not is_arn and user_agent.startswith("aws-internal/")

    # Resolved actor name used both for actor.user.name and NHI classification.
    if is_s3_log_delivery:
        actor_name = "s3-log-delivery"
    elif is_arn:
        actor_name = requester.split("/")[-1]
    else:
        actor_name = None

    is_system = _is_system_actor_s3(requester, user_agent, actor_name)

    def to_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    op_verb = operation.replace("REST.", "").split(".")[0] if operation else None
    activity_id = guess_activity_id_from_event_name(op_verb)

    ocsf = {
        "category_uid": CATEGORY_APPLICATION_ACTIVITY,
        "category_name": "Application Activity",
        "class_uid": CLASS_API_ACTIVITY,
        "class_name": "API Activity",
        "activity_id": activity_id,
        "type_uid": CLASS_API_ACTIVITY * 100 + activity_id,
        "severity_id": STATUS_FAILURE if is_error else 1,
        "status_id": STATUS_FAILURE if is_error else STATUS_SUCCESS,
        "time": s3_timestamp_to_epoch_ms(record.get("timestamp")),
        "metadata": {
            "product": {
                "name": "Amazon S3",
                "vendor_name": "AWS",
            },
            "version": "1.1.0",
            "uid": record.get("request_id"),
        },
        "cloud": {
            "provider": "AWS",
        },
        "actor": {
            "user": {
                "uid": requester if not is_arn else None,
                "uid_alt": requester if is_arn else None,
                "name": actor_name,
            },
        },
        "api": {
            "operation": operation,
            "service": {
                "name": "s3.amazonaws.com",
            },
            "request": {
                "uid": record.get("request_id"),
            },
            "response": ({
                "code": to_int(http_status),
                "error": record.get("error_code"),
            } if record.get("error_code") not in (None, "-") else {
                "code": to_int(http_status),
            }),
        },
        "src_endpoint": {
            "ip": record.get("remote_ip"),
        },
        "resources": [
            {
                "name": record.get("bucket"),
                "type": "bucket",
                "data": {
                    "key": record.get("key"),
                },
            }
        ],
        "http_request": {
            "http_method": record.get("request_uri", "").split(" ")[0] if record.get("request_uri") else None,
            "url": {
                "path": record.get("request_uri", "").split(" ")[1] if record.get("request_uri") and len(record.get("request_uri", "").split(" ")) > 1 else None,
            },
            "user_agent": record.get("user_agent"),
        },
        "unmapped": {
            "bucket_owner": record.get("bucket_owner"),
            "object_size": record.get("object_size"),
            "bytes_sent": record.get("bytes_sent"),
            "total_time": record.get("total_time"),
            "turnaround_time": record.get("turnaround_time"),
            "version_id": record.get("version_id"),
            "referer": record.get("referer"),
            "is_system_actor": is_system,
        },
    }
    return ocsf


def map_vpcflow_to_ocsf(record: dict) -> dict:
    """
    Map one raw VPC Flow Log record to OCSF Network Activity (4001).

    Field layout per the OpenSearch VPC Flow -> OCSF mapping table:
      srcport     -> src_endpoint.port
      dstport     -> dst_endpoint.port
      protocol    -> connection_info.protocol_num
      packets     -> traffic.packets
      bytes       -> traffic.bytes
      account_id  -> cloud.account_uid
      end         -> end_time
    """
    def to_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    action = record.get("action", "")
    disposition_allowed = action == "ACCEPT"

    ocsf = {
        "category_uid": CATEGORY_NETWORK_ACTIVITY,
        "category_name": "Network Activity",
        "class_uid": CLASS_NETWORK_ACTIVITY,
        "class_name": "Network Activity",
        "activity_id": NET_ACTIVITY_TRAFFIC,
        "type_uid": CLASS_NETWORK_ACTIVITY * 100 + NET_ACTIVITY_TRAFFIC,
        "severity_id": 1,
        "status_id": STATUS_SUCCESS if disposition_allowed else STATUS_FAILURE,
        "time": to_int(record.get("start")) * 1000 if to_int(record.get("start")) else None,
        "start_time": to_int(record.get("start")) * 1000 if to_int(record.get("start")) else None,
        "end_time": to_int(record.get("end")) * 1000 if to_int(record.get("end")) else None,
        "metadata": {
            "product": {
                "name": "VPC Flow Logs",
                "vendor_name": "AWS",
                "version": record.get("version"),
            },
            "version": "1.1.0",
        },
        "cloud": {
            "provider": "AWS",
            "account": {
                "uid": record.get("account_id"),
            },
        },
        "src_endpoint": {
            "ip": record.get("srcaddr"),
            "port": to_int(record.get("srcport")),
            "interface_uid": record.get("interface_id"),
        },
        "dst_endpoint": {
            "ip": record.get("dstaddr"),
            "port": to_int(record.get("dstport")),
        },
        "connection_info": {
            "protocol_num": to_int(record.get("protocol")),
            "direction_id": 0,  # unknown directionality from flow log alone
        },
        "traffic": {
            "packets": to_int(record.get("packets")),
            "bytes": to_int(record.get("bytes")),
        },
        "unmapped": {
            "log_status": record.get("log_status"),
            "action": action,
            # VPC Flow Logs carry no actor/user identity, so system-actor
            # classification is not applicable; always False here.
            "is_system_actor": False,
        },
    }
    return ocsf


def strip_nones(obj):
    """
    Recursively remove keys with None values, and drop empty dicts/lists
    that result. OCSF's JSON Schema does not allow null for typed fields
    (e.g. a string-typed field rejects None) -- the correct way to omit
    an unknown/absent value is to leave the key out entirely, not set it
    to null. This is applied as a final pass over every mapped event.
    """
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            v2 = strip_nones(v)
            if v2 is None:
                continue
            if isinstance(v2, (dict, list)) and len(v2) == 0:
                continue
            cleaned[k] = v2
        return cleaned
    elif isinstance(obj, list):
        cleaned_list = [strip_nones(v) for v in obj]
        return [v for v in cleaned_list if v is not None]
    else:
        return obj


def process_file(in_path: Path, out_path: Path, mapper_fn):
    count = 0
    errors = 0
    with open(in_path, "r") as fin, open(out_path, "w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                ocsf_event = strip_nones(mapper_fn(raw))
                fout.write(json.dumps(ocsf_event) + "\n")
                count += 1
            except Exception as e:
                errors += 1
                if errors <= 5:
                    print(f"    WARNING: failed to map a record: {e}")
    return count, errors


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <aws_raw_out_dir> <ocsf_out_dir>")
        sys.exit(1)

    in_dir = Path(sys.argv[1]).expanduser().resolve()
    out_dir = Path(sys.argv[2]).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    jobs = [
        ("cloudtrail_raw.jsonl", "cloudtrail_ocsf.jsonl", map_cloudtrail_to_ocsf),
        ("vpcflow_raw.jsonl", "vpcflow_ocsf.jsonl", map_vpcflow_to_ocsf),
        ("s3_accesslogs_raw.jsonl", "s3_accesslogs_ocsf.jsonl", map_s3_accesslog_to_ocsf),
    ]

    summary = {}
    for in_name, out_name, mapper_fn in jobs:
        in_path = in_dir / in_name
        if not in_path.exists():
            print(f"SKIP: {in_path} not found")
            continue
        out_path = out_dir / out_name
        print(f"Mapping {in_name} -> {out_name} ...")
        count, errors = process_file(in_path, out_path, mapper_fn)
        summary[out_name] = {"mapped": count, "errors": errors}
        print(f"  mapped={count} errors={errors}")

    print("\n--- Summary ---")
    print(json.dumps(summary, indent=2))
    print(f"\nOutput written to: {out_dir}")


if __name__ == "__main__":
    main()