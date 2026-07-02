"""Maps raw AWS API event_name -> broad action category.

Some API calls legitimately belong to more than one category (e.g.
CreateAccessKey is both CredentialAccess and Persistence). Since a session's
ordered category sequence needs exactly one category per event, ties are
resolved with CATEGORY_PRIORITY: the first category in that list that the
event belongs to wins.
"""
from typing import Dict, List, Set, Tuple

AUTH = {"ConsoleLogin", "AssumeRole", "AssumeRoleWithSAML", "GetSessionToken"}

DISCOVERY = {
    "ListBuckets", "ListUsers", "ListRoles", "ListPolicies",
    "DescribeInstances", "DescribeSecurityGroups", "DescribeSnapshots",
    "DescribeVolumes", "GetCallerIdentity", "GetBucketPolicy",
    "GetAccountAuthorizationDetails", "ListAccessKeys", "ListObjects",
    "HeadObject",
}

DATA_ACCESS = {
    "GetObject", "GetSecretValue", "Decrypt", "GetParameter",
    "BatchGetItem", "Scan", "Query", "CopyObject", "RestoreObject",
    "PutObject", "CompleteMultipartUpload",
}

PERMISSION_CHANGE = {
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "AddUserToGroup", "UpdateAssumeRolePolicy", "PutBucketPolicy",
    "PutBucketAcl", "PutKeyPolicy", "CreateGrant", "DeleteBucketPolicy",
}

CREDENTIAL_ACCESS = {
    "CreateAccessKey", "UpdateAccessKey", "GetSecretValue", "Decrypt",
    "GetParameter",
}

PERSISTENCE = {
    "CreateUser", "CreateAccessKey", "CreateLoginProfile",
    "UpdateAssumeRolePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "AttachUserPolicy", "AttachRolePolicy",
}

DEFENSE_EVASION = {
    "StopLogging", "DeleteTrail", "PutEventSelectors", "DisableSecurityHub",
    "DeleteDetector", "UpdateDetector", "PutBucketLogging",
}

NETWORK_CHANGE = {
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress", "CreateSecurityGroup", "ModifyVpcAttribute",
    "CreateVpc", "DeleteVpc",
}

COMPUTE_CHANGE = {
    "StartInstances", "StopInstances", "RunInstances", "TerminateInstances",
    "ModifyInstanceAttribute",
}

STORAGE_CHANGE = {"CreateSnapshot", "ModifySnapshotAttribute", "DeleteObject"}

# Order matters: first matching category wins for events that fall into
# multiple sets above.
CATEGORY_PRIORITY: List[Tuple[str, Set[str]]] = [
    ("DefenseEvasion", DEFENSE_EVASION),
    ("PermissionChange", PERMISSION_CHANGE),
    ("CredentialAccess", CREDENTIAL_ACCESS),
    ("Persistence", PERSISTENCE),
    ("DataAccess", DATA_ACCESS),
    ("NetworkChange", NETWORK_CHANGE),
    ("ComputeChange", COMPUTE_CHANGE),
    ("StorageChange", STORAGE_CHANGE),
    ("Discovery", DISCOVERY),
    ("Auth", AUTH),
]

# Sensitive actions worth flagging on their own, regardless of category.
SENSITIVE_ACTIONS = {
    "CreateAccessKey", "AttachRolePolicy", "AttachUserPolicy",
    "PutBucketPolicy", "PutBucketAcl", "PutKeyPolicy", "StopLogging",
    "DeleteTrail", "GetSecretValue", "Decrypt", "UpdateAssumeRolePolicy",
    "CreateGrant", "CreateUser", "DeleteBucketPolicy",
}

_EVENT_TO_CATEGORY_CACHE: Dict[str, str] = {}


def map_action_category(event_name: str) -> str:
    """Map a raw AWS API event_name to one broad action category."""
    if event_name in _EVENT_TO_CATEGORY_CACHE:
        return _EVENT_TO_CATEGORY_CACHE[event_name]

    category = "Other"
    for cat_name, members in CATEGORY_PRIORITY:
        if event_name in members:
            category = cat_name
            break

    _EVENT_TO_CATEGORY_CACHE[event_name] = category
    return category


def is_sensitive_action(event_name: str) -> bool:
    return event_name in SENSITIVE_ACTIONS
