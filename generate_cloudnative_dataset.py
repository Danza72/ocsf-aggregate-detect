#!/usr/bin/env python3
"""
generate_cloudnative_dataset.py

Generates a realistic cloud-native AWS OCSF dataset simulating a SaaS company
running microservices on ECS + Lambda, with a realistic CI/CD pipeline attack
embedded in the incident window.

Environment: fictional SaaS company "NovaPay" — a payments platform.
  - API backend:     ECS Fargate tasks (api-service-role)
  - Job workers:     ECS Fargate tasks (worker-service-role)
  - Image/doc proc:  Lambda (lambda-processor-role)
  - Notifications:   Lambda (lambda-notif-role)
  - Monitoring:      CloudWatch agent on NAT/bastion (cloudwatch-agent-role)
  - CI/CD:           GitHub Actions OIDC (ci-deploy-role)
  - Backup:          AWS Backup (backup-service-role)
  - Humans (rare):   dev.sarah (engineer), ops.james (SRE)

Attack chain (injected into incident days 10-12):
  Day 10 — Attacker uses leaked GitHub Actions OIDC token to call AWS as
            ci-deploy-role. Runs Discovery ops never seen for that role.
  Day 11 — Pivots: registers a rogue ECS task definition that uses
            worker-service-role (has SecretsManager access). Runs the task.
            Rogue task calls GetSecretValue on prod DB + payment API keys.
  Day 12 — Creates a backdoor IAM user (svc.monitor) with admin rights,
            mints an access key, then disables CloudTrail logging.

Usage:
    python3 generate_cloudnative_dataset.py --output ocsf_cloudnative
    python3 generate_cloudnative_dataset.py --output ocsf_cloudnative \\
        --baseline-days 30 --incident-start 2024-03-01 --incident-days 14

Then run the full pipeline:
    python3 run_analytics.py --input ocsf_cloudnative \\
        --output output_cloudnative \\
        --start 2024-03-01 --end 2024-03-14 --report-date 2024-03-14
"""

import argparse
import datetime
import json
import os
import random
import uuid

random.seed(2024)

# ── Environment constants ──────────────────────────────────────────────────

ACCOUNT   = "445566778899"
REGIONS   = ["us-east-1", "us-west-2"]
PRIMARY   = "us-east-1"

# Internal VPC CIDRs
API_IPS      = [f"10.0.1.{i}" for i in range(10, 18)]   # ECS api tasks
WORKER_IPS   = [f"10.0.2.{i}" for i in range(10, 16)]   # ECS worker tasks
LAMBDA_IPS   = [f"10.0.3.{i}" for i in range(10, 14)]   # Lambda ENIs
ALB_IPS      = [f"10.0.0.{i}" for i in range(5, 9)]     # ALB nodes
RDS_IP       = "10.0.4.20"
ELASTICACHE_IP = "10.0.4.50"
DYNAMO_EP_IP = "10.0.100.10"   # VPC endpoint for DynamoDB
NAT_IP       = "10.0.5.1"
BASTION_IP   = "10.0.6.5"

# External IPs used for outbound (AWS service endpoints, CDN)
AWS_HTTPS_IPS = ["52.94.0.1", "52.94.1.1", "54.239.0.1", "54.239.1.1"]
ATTACKER_IP   = "185.220.101.42"  # tor exit node / attacker infra

# IAM roles
ROLES = {
    "api-service-role": {
        "uid": "AROA445API0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/api-service-role",
        "region": PRIMARY,
        "ips": API_IPS,
        "eni_prefix": "eni-api",
    },
    "worker-service-role": {
        "uid": "AROA445WRK0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/worker-service-role",
        "region": PRIMARY,
        "ips": WORKER_IPS,
        "eni_prefix": "eni-wrk",
    },
    "lambda-processor-role": {
        "uid": "AROA445LAM0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/lambda-processor-role",
        "region": PRIMARY,
        "ips": LAMBDA_IPS,
        "eni_prefix": "eni-lam",
    },
    "lambda-notif-role": {
        "uid": "AROA445NTF0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/lambda-notif-role",
        "region": PRIMARY,
        "ips": LAMBDA_IPS,
        "eni_prefix": "eni-ntf",
    },
    "cloudwatch-agent-role": {
        "uid": "AROA445CWA0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/cloudwatch-agent-role",
        "region": PRIMARY,
        "ips": [BASTION_IP],
        "eni_prefix": "eni-cwa",
    },
    "ci-deploy-role": {
        "uid": "AROA445CID0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/ci-deploy-role",
        "region": PRIMARY,
        "ips": ["18.185.0.1", "18.185.0.2"],  # GitHub Actions runner IPs
        "eni_prefix": None,
    },
    "backup-service-role": {
        "uid": "AROA445BAK0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/backup-service-role",
        "region": PRIMARY,
        "ips": [NAT_IP],
        "eni_prefix": "eni-bak",
    },
}

HUMAN_USERS = {
    "dev.sarah": {
        "uid": "AIDA445DVS0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/dev.sarah",
        "ip": "203.45.67.89",
        "region": PRIMARY,
    },
    "ops.james": {
        "uid": "AIDA445OPS0000001",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/ops.james",
        "ip": "203.45.67.90",
        "region": PRIMARY,
    },
}

# S3 buckets
BUCKETS = {
    "novapay-uploads":         "user document uploads (input to lambda-processor)",
    "novapay-processed":       "processed documents output",
    "novapay-reports":         "generated financial reports",
    "novapay-logs-archive":    "log archive",
    "novapay-tf-state":        "Terraform state (ci-deploy-role only)",
    "novapay-backups":         "AWS Backup output",
}

# Secrets
SECRETS = [
    "prod/rds/password",
    "prod/payment-gateway/api-key",
    "prod/redis/auth-token",
    "prod/internal-service/jwt-secret",
]


# ── OCSF record builders ───────────────────────────────────────────────────

def _ts(dt: datetime.datetime) -> int:
    return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)

def _assumed_role_actor(role_name: str, session_suffix: str):
    r = ROLES[role_name]
    session = session_suffix
    return {
        "name": role_name,
        "uid": r["uid"],
        "uid_alt": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role_name}/{session}",
        "type": "AssumedRole",
    }

def _iam_user_actor(username: str):
    u = HUMAN_USERS[username]
    return {
        "name": username,
        "uid": u["uid"],
        "uid_alt": u["arn"],
        "type": "IAMUser",
    }

def ct_event(dt, actor_dict, operation, resource, src_ip, region=PRIMARY):
    return {
        "category_uid": 6,
        "class_uid": 6003,
        "time": _ts(dt),
        "actor": {"user": actor_dict},
        "api": {"operation": operation},
        "src_endpoint": {"ip": src_ip},
        "cloud": {"provider": "AWS", "region": region, "account": {"uid": ACCOUNT}},
        "resources": [{"name": resource}],
        "unmapped": {"is_system_actor": isinstance(actor_dict.get("type"), str) and actor_dict["type"] == "AssumedRole"},
    }

def s3_event(dt, actor_name, operation, bucket, src_ip, bytes_sent=None):
    return {
        "category_uid": 6,
        "class_uid": 6003,
        "time": _ts(dt),
        "actor": {"user": {"name": actor_name}},
        "api": {"operation": operation, "response": {"code": 200}},
        "src_endpoint": {"ip": src_ip},
        "resources": [{"name": bucket}],
        "unmapped": {
            "bytes_sent": str(bytes_sent or random.randint(1024, 500000)),
            "is_system_actor": False,
        },
    }

def vpc_event(dt, src_ip, dst_ip, src_port, dst_port, eni, bytes_=None, packets=None, action="ACCEPT"):
    return {
        "category_uid": 4,
        "class_uid": 4001,
        "time": _ts(dt),
        "src_endpoint": {"ip": src_ip, "interface_uid": eni, "port": src_port},
        "dst_endpoint": {"ip": dst_ip, "port": dst_port},
        "connection_info": {"protocol_num": 6},
        "traffic": {
            "bytes": bytes_ or random.randint(500, 80000),
            "packets": packets or random.randint(2, 30),
        },
        "unmapped": {"action": action, "is_system_actor": False},
    }


# ── Per-service traffic generators ────────────────────────────────────────

def _jitter(base_dt, minutes_window=5):
    return base_dt + datetime.timedelta(seconds=random.randint(0, minutes_window * 60))

def gen_api_service(date: datetime.date, count=None):
    """ECS api-service-role: handles HTTP requests, reads DynamoDB, caches in Redis."""
    events_ct, events_s3, events_vpc = [], [], []
    # ~200-400 task invocations per day spread across 24h
    n = count or random.randint(200, 380)
    for _ in range(n):
        h = random.randint(0, 23)
        # traffic heavier during business hours (weight toward 8-22 UTC)
        h = random.choices(range(24), weights=[1,1,1,1,1,1,1,2,3,4,5,6,6,5,5,5,5,4,4,3,3,2,2,1])[0]
        dt = datetime.datetime(date.year, date.month, date.day, h,
                               random.randint(0,59), random.randint(0,59))
        task_id = uuid.uuid4().hex[:12]
        actor = _assumed_role_actor("api-service-role", f"ecs-task-{task_id}")
        src_ip = random.choice(API_IPS)
        eni = f"eni-api{task_id[:6]}"

        # Normal ops: AssumeRole (sts) + DynamoDB reads + occasional SecretsManager on cold start
        events_ct.append(ct_event(dt, actor, "AssumeRole", "api-service-role", src_ip))
        for _ in range(random.randint(2, 6)):
            sub_dt = _jitter(dt)
            op = random.choices(
                ["Query", "GetItem", "BatchGetItem", "PutItem"],
                weights=[40, 30, 20, 10]
            )[0]
            events_ct.append(ct_event(sub_dt, actor, op, "novapay-transactions", src_ip))
        if random.random() < 0.08:  # cold start ~8% of tasks fetch secret
            events_ct.append(ct_event(_jitter(dt, 1), actor, "GetSecretValue",
                                       "prod/internal-service/jwt-secret", src_ip))
        # VPC: task → DynamoDB VPC endpoint
        for _ in range(random.randint(2, 5)):
            events_vpc.append(vpc_event(_jitter(dt), src_ip, DYNAMO_EP_IP,
                                         random.randint(32768, 60999), 443, eni))
        # VPC: task → ElastiCache
        if random.random() < 0.6:
            events_vpc.append(vpc_event(_jitter(dt), src_ip, ELASTICACHE_IP,
                                         random.randint(32768, 60999), 6379, eni,
                                         bytes_=random.randint(200, 5000), packets=random.randint(2,8)))
    return events_ct, events_s3, events_vpc

def gen_worker_service(date: datetime.date):
    """ECS worker-service-role: processes async jobs from SQS, writes to RDS + S3."""
    events_ct, events_s3, events_vpc = [], [], []
    n = random.randint(40, 90)
    for _ in range(n):
        h = random.randint(0, 23)
        dt = datetime.datetime(date.year, date.month, date.day, h,
                               random.randint(0,59), random.randint(0,59))
        task_id = uuid.uuid4().hex[:12]
        actor = _assumed_role_actor("worker-service-role", f"ecs-task-{task_id}")
        src_ip = random.choice(WORKER_IPS)
        eni = f"eni-wrk{task_id[:6]}"

        events_ct.append(ct_event(dt, actor, "AssumeRole", "worker-service-role", src_ip))
        # Workers fetch DB secret on startup
        events_ct.append(ct_event(_jitter(dt, 1), actor, "GetSecretValue",
                                   "prod/rds/password", src_ip))
        # Process job: read from S3, write result
        in_bucket = "novapay-uploads"
        out_bucket = "novapay-processed"
        events_ct.append(ct_event(_jitter(dt, 2), actor, "GetObject", in_bucket, src_ip))
        events_ct.append(ct_event(_jitter(dt, 3), actor, "PutObject", out_bucket, src_ip))
        events_s3.append(s3_event(_jitter(dt, 2), "worker-service-role", "GetObject", in_bucket, src_ip))
        events_s3.append(s3_event(_jitter(dt, 3), "worker-service-role", "PutObject", out_bucket, src_ip))
        # VPC: worker → RDS
        events_vpc.append(vpc_event(_jitter(dt), src_ip, RDS_IP,
                                     random.randint(32768, 60999), 5432, eni,
                                     bytes_=random.randint(2000, 30000)))
    return events_ct, events_s3, events_vpc

def gen_lambda_processor(date: datetime.date):
    """Lambda triggered by S3 PutObject events — image/PDF processing."""
    events_ct, events_s3, events_vpc = [], [], []
    n = random.randint(60, 140)
    for _ in range(n):
        h = random.choices(range(24), weights=[1,1,1,1,1,1,1,2,4,5,6,6,6,5,5,5,5,4,4,3,2,2,1,1])[0]
        dt = datetime.datetime(date.year, date.month, date.day, h,
                               random.randint(0,59), random.randint(0,59))
        fn_id = uuid.uuid4().hex[:8]
        actor = _assumed_role_actor("lambda-processor-role",
                                    f"novapay-doc-processor-{fn_id}")
        src_ip = random.choice(LAMBDA_IPS)
        eni = f"eni-lam{fn_id[:6]}"

        events_ct.append(ct_event(dt, actor, "AssumeRole", "lambda-processor-role", src_ip))
        events_ct.append(ct_event(_jitter(dt, 1), actor, "GetObject", "novapay-uploads", src_ip))
        events_ct.append(ct_event(_jitter(dt, 2), actor, "PutObject", "novapay-processed", src_ip))
        events_s3.append(s3_event(_jitter(dt, 1), "lambda-processor-role", "GetObject",
                                   "novapay-uploads", src_ip))
        events_s3.append(s3_event(_jitter(dt, 2), "lambda-processor-role", "PutObject",
                                   "novapay-processed", src_ip, bytes_sent=random.randint(50000,2000000)))
        events_vpc.append(vpc_event(_jitter(dt), src_ip, random.choice(AWS_HTTPS_IPS),
                                     random.randint(32768, 60999), 443, eni))
    return events_ct, events_s3, events_vpc

def gen_lambda_notif(date: datetime.date):
    """Lambda notification service — sends emails/SMS, publishes to SNS."""
    events_ct, events_s3, events_vpc = [], [], []
    n = random.randint(80, 180)
    for _ in range(n):
        h = random.choices(range(24), weights=[1,1,1,1,1,1,1,2,4,5,6,6,6,5,5,5,5,4,4,3,2,2,1,1])[0]
        dt = datetime.datetime(date.year, date.month, date.day, h,
                               random.randint(0,59), random.randint(0,59))
        fn_id = uuid.uuid4().hex[:8]
        actor = _assumed_role_actor("lambda-notif-role", f"novapay-notif-{fn_id}")
        src_ip = random.choice(LAMBDA_IPS)
        eni = f"eni-ntf{fn_id[:6]}"

        events_ct.append(ct_event(dt, actor, "AssumeRole", "lambda-notif-role", src_ip))
        # Notif lambda reads template from S3
        if random.random() < 0.3:
            events_ct.append(ct_event(_jitter(dt, 1), actor, "GetObject", "novapay-processed", src_ip))
        events_vpc.append(vpc_event(_jitter(dt), src_ip, random.choice(AWS_HTTPS_IPS),
                                     random.randint(32768, 60999), 443, eni))
    return events_ct, events_s3, events_vpc

def gen_cloudwatch_agent(date: datetime.date):
    """CloudWatch agent on bastion/NAT host — emits metrics every minute."""
    events_ct, events_s3, events_vpc = [], [], []
    inst_id = "i-0abc123def456789"
    actor = _assumed_role_actor("cloudwatch-agent-role", inst_id)
    src_ip = BASTION_IP
    eni = "eni-cwa000001"
    # ~24*6 = 144 PutMetricData calls per day (every 10 min)
    for h in range(24):
        for m in range(0, 60, 10):
            dt = datetime.datetime(date.year, date.month, date.day, h, m,
                                   random.randint(0, 9))
            events_ct.append(ct_event(dt, actor, "PutMetricData", "NovaPay/App", src_ip))
            events_vpc.append(vpc_event(dt, src_ip, random.choice(AWS_HTTPS_IPS),
                                         random.randint(32768, 60999), 443, eni,
                                         bytes_=random.randint(500, 3000), packets=random.randint(2,6)))
    return events_ct, events_s3, events_vpc

def gen_ci_deploy(date: datetime.date, is_weekday: bool):
    """GitHub Actions CI/CD — deploys ECS service + Lambda on pushes (weekdays mostly)."""
    events_ct, events_s3, events_vpc = [], [], []
    if not is_weekday and random.random() < 0.7:
        return events_ct, events_s3, events_vpc
    n = random.randint(1, 4) if is_weekday else 1
    for _ in range(n):
        h = random.randint(9, 20)
        dt = datetime.datetime(date.year, date.month, date.day, h,
                               random.randint(0,59), random.randint(0,59))
        run_id = str(random.randint(8000000000, 9999999999))
        actor = _assumed_role_actor("ci-deploy-role", f"GitHubActions-{run_id}")
        src_ip = random.choice(ROLES["ci-deploy-role"]["ips"])

        events_ct.append(ct_event(dt, actor, "AssumeRole", "ci-deploy-role", src_ip))
        # Normal deploy ops: register new task def, update ECS service, deploy Lambda
        for op, res in [
            ("DescribeTaskDefinition", "novapay-api"),
            ("RegisterTaskDefinition", "novapay-api"),
            ("UpdateService",          "novapay-api-service"),
            ("DescribeServices",       "novapay-api-service"),
            ("UpdateFunctionCode",     "novapay-doc-processor"),
        ]:
            events_ct.append(ct_event(_jitter(dt, 2), actor, op, res, src_ip))
        # Reads tf state + uploads build artifact
        events_ct.append(ct_event(_jitter(dt, 3), actor, "GetObject", "novapay-tf-state", src_ip))
        events_ct.append(ct_event(_jitter(dt, 4), actor, "PutObject", "novapay-tf-state", src_ip))
        events_s3.append(s3_event(_jitter(dt, 3), "ci-deploy-role", "GetObject", "novapay-tf-state", src_ip))
        events_s3.append(s3_event(_jitter(dt, 4), "ci-deploy-role", "PutObject", "novapay-tf-state", src_ip))
    return events_ct, events_s3, events_vpc

def gen_backup(date: datetime.date):
    """AWS Backup — nightly backup job (runs 01:00-03:00 UTC)."""
    events_ct, events_s3, events_vpc = [], [], []
    actor = _assumed_role_actor("backup-service-role", "AWSBackup-job")
    src_ip = NAT_IP
    eni = "eni-bak000001"
    base = datetime.datetime(date.year, date.month, date.day, 1, 0, 0)
    for i, op in enumerate([
        ("CreateBackupVault",  "novapay-daily-vault"),
        ("StartBackupJob",     "novapay-rds-instance"),
        ("DescribeBackupJob",  "novapay-daily-vault"),
        ("PutObject",          "novapay-backups"),
        ("PutObject",          "novapay-backups"),
    ]):
        dt = base + datetime.timedelta(minutes=i * 20 + random.randint(0, 10))
        events_ct.append(ct_event(dt, actor, op[0], op[1], src_ip))
    events_vpc.append(vpc_event(base, src_ip, random.choice(AWS_HTTPS_IPS),
                                 random.randint(32768, 60999), 443, eni,
                                 bytes_=random.randint(500000, 5000000)))
    return events_ct, events_s3, events_vpc

def gen_human(date: datetime.date, is_weekday: bool):
    """Occasional human console access (dev.sarah, ops.james) — weekdays only."""
    events_ct, events_s3, events_vpc = [], [], []
    if not is_weekday:
        return events_ct, events_s3, events_vpc
    for username, prob in [("dev.sarah", 0.7), ("ops.james", 0.4)]:
        if random.random() > prob:
            continue
        u = HUMAN_USERS[username]
        actor = _iam_user_actor(username)
        src_ip = u["ip"]
        h = random.randint(9, 17)
        dt = datetime.datetime(date.year, date.month, date.day, h,
                               random.randint(0,59), random.randint(0,59))
        ops = {
            "dev.sarah": [
                ("DescribeServices",      "novapay-api-service"),
                ("DescribeTasks",         "novapay-api"),
                ("GetLogEvents",          "novapay-api-logs"),
                ("DescribeLogStreams",     "novapay-api-logs"),
            ],
            "ops.james": [
                ("DescribeInstances",     "novapay-bastion"),
                ("DescribeSecurityGroups","novapay-vpc"),
                ("GetMetricData",         "NovaPay/App"),
                ("DescribeAlarms",        "NovaPay/Alarms"),
            ],
        }[username]
        for op, res in random.sample(ops, k=random.randint(1, len(ops))):
            events_ct.append(ct_event(_jitter(dt, 10), actor, op, res, src_ip))
    return events_ct, events_s3, events_vpc


def gen_normal_day(date: datetime.date):
    """Aggregate all normal service traffic for one day."""
    is_weekday = date.weekday() < 5
    ct, s3, vpc = [], [], []
    for gen, kwargs in [
        (gen_api_service,      {"date": date}),
        (gen_worker_service,   {"date": date}),
        (gen_lambda_processor, {"date": date}),
        (gen_lambda_notif,     {"date": date}),
        (gen_cloudwatch_agent, {"date": date}),
        (gen_ci_deploy,        {"date": date, "is_weekday": is_weekday}),
        (gen_backup,           {"date": date}),
        (gen_human,            {"date": date, "is_weekday": is_weekday}),
    ]:
        a, b, c = gen(**kwargs)
        ct += a; s3 += b; vpc += c
    return ct, s3, vpc


# ── Attack chain ───────────────────────────────────────────────────────────

def gen_attack_day10(date: datetime.date):
    """
    Day 10 of incident window.
    Attacker has a leaked GitHub OIDC token. Uses ci-deploy-role from their
    own IP. Runs Discovery ops that ci-deploy-role NEVER does normally.
    Session is tightly packed (~20 min) — timing burst signal.
    """
    events_ct, events_s3, events_vpc = [], [], []
    base = datetime.datetime(date.year, date.month, date.day, 3, 12, 0)  # 03:12 UTC, off-hours
    run_id = "9876543210"
    actor = _assumed_role_actor("ci-deploy-role", f"GitHubActions-{run_id}")

    recon_ops = [
        (0,  "AssumeRole",                    "ci-deploy-role"),
        (2,  "GetCallerIdentity",             "ci-deploy-role"),
        (4,  "ListUsers",                     "iam-users"),
        (6,  "ListRoles",                     "iam-roles"),
        (8,  "GetAccountAuthorizationDetails","novapay-account"),
        (10, "ListBuckets",                   "novapay-buckets"),
        (12, "DescribeInstances",             "novapay-vpc"),
        (14, "DescribeSecurityGroups",        "novapay-vpc"),
        (16, "ListTasks",                     "novapay-api-cluster"),
        (18, "DescribeTaskDefinition",        "novapay-worker"),
        (20, "ListAccessKeys",                "ci-deploy-role"),
    ]
    for mins, op, res in recon_ops:
        dt = base + datetime.timedelta(minutes=mins, seconds=random.randint(0,30))
        events_ct.append(ct_event(dt, actor, op, res, ATTACKER_IP))

    # Some outbound VPC traffic from the GitHub runner IP (anomalous src)
    events_vpc.append(vpc_event(base, ATTACKER_IP, random.choice(AWS_HTTPS_IPS),
                                 random.randint(40000,60000), 443, "eni-atk000001",
                                 bytes_=2400, packets=5))
    return events_ct, events_s3, events_vpc


def gen_attack_day11(date: datetime.date):
    """
    Day 11.
    Attacker uses ci-deploy-role to register a rogue task definition that runs
    under worker-service-role (which has SecretsManager access). Then runs the
    task. Rogue task immediately calls ListSecrets + GetSecretValue on all prod
    secrets. Classic ECS task-definition privilege escalation.
    """
    events_ct, events_s3, events_vpc = [], [], []

    # --- Phase 1: ci-deploy-role registers rogue task def + runs it ---
    base1 = datetime.datetime(date.year, date.month, date.day, 2, 5, 0)
    run_id = "9876543211"
    ci_actor = _assumed_role_actor("ci-deploy-role", f"GitHubActions-{run_id}")

    privesc_ops = [
        (0,  "AssumeRole",            "ci-deploy-role"),
        (2,  "RegisterTaskDefinition","novapay-worker"),    # rogue task def
        (5,  "RunTask",               "novapay-api-cluster"),
        (7,  "DescribeTasks",         "novapay-api-cluster"),
    ]
    for mins, op, res in privesc_ops:
        dt = base1 + datetime.timedelta(minutes=mins, seconds=random.randint(0,20))
        events_ct.append(ct_event(dt, ci_actor, op, res, ATTACKER_IP))

    # --- Phase 2: rogue ECS task runs as worker-service-role ---
    # Session name is NOT the normal ecs-task-{uuid} pattern
    base2 = base1 + datetime.timedelta(minutes=10)
    rogue_task_id = "rogue-maintenance-d4f8a"
    w_actor = _assumed_role_actor("worker-service-role", rogue_task_id)
    rogue_ip = random.choice(WORKER_IPS)
    rogue_eni = "eni-wrk-rogue01"

    cred_ops = [
        (0,  "AssumeRole",    "worker-service-role"),
        (1,  "ListSecrets",   "prod-secrets"),
        (3,  "GetSecretValue","prod/rds/password"),
        (5,  "GetSecretValue","prod/payment-gateway/api-key"),
        (7,  "GetSecretValue","prod/redis/auth-token"),
        (9,  "GetSecretValue","prod/internal-service/jwt-secret"),
        (11, "PutObject",     "novapay-logs-archive"),   # staging exfil data in a legit bucket
    ]
    for mins, op, res in cred_ops:
        dt = base2 + datetime.timedelta(minutes=mins, seconds=random.randint(0,15))
        events_ct.append(ct_event(dt, w_actor, op, res, rogue_ip))

    # S3 write (exfil staging)
    events_s3.append(s3_event(base2 + datetime.timedelta(minutes=11), "worker-service-role",
                               "PutObject", "novapay-logs-archive", rogue_ip, bytes_sent=48200))

    # VPC: rogue task → external HTTPS (exfil)
    for i in range(3):
        dt = base2 + datetime.timedelta(minutes=12 + i*2)
        events_vpc.append(vpc_event(dt, rogue_ip, ATTACKER_IP,
                                     random.randint(40000,60000), 443, rogue_eni,
                                     bytes_=random.randint(40000, 120000), packets=random.randint(30,80)))

    return events_ct, events_s3, events_vpc


def gen_attack_day12(date: datetime.date):
    """
    Day 12.
    Attacker uses ci-deploy-role again to establish persistent IAM backdoor:
    creates user svc.monitor, attaches AdministratorAccess, creates access key.
    Then disables CloudTrail logging to cover tracks.
    """
    events_ct, events_s3, events_vpc = [], [], []
    base = datetime.datetime(date.year, date.month, date.day, 1, 44, 0)
    run_id = "9876543212"
    ci_actor = _assumed_role_actor("ci-deploy-role", f"GitHubActions-{run_id}")

    persistence_ops = [
        (0,  "AssumeRole",       "ci-deploy-role"),
        (2,  "GetCallerIdentity","ci-deploy-role"),
        (4,  "CreateUser",       "svc.monitor"),
        (6,  "CreateAccessKey",  "svc.monitor"),
        (8,  "AttachUserPolicy", "svc.monitor"),          # AdministratorAccess
        (10, "CreateLoginProfile","svc.monitor"),
        (12, "StopLogging",      "novapay-management-trail"),
    ]
    for mins, op, res in persistence_ops:
        dt = base + datetime.timedelta(minutes=mins, seconds=random.randint(0,20))
        events_ct.append(ct_event(dt, ci_actor, op, res, ATTACKER_IP))

    # C2 beacon from attacker IP after persistence established
    for i in range(5):
        dt = base + datetime.timedelta(minutes=15 + i*20)
        events_vpc.append(vpc_event(dt, ATTACKER_IP, "91.108.4.1",
                                     random.randint(40000,60000), 8080, "eni-atk000001",
                                     bytes_=2200, packets=4))

    return events_ct, events_s3, events_vpc


# ── File writers ───────────────────────────────────────────────────────────

def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def generate(output_dir: str, baseline_days: int,
             incident_start: str, incident_days: int):

    inc_start = datetime.date.fromisoformat(incident_start)
    inc_dates = [inc_start + datetime.timedelta(days=i) for i in range(incident_days)]

    # Which incident days get attack traffic (days 10, 11, 12 — 0-indexed)
    attack_day_funcs = {}
    if len(inc_dates) > 10:
        attack_day_funcs[inc_dates[9]]  = gen_attack_day10
    if len(inc_dates) > 11:
        attack_day_funcs[inc_dates[10]] = gen_attack_day11
    if len(inc_dates) > 12:
        attack_day_funcs[inc_dates[11]] = gen_attack_day12

    # ── Baseline ──────────────────────────────────────────────────────────
    print("Generating baseline logs ...")
    # baseline starts 60 days before incident
    bl_start = inc_start - datetime.timedelta(days=60)
    bl_dates = [bl_start + datetime.timedelta(days=i) for i in range(baseline_days)]

    bl_ct, bl_s3, bl_vpc = [], [], []
    for d in bl_dates:
        a, b, c = gen_normal_day(d)
        bl_ct += a; bl_s3 += b; bl_vpc += c

    _write_jsonl(f"{output_dir}/cloudtrail_synthetic_baseline.jsonl", bl_ct)
    _write_jsonl(f"{output_dir}/s3_synthetic_baseline.jsonl", bl_s3)
    _write_jsonl(f"{output_dir}/vpcflow_synthetic_baseline.jsonl", bl_vpc)
    print(f"  Baseline: {len(bl_ct)} CT | {len(bl_s3)} S3 | {len(bl_vpc)} VPC  ({baseline_days} days)")

    # ── Incident days ─────────────────────────────────────────────────────
    print("Generating incident logs ...")
    total_ct = total_s3 = total_vpc = 0
    for d in inc_dates:
        ct, s3, vpc = gen_normal_day(d)
        if d in attack_day_funcs:
            a, b, c = attack_day_funcs[d](d)
            ct += a; s3 += b; vpc += c
            tag = " ← ATTACK"
        else:
            tag = ""
        day_str = d.isoformat()
        _write_jsonl(f"{output_dir}/incident/{day_str}/cloudtrail_ocsf.jsonl", ct)
        _write_jsonl(f"{output_dir}/incident/{day_str}/s3_accesslogs_ocsf.jsonl", s3)
        _write_jsonl(f"{output_dir}/incident/{day_str}/vpcflow_ocsf.jsonl", vpc)
        print(f"  {day_str}: {len(ct):4d} CT | {len(s3):3d} S3 | {len(vpc):3d} VPC{tag}")
        total_ct += len(ct); total_s3 += len(s3); total_vpc += len(vpc)

    print(f"\nDone → {output_dir}/")
    print(f"  Incident total: {total_ct} CT | {total_s3} S3 | {total_vpc} VPC")
    print(f"\nTo run the full pipeline:")
    end_str = inc_dates[-1].isoformat()
    print(f"  python3 run_analytics.py --input {output_dir} \\")
    print(f"    --output output_cloudnative \\")
    print(f"    --start {incident_start} --end {end_str} --report-date {end_str}")


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output",          default="ocsf_cloudnative",
                   help="Output directory (default: ocsf_cloudnative)")
    p.add_argument("--baseline-days",   type=int, default=30,
                   help="Number of baseline days to generate (default: 30)")
    p.add_argument("--incident-start",  default="2024-03-01",
                   help="First incident date YYYY-MM-DD (default: 2024-03-01)")
    p.add_argument("--incident-days",   type=int, default=14,
                   help="Number of incident days (default: 14, attack on days 10-12)")
    args = p.parse_args()

    generate(args.output, args.baseline_days, args.incident_start, args.incident_days)
