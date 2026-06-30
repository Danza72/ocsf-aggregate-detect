#!/usr/bin/env python3
"""
generate_advanced_dataset.py  —  "Operation Quiet Harvest"

Advanced synthetic dataset for validating all three detection layers:
  UEBA, network exfil, and time-based exfil.

  True positives  (6): full kill chains, multi-vector attacks
  False positives (9): legitimate behaviour that looks suspicious
  Benign         (10): background noise

Baseline : 2018-07-21 → 2018-08-19  (30 days)
Incident : 2018-08-20 → 2018-09-02  (14 days)

Output → test_data_advanced/ocsf_out/
Run:
  python3 generate_advanced_dataset.py
  python3 run_ueba_v3.py \\
      --input  test_data_advanced/ocsf_out \\
      --output test_data_advanced/output   \\
      --start  2018-08-20 --end 2018-09-02
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(99)

# ── Paths & constants ─────────────────────────────────────────────────────────
BASE_DIR      = Path("test_data_advanced")
OCSF_DIR      = BASE_DIR / "ocsf_out"
INCIDENT_DIR  = OCSF_DIR / "incident"
GROUND_TRUTH  = BASE_DIR / "ground_truth.json"

CT_BASELINE  = OCSF_DIR / "cloudtrail_synthetic_baseline.jsonl"
S3_BASELINE  = OCSF_DIR / "s3_synthetic_baseline.jsonl"
VPC_BASELINE = OCSF_DIR / "vpcflow_synthetic_baseline.jsonl"

ACCOUNT_ID     = "111122223333"
BASELINE_START = datetime(2018, 7, 21, tzinfo=timezone.utc)
INCIDENT_DAY   = datetime(2018, 8, 20, tzinfo=timezone.utc)
BASELINE_DAYS  = 30
INCIDENT_DAYS  = 14

OCSF_DIR.mkdir(parents=True, exist_ok=True)

# ── Actor definitions ─────────────────────────────────────────────────────────
# Each entry: is_system, uid, label, ct, s3 (or None), vpc (or None)
# vpc keys: src_ip, src_eni, dst_ips {ip: weight}, dst_ports {port: weight},
#           protocol, active_hours, daily_flows (mean,std), daily_bytes (mean,std)

ACTORS: dict = {

    # ═══════════════════════ TRUE POSITIVES ══════════════════════════════════

    # James: compromised creds — UEBA (new IP/region/ops) + network exfil
    "james_dev": {
        "label": "TP_UEBA_NETEXFIL",
        "is_system": False, "uid": "AIDA200JAMES01",
        "ct": {
            "ip": "203.10.1.100", "region": "us-east-1",
            "ops": {"GetObject": 5, "DescribeInstances": 3, "PutObject": 2, "ListBuckets": 2},
            "resources": ["dev-data", "app-artifacts", "dev-server-1"],
            "active_hours": list(range(9, 18)), "daily_mean": 20,
        },
        "s3": {
            "ops": ["GetObject", "PutObject", "ListBuckets"],
            "buckets": ["dev-data", "app-artifacts"],
            "ip": "203.10.1.100",
            "daily_events": (25, 5), "daily_bytes": (3_000_000, 600_000),
        },
        "vpc": None,
    },

    # svc_data_pipeline: compromised service account — time-based + network exfil
    "svc_data_pipeline": {
        "label": "TP_TIMEXFIL_NETEXFIL",
        "is_system": True, "uid": "AIDA200PIPE01",
        "ct": {
            "ip": "10.0.0.20", "region": "us-east-1",
            "ops": {"GetObject": 6, "PutObject": 3, "DescribeInstances": 1},
            "resources": ["data-lake", "processed-data", "etl-server-1"],
            "active_hours": list(range(0, 5)) + list(range(20, 24)), "daily_mean": 50,
        },
        "s3": {
            "ops": ["GetObject", "PutObject"],
            "buckets": ["data-lake", "processed-data"],
            "ip": "10.0.0.20",
            "daily_events": (100, 10), "daily_bytes": (50_000_000, 5_000_000),
        },
        "vpc": {
            "src_ip": "10.0.0.20", "src_eni": "eni-pipeline001",
            "dst_ips": {"10.0.0.1": 2, "52.0.5.100": 1},
            "dst_ports": {443: 1}, "protocol": 6,
            "active_hours": list(range(0, 5)) + list(range(20, 24)),
            "daily_flows": (30, 5), "daily_bytes": (20_000_000, 3_000_000),
        },
    },

    # mallory_insider: insider, gradual S3 ramp + slow VPC drip — time-based exfil
    "mallory_insider": {
        "label": "TP_TIMEXFIL_NETEXFIL",
        "is_system": False, "uid": "AIDA200MALL01",
        "ct": {
            "ip": "203.10.1.110", "region": "us-east-1",
            "ops": {"GetObject": 7, "HeadObject": 2, "ListBuckets": 1},
            "resources": ["hr-data", "compliance-reports"],
            "active_hours": list(range(9, 18)), "daily_mean": 12,
        },
        "s3": {
            "ops": ["GetObject", "HeadObject"],
            "buckets": ["hr-data", "compliance-reports"],
            "ip": "203.10.1.110",
            "daily_events": (20, 3), "daily_bytes": (5_000_000, 800_000),
        },
        "vpc": None,
    },

    # petra_privesc: privilege escalation chain — UEBA (new ops: DeleteTrail/StopLogging)
    "petra_privesc": {
        "label": "TP_UEBA",
        "is_system": False, "uid": "AIDA200PETR01",
        "ct": {
            "ip": "203.10.1.120", "region": "us-east-1",
            "ops": {"GetObject": 5, "DescribeInstances": 3, "ListBuckets": 2},
            "resources": ["dev-server-1", "dev-data", "app-config"],
            "active_hours": list(range(9, 18)), "daily_mean": 15,
        },
        "s3": {
            "ops": ["GetObject", "ListBuckets"],
            "buckets": ["dev-data", "app-config"],
            "ip": "203.10.1.120",
            "daily_events": (15, 3), "daily_bytes": (3_000_000, 500_000),
        },
        "vpc": None,
    },

    # neil_c2: C2 beaconing — network exfil + UEBA (off-hours)
    "neil_c2": {
        "label": "TP_UEBA_NETEXFIL",
        "is_system": False, "uid": "AIDA200NEIL01",
        "ct": {
            "ip": "203.10.1.130", "region": "us-east-1",
            "ops": {"GetObject": 5, "DescribeInstances": 3, "ListBuckets": 2},
            "resources": ["ml-data", "gpu-server-1", "notebooks-bucket"],
            "active_hours": list(range(10, 19)), "daily_mean": 18,
        },
        "s3": {
            "ops": ["GetObject", "ListBuckets"],
            "buckets": ["ml-data", "notebooks-bucket"],
            "ip": "203.10.1.130",
            "daily_events": (30, 5), "daily_bytes": (20_000_000, 3_000_000),
        },
        "vpc": None,
    },

    # oscar_ransomprep: mass Describe recon — UEBA (new ops + volume spike)
    "oscar_ransomprep": {
        "label": "TP_UEBA",
        "is_system": False, "uid": "AIDA200OSCA01",
        "ct": {
            "ip": "203.10.1.140", "region": "us-east-1",
            "ops": {"DescribeInstances": 4, "DescribeSecurityGroups": 3,
                    "ListBuckets": 2, "DescribeSnapshots": 1},
            "resources": ["prod-server-1", "prod-server-2", "prod-db-1"],
            "active_hours": list(range(9, 18)), "daily_mean": 10,
        },
        "s3": None,
        "vpc": None,
    },

    # ═══════════════════════ FALSE POSITIVES ═════════════════════════════════

    # sarah_finance: quarter-end spike (days 0-2) — time-based exfil FP
    "sarah_finance": {
        "label": "FP_TIMEXFIL",
        "is_system": False, "uid": "AIDA200SARA01",
        "ct": {
            "ip": "203.10.1.150", "region": "us-east-1",
            "ops": {"GetObject": 6, "ListBuckets": 3, "HeadObject": 1},
            "resources": ["finance-data", "finance-reports"],
            "active_hours": list(range(9, 18)), "daily_mean": 12,
        },
        "s3": {
            "ops": ["GetObject", "ListBuckets"],
            "buckets": ["finance-data", "finance-reports"],
            "ip": "203.10.1.150",
            "daily_events": (30, 5), "daily_bytes": (10_000_000, 2_000_000),
        },
        "vpc": None,
    },

    # tom_devops: EU expansion — UEBA (new region/IP/resources) + network exfil FP
    "tom_devops": {
        "label": "FP_UEBA_NETEXFIL",
        "is_system": False, "uid": "AIDA200TDEV01",
        "ct": {
            "ip": "203.10.1.160", "region": "us-east-1",
            "ops": {"DescribeInstances": 4, "CreateSecurityGroup": 2,
                    "PutObject": 2, "ListBuckets": 2},
            "resources": ["infra-bucket", "prod-server-1", "prod-server-2"],
            "active_hours": list(range(8, 18)), "daily_mean": 15,
        },
        "s3": {
            "ops": ["PutObject", "ListBuckets"],
            "buckets": ["infra-bucket"],
            "ip": "203.10.1.160",
            "daily_events": (10, 2), "daily_bytes": (5_000_000, 1_000_000),
        },
        "vpc": {
            "src_ip": "203.10.1.160", "src_eni": "eni-tom000001",
            "dst_ips": {"54.240.193.1": 1},
            "dst_ports": {443: 1}, "protocol": 6,
            "active_hours": list(range(8, 18)),
            "daily_flows": (5, 1), "daily_bytes": (10_000_000, 2_000_000),
        },
    },

    # bob_analytics: team transfer, new S3 buckets — UEBA (new_bucket) FP
    "bob_analytics": {
        "label": "FP_UEBA",
        "is_system": False, "uid": "AIDA200BANA01",
        "ct": {
            "ip": "203.10.1.170", "region": "us-east-1",
            "ops": {"GetObject": 6, "ListBuckets": 3, "HeadObject": 1},
            "resources": ["analytics-data", "reports-data"],
            "active_hours": list(range(9, 18)), "daily_mean": 15,
        },
        "s3": {
            "ops": ["GetObject", "ListBuckets"],
            "buckets": ["analytics-data", "reports-data"],
            "ip": "203.10.1.170",
            "daily_events": (20, 4), "daily_bytes": (8_000_000, 1_500_000),
        },
        "vpc": None,
    },

    # svc_backup: nightly backup — network exfil FP (high bytes to known endpoint)
    "svc_backup": {
        "label": "FP_NETEXFIL",
        "is_system": True, "uid": "AIDA200BACK01",
        "ct": {
            "ip": "10.0.0.5", "region": "us-east-1",
            "ops": {"PutObject": 7, "ListBuckets": 3},
            "resources": ["backup-bucket"],
            "active_hours": [2, 3], "daily_mean": 10,
        },
        "s3": {
            "ops": ["PutObject", "ListBuckets"],
            "buckets": ["backup-bucket"],
            "ip": "10.0.0.5",
            "daily_events": (10, 1), "daily_bytes": (50_000_000, 5_000_000),
        },
        "vpc": {
            "src_ip": "10.0.0.5", "src_eni": "eni-backup0001",
            "dst_ips": {"52.219.100.1": 1},
            "dst_ports": {443: 1}, "protocol": 6,
            "active_hours": [2, 3],
            "daily_flows": (10, 1), "daily_bytes": (50_000_000, 5_000_000),
        },
    },

    # jenkins_ci: CI/CD off-hours burst — UEBA (low_frequency_hour) FP
    "jenkins_ci": {
        "label": "FP_UEBA",
        "is_system": True, "uid": "AIDA200JENK01",
        "ct": {
            "ip": "10.0.0.30", "region": "us-east-1",
            "ops": {"GetObject": 4, "PutObject": 4, "DescribeInstances": 2},
            "resources": ["app-bucket", "deploy-bucket", "ci-server-1"],
            "active_hours": [3, 4], "daily_mean": 60,
        },
        "s3": {
            "ops": ["GetObject", "PutObject"],
            "buckets": ["app-bucket", "deploy-bucket"],
            "ip": "10.0.0.30",
            "daily_events": (50, 8), "daily_bytes": (100_000_000, 15_000_000),
        },
        "vpc": None,
        "baseline_run_days": list(range(0, 30, 2)),  # every 2 days
    },

    # alice_hr: annual access review (days 3-5) — sequence FP (looks like recon)
    "alice_hr": {
        "label": "FP_SEQUENCE",
        "is_system": False, "uid": "AIDA200ALHR01",
        "ct": {
            "ip": "203.10.1.180", "region": "us-east-1",
            "ops": {"GetObject": 5, "ListUsers": 3, "GetUser": 2},
            "resources": ["hr-reports", "employee-data"],
            "active_hours": list(range(9, 18)), "daily_mean": 10,
        },
        "s3": {
            "ops": ["GetObject"],
            "buckets": ["hr-reports"],
            "ip": "203.10.1.180",
            "daily_events": (5, 1), "daily_bytes": (1_000_000, 200_000),
        },
        "vpc": None,
    },

    # svc_provisioning: user onboarding (day 6) — sequence FP (looks like persistence)
    "svc_provisioning": {
        "label": "FP_SEQUENCE",
        "is_system": True, "uid": "AIDA200PROV01",
        "ct": {
            "ip": "10.0.0.40", "region": "us-east-1",
            "ops": {"CreateUser": 2, "AddUserToGroup": 2,
                    "AttachUserPolicy": 2, "CreateAccessKey": 2, "ListUsers": 2},
            "resources": ["iam-users", "iam-groups"],
            "active_hours": list(range(9, 17)), "daily_mean": 10,
        },
        "s3": None,
        "vpc": None,
        "baseline_run_days": [2, 7, 14, 21, 28],  # occasional in baseline
    },

    # dave_keyrotation: key rotation (day 1) — sequence FP (looks like credential abuse)
    "dave_keyrotation": {
        "label": "FP_SEQUENCE",
        "is_system": False, "uid": "AIDA200DKRT01",
        "ct": {
            "ip": "203.10.1.190", "region": "us-east-1",
            "ops": {"ListAccessKeys": 3, "GetUser": 3, "CreateAccessKey": 2, "UpdateAccessKey": 2},
            "resources": ["iam-users"],
            "active_hours": list(range(9, 18)), "daily_mean": 10,
        },
        "s3": None,
        "vpc": None,
        "baseline_run_days": [4, 11, 18, 25],  # monthly-ish
    },

    # carol_pentest: authorized pentester (days 0-1) — UEBA FP (new IP, recon ops)
    "carol_pentest": {
        "label": "FP_UEBA",
        "is_system": False, "uid": "AIDA200PENT01",
        "ct": {
            "ip": "203.10.1.200", "region": "us-east-1",
            "ops": {"GetObject": 5, "DescribeInstances": 4, "ListBuckets": 1},
            "resources": ["dev-data", "dev-server-1"],
            "active_hours": list(range(9, 18)), "daily_mean": 10,
        },
        "s3": {
            "ops": ["GetObject"],
            "buckets": ["dev-data"],
            "ip": "203.10.1.200",
            "daily_events": (5, 1), "daily_bytes": (1_000_000, 200_000),
        },
        "vpc": None,
    },

    # ═══════════════════════ BENIGN ══════════════════════════════════════════

    "eng_01": {
        "label": "BENIGN", "is_system": False, "uid": "AIDA200ENG001",
        "ct": {
            "ip": "203.10.2.1", "region": "us-east-1",
            "ops": {"GetObject": 5, "PutObject": 3, "ListBuckets": 2},
            "resources": ["eng-data", "build-output"],
            "active_hours": list(range(9, 18)), "daily_mean": 20,
        },
        "s3": {
            "ops": ["GetObject", "PutObject"],
            "buckets": ["eng-data", "build-output"],
            "ip": "203.10.2.1",
            "daily_events": (20, 4), "daily_bytes": (5_000_000, 1_000_000),
        },
        "vpc": None,
    },
    "eng_02": {
        "label": "BENIGN", "is_system": False, "uid": "AIDA200ENG002",
        "ct": {
            "ip": "203.10.2.2", "region": "us-east-1",
            "ops": {"GetObject": 6, "DescribeInstances": 2, "ListBuckets": 2},
            "resources": ["eng-data", "test-server-1"],
            "active_hours": list(range(8, 17)), "daily_mean": 18,
        },
        "s3": {
            "ops": ["GetObject", "ListBuckets"],
            "buckets": ["eng-data"],
            "ip": "203.10.2.2",
            "daily_events": (15, 3), "daily_bytes": (4_000_000, 800_000),
        },
        "vpc": None,
    },
    "eng_03": {
        "label": "BENIGN", "is_system": False, "uid": "AIDA200ENG003",
        "ct": {
            "ip": "203.10.2.3", "region": "us-east-1",
            "ops": {"GetObject": 5, "PutObject": 4, "ListBuckets": 1},
            "resources": ["staging-data", "staging-bucket"],
            "active_hours": list(range(9, 17)), "daily_mean": 15,
        },
        "s3": {
            "ops": ["GetObject", "PutObject"],
            "buckets": ["staging-data", "staging-bucket"],
            "ip": "203.10.2.3",
            "daily_events": (18, 3), "daily_bytes": (6_000_000, 1_200_000),
        },
        "vpc": None,
    },
    "eng_04": {
        "label": "BENIGN", "is_system": False, "uid": "AIDA200ENG004",
        "ct": {
            "ip": "203.10.2.4", "region": "us-east-1",
            "ops": {"GetObject": 7, "HeadObject": 2, "ListBuckets": 1},
            "resources": ["qa-data", "qa-bucket"],
            "active_hours": list(range(8, 17)), "daily_mean": 20,
        },
        "s3": {
            "ops": ["GetObject", "HeadObject"],
            "buckets": ["qa-data", "qa-bucket"],
            "ip": "203.10.2.4",
            "daily_events": (22, 4), "daily_bytes": (7_000_000, 1_400_000),
        },
        "vpc": None,
    },
    "eng_05": {
        "label": "BENIGN", "is_system": False, "uid": "AIDA200ENG005",
        "ct": {
            "ip": "203.10.2.5", "region": "us-east-1",
            "ops": {"GetObject": 5, "PutObject": 3, "DescribeInstances": 2},
            "resources": ["dev-shared", "dev-server-2"],
            "active_hours": list(range(9, 18)), "daily_mean": 18,
        },
        "s3": {
            "ops": ["GetObject", "PutObject"],
            "buckets": ["dev-shared"],
            "ip": "203.10.2.5",
            "daily_events": (16, 3), "daily_bytes": (4_500_000, 900_000),
        },
        "vpc": None,
    },
    "svc_monitoring": {
        "label": "BENIGN", "is_system": True, "uid": "AIDA200MON001",
        "ct": {
            "ip": "10.0.1.1", "region": "us-east-1",
            "ops": {"DescribeInstances": 5, "DescribeAlarms": 3, "GetMetricData": 2},
            "resources": ["prod-server-1", "prod-server-2"],
            "active_hours": list(range(0, 24)), "daily_mean": 100,
        },
        "s3": None, "vpc": None,
    },
    "svc_logging": {
        "label": "BENIGN", "is_system": True, "uid": "AIDA200LOG001",
        "ct": {
            "ip": "10.0.1.2", "region": "us-east-1",
            "ops": {"PutObject": 6, "CreateLogGroup": 2, "PutLogEvents": 2},
            "resources": ["log-archive", "cloudwatch-logs"],
            "active_hours": list(range(0, 24)), "daily_mean": 200,
        },
        "s3": {
            "ops": ["PutObject"],
            "buckets": ["log-archive"],
            "ip": "10.0.1.2",
            "daily_events": (50, 5), "daily_bytes": (30_000_000, 3_000_000),
        },
        "vpc": None,
    },
    "svc_alerts": {
        "label": "BENIGN", "is_system": True, "uid": "AIDA200ALT001",
        "ct": {
            "ip": "10.0.1.3", "region": "us-east-1",
            "ops": {"PutMetricAlarm": 4, "DescribeAlarms": 4, "GetMetricData": 2},
            "resources": ["monitoring-config"],
            "active_hours": list(range(0, 24)), "daily_mean": 30,
        },
        "s3": None, "vpc": None,
    },
    "svc_metrics": {
        "label": "BENIGN", "is_system": True, "uid": "AIDA200MET001",
        "ct": {
            "ip": "10.0.1.4", "region": "us-east-1",
            "ops": {"GetMetricData": 5, "PutMetricData": 4, "ListMetrics": 1},
            "resources": ["metrics-store"],
            "active_hours": list(range(0, 24)), "daily_mean": 80,
        },
        "s3": None, "vpc": None,
    },
    "frank_pm": {
        "label": "BENIGN", "is_system": False, "uid": "AIDA200FPPM01",
        "ct": {
            "ip": "203.10.2.10", "region": "us-east-1",
            "ops": {"GetObject": 6, "ListBuckets": 3, "HeadObject": 1},
            "resources": ["project-docs", "roadmap-data"],
            "active_hours": list(range(9, 17)), "daily_mean": 8,
        },
        "s3": {
            "ops": ["GetObject", "ListBuckets"],
            "buckets": ["project-docs"],
            "ip": "203.10.2.10",
            "daily_events": (8, 2), "daily_bytes": (2_000_000, 400_000),
        },
        "vpc": None,
    },
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _random_ts(base: datetime, hours: list, jitter_secs: int = 59) -> int:
    h = random.choice(hours)
    m = random.randint(0, 59)
    s = random.randint(0, jitter_secs)
    return _ts(base.replace(hour=h, minute=m, second=s))


def _evenly_spaced_ts(base: datetime, count: int,
                      start_hour: int = 9, end_hour: int = 17) -> list[int]:
    """Return `count` nearly-evenly-spaced timestamps (small jitter)."""
    start = base.replace(hour=start_hour, minute=0, second=0)
    total = (end_hour - start_hour) * 3600
    if count < 2:
        return [_ts(start) + random.randint(0, total * 1000)]
    step = total / count
    return [
        _ts(start + timedelta(seconds=int(i * step) + random.randint(-30, 30)))
        for i in range(count)
    ]


def _weighted_choice(weights: dict):
    keys = list(weights.keys())
    vals = list(weights.values())
    total = sum(vals)
    r = random.random() * total
    cum = 0
    for k, v in zip(keys, vals):
        cum += v
        if r <= cum:
            return k
    return keys[-1]


def _baseline_days(actor: dict) -> list[int]:
    return actor.get("baseline_run_days", list(range(BASELINE_DAYS)))


# ── OCSF event builders ───────────────────────────────────────────────────────

def _ct_event(name: str, uid: str, ip: str, region: str,
              op: str, resource: str, ts: int, is_system: bool) -> dict:
    return {
        "category_uid": 6, "class_uid": 6003, "time": ts,
        "actor": {"user": {"name": name, "uid": uid,
                           "uid_alt": f"arn:aws:iam::{ACCOUNT_ID}:user/{name}",
                           "type": "AssumedRole" if is_system else "IAMUser"}},
        "api": {"operation": op},
        "src_endpoint": {"ip": ip},
        "cloud": {"provider": "AWS", "region": region,
                  "account": {"uid": ACCOUNT_ID}},
        "resources": [{"name": resource}] if resource else [],
        "unmapped": {"is_system_actor": is_system},
    }


def _s3_event(name: str, ip: str, op: str, bucket: str,
              ts: int, bytes_val: int, is_system: bool) -> dict:
    return {
        "category_uid": 6, "class_uid": 6003, "time": ts,
        "actor": {"user": {"name": name}},
        "api": {"operation": op, "response": {"code": 200}},
        "src_endpoint": {"ip": ip},
        "resources": [{"name": bucket}],
        "unmapped": {"bytes_sent": str(bytes_val), "is_system_actor": is_system},
    }


def _vpc_event(src_ip: str, eni: str, dst_ip: str, dst_port: int,
               proto: int, ts: int, bytes_val: int,
               action: str = "ACCEPT") -> dict:
    return {
        "category_uid": 4, "class_uid": 4001, "time": ts,
        "src_endpoint": {"ip": src_ip, "interface_uid": eni,
                         "port": random.randint(1024, 65535)},
        "dst_endpoint": {"ip": dst_ip, "port": dst_port},
        "connection_info": {"protocol_num": proto},
        "traffic": {"bytes": bytes_val, "packets": random.randint(1, 20)},
        "unmapped": {"action": action, "is_system_actor": False},
    }


# ── Baseline generators ───────────────────────────────────────────────────────

def generate_ct_baseline() -> int:
    total = 0
    with open(CT_BASELINE, "w") as f:
        for name, actor in ACTORS.items():
            ct = actor["ct"]
            for day in _baseline_days(actor):
                date = BASELINE_START + timedelta(days=day)
                count = max(1, round(random.gauss(ct["daily_mean"],
                                                  ct["daily_mean"] * 0.2)))
                for _ in range(count):
                    op  = _weighted_choice(ct["ops"])
                    res = random.choice(ct["resources"])
                    ts  = _random_ts(date, ct["active_hours"])
                    f.write(json.dumps(_ct_event(name, actor["uid"], ct["ip"],
                                                  ct["region"], op, res, ts,
                                                  actor["is_system"])) + "\n")
                    total += 1
    return total


def generate_s3_baseline() -> int:
    total = 0
    with open(S3_BASELINE, "w") as f:
        for name, actor in ACTORS.items():
            s3 = actor.get("s3")
            if not s3:
                continue
            me, se = s3["daily_events"]
            mb, sb = s3["daily_bytes"]
            for day in _baseline_days(actor):
                date  = BASELINE_START + timedelta(days=day)
                count = max(1, round(random.gauss(me, se)))
                for _ in range(count):
                    op      = random.choice(s3["ops"])
                    bucket  = random.choice(s3["buckets"])
                    ts      = _random_ts(date, actor["ct"]["active_hours"])
                    bytes_v = max(0, round(random.gauss(mb / me, sb / max(me, 1))))
                    f.write(json.dumps(_s3_event(name, s3["ip"], op, bucket,
                                                  ts, bytes_v,
                                                  actor["is_system"])) + "\n")
                    total += 1
    return total


def generate_vpc_baseline() -> int:
    total = 0
    with open(VPC_BASELINE, "w") as f:
        for name, actor in ACTORS.items():
            vpc = actor.get("vpc")
            if not vpc:
                continue
            mf, sf = vpc["daily_flows"]
            mb, sb = vpc["daily_bytes"]
            for day in _baseline_days(actor):
                date  = BASELINE_START + timedelta(days=day)
                count = max(1, round(random.gauss(mf, sf)))
                for _ in range(count):
                    dst_ip   = _weighted_choice(vpc["dst_ips"])
                    dst_port = _weighted_choice(vpc["dst_ports"])
                    ts       = _random_ts(date, vpc["active_hours"])
                    bytes_v  = max(0, round(random.gauss(mb / mf, sb / max(mf, 1))))
                    f.write(json.dumps(_vpc_event(vpc["src_ip"], vpc["src_eni"],
                                                   dst_ip, dst_port, vpc["protocol"],
                                                   ts, bytes_v)) + "\n")
                    total += 1
    return total


# ── Incident generators ───────────────────────────────────────────────────────

def _incident_path(day_offset: int) -> Path:
    d = INCIDENT_DAY + timedelta(days=day_offset)
    p = INCIDENT_DIR / d.strftime("%Y-%m-%d")
    p.mkdir(parents=True, exist_ok=True)
    return p


def _mallory_s3_count(day: int) -> int:
    """Linear ramp: 20 events/day (day 0) → 200 events/day (day 13)."""
    return round(20 + (200 - 20) * day / 13)


def generate_ct_incident() -> int:
    total = 0

    # Actors whose incident CT is identical to baseline (no special handling)
    CT_NORMAL = {
        "mallory_insider", "sarah_finance", "svc_backup",
        "svc_monitoring", "svc_logging", "svc_alerts", "svc_metrics",
        "eng_01", "eng_02", "eng_03", "eng_04", "eng_05", "frank_pm",
    }

    for day_offset in range(INCIDENT_DAYS):
        date = INCIDENT_DAY + timedelta(days=day_offset)
        out  = _incident_path(day_offset) / "cloudtrail_ocsf.jsonl"

        with open(out, "w") as f:

            def write(ev: dict):
                nonlocal total
                f.write(json.dumps(ev) + "\n")
                total += 1

            def normal_ct(name: str):
                ct = ACTORS[name]["ct"]
                actor = ACTORS[name]
                count = max(1, round(random.gauss(ct["daily_mean"],
                                                  ct["daily_mean"] * 0.2)))
                for _ in range(count):
                    op  = _weighted_choice(ct["ops"])
                    res = random.choice(ct["resources"])
                    ts  = _random_ts(date, ct["active_hours"])
                    write(_ct_event(name, actor["uid"], ct["ip"], ct["region"],
                                    op, res, ts, actor["is_system"]))

            # Normal actors — same behaviour every incident day
            for name in CT_NORMAL:
                normal_ct(name)

            # ── james_dev ─────────────────────────────────────────────────
            # Days 0-2: compromised creds from external IP, new region, IAM ops
            # Days 3-13: goes quiet (attacker achieved objective)
            if day_offset <= 2:
                atk_ops = ["CreateUser", "AttachUserPolicy", "ListUsers",
                           "GetObject", "DeleteBucketPolicy", "PutUserPolicy"]
                atk_resources = ["finance-data", "hr-data", "backup-bucket", "ml-data"]
                for _ in range(50):
                    op  = random.choice(atk_ops)
                    res = random.choice(atk_resources)
                    ts  = _random_ts(date, [2, 3, 4])
                    write(_ct_event("james_dev", ACTORS["james_dev"]["uid"],
                                    "185.100.200.30", "ap-southeast-1",
                                    op, res, ts, False))

            # ── svc_data_pipeline ─────────────────────────────────────────
            # Days 0-13: 10x volume, same ops (compromised, draining data-lake)
            pipe_ct = ACTORS["svc_data_pipeline"]["ct"]
            pipe_count = max(1, round(random.gauss(pipe_ct["daily_mean"] * 10,
                                                   pipe_ct["daily_mean"] * 2)))
            for _ in range(pipe_count):
                op  = _weighted_choice(pipe_ct["ops"])
                res = random.choice(pipe_ct["resources"])
                ts  = _random_ts(date, pipe_ct["active_hours"])
                write(_ct_event("svc_data_pipeline",
                                ACTORS["svc_data_pipeline"]["uid"],
                                pipe_ct["ip"], pipe_ct["region"],
                                op, res, ts, True))

            # ── petra_privesc ─────────────────────────────────────────────
            # Day 0 only: privilege escalation sequence at 3am (tight 10-min window)
            # Days 1-13: normal ops
            if day_offset == 0:
                base_dt = date.replace(hour=3, minute=0, second=0)
                sequence = [
                    (1,  "DescribeInstances",  "prod-server-1"),
                    (3,  "CreateUser",          "iam-users"),
                    (5,  "AttachUserPolicy",    "iam-policies"),
                    (7,  "CreateAccessKey",     "iam-users"),
                    (10, "DeleteTrail",         "cloudtrail-main"),
                    (12, "StopLogging",         "cloudtrail-main"),
                ]
                for (min_offset, op, res) in sequence:
                    ts = _ts(base_dt + timedelta(minutes=min_offset))
                    write(_ct_event("petra_privesc",
                                    ACTORS["petra_privesc"]["uid"],
                                    ACTORS["petra_privesc"]["ct"]["ip"],
                                    ACTORS["petra_privesc"]["ct"]["region"],
                                    op, res, ts, False))
            else:
                normal_ct("petra_privesc")

            # ── neil_c2 ───────────────────────────────────────────────────
            # Days 0-13: same ops but at 2-4am (off-hours), plus daytime recon
            neil_ct = ACTORS["neil_c2"]["ct"]
            # Off-hours events (suspicious timing)
            for _ in range(8):
                op  = _weighted_choice(neil_ct["ops"])
                res = random.choice(neil_ct["resources"])
                ts  = _random_ts(date, [2, 3, 4])
                write(_ct_event("neil_c2", ACTORS["neil_c2"]["uid"],
                                neil_ct["ip"], neil_ct["region"],
                                op, res, ts, False))
            # Daytime recon
            for _ in range(10):
                op  = _weighted_choice(neil_ct["ops"])
                res = random.choice(neil_ct["resources"])
                ts  = _random_ts(date, neil_ct["active_hours"])
                write(_ct_event("neil_c2", ACTORS["neil_c2"]["uid"],
                                neil_ct["ip"], neil_ct["region"],
                                op, res, ts, False))

            # ── oscar_ransomprep ─────────────────────────────────────────
            # Days 0-3: mass Describe burst + new ops (DescribeDBInstances, DescribeNetworkInterfaces)
            # Days 4-13: goes quiet
            if day_offset <= 3:
                oscar_ops = (["DescribeInstances"] * 20 +
                             ["DescribeSecurityGroups"] * 15 +
                             ["ListBuckets"] * 10 +
                             ["DescribeSnapshots"] * 8 +
                             ["DescribeDBInstances"] * 7 +   # new op
                             ["DescribeNetworkInterfaces"] * 5)  # new op
                oscar_resources = (["prod-server-1", "prod-server-2", "prod-db-1",
                                    "prod-db-2", "prod-subnet-1"])
                for op in oscar_ops:
                    res = random.choice(oscar_resources)
                    ts  = _random_ts(date, list(range(9, 18)))
                    write(_ct_event("oscar_ransomprep",
                                    ACTORS["oscar_ransomprep"]["uid"],
                                    ACTORS["oscar_ransomprep"]["ct"]["ip"],
                                    ACTORS["oscar_ransomprep"]["ct"]["region"],
                                    op, res, ts, False))

            # ── tom_devops ─────────────────────────────────────────────────
            # Days 0-13: EU expansion — new region, new IP, new resources, new ops
            tom_ops = ["DescribeInstances", "RunInstances", "CreateSecurityGroup",
                       "CreateSubnet", "PutObject", "DescribeVpcs"]
            tom_resources = ["eu-server-1", "eu-server-2", "eu-database-1",
                             "eu-bucket", "eu-vpc-1"]
            for _ in range(20):
                op  = random.choice(tom_ops)
                res = random.choice(tom_resources)
                ts  = _random_ts(date, list(range(8, 18)))
                write(_ct_event("tom_devops", ACTORS["tom_devops"]["uid"],
                                "10.0.1.50", "eu-west-1",
                                op, res, ts, False))
            # Also some US activity (normal)
            normal_ct("tom_devops")

            # ── bob_analytics ─────────────────────────────────────────────
            # Days 0-13: new buckets ml-experiments/ai-models (team transfer)
            bob_ct = ACTORS["bob_analytics"]["ct"]
            for _ in range(15):
                op  = _weighted_choice(bob_ct["ops"])
                res = random.choice(["ml-experiments", "ai-models", "feature-store"])
                ts  = _random_ts(date, bob_ct["active_hours"])
                write(_ct_event("bob_analytics", ACTORS["bob_analytics"]["uid"],
                                bob_ct["ip"], bob_ct["region"],
                                op, res, ts, False))

            # ── jenkins_ci ────────────────────────────────────────────────
            # Days 0-13: every day (in baseline only every 2 days) — more CI builds
            normal_ct("jenkins_ci")

            # ── alice_hr ──────────────────────────────────────────────────
            # Days 3-5: access review sequence
            if 3 <= day_offset <= 5:
                review_ops = (["ListUsers"] * 5 + ["GetUser"] * 5 +
                              ["ListAccessKeys"] * 5 + ["ListAttachedUserPolicies"] * 5)
                for op in review_ops:
                    ts = _random_ts(date, list(range(9, 17)))
                    write(_ct_event("alice_hr", ACTORS["alice_hr"]["uid"],
                                    ACTORS["alice_hr"]["ct"]["ip"],
                                    ACTORS["alice_hr"]["ct"]["region"],
                                    op, "iam-users", ts, False))
            else:
                normal_ct("alice_hr")

            # ── svc_provisioning ─────────────────────────────────────────
            # Day 6: onboarding burst (CreateUser→AddUserToGroup→AttachUserPolicy→CreateAccessKey)
            if day_offset == 6:
                onboard_seq = (["CreateUser"] * 5 + ["AddUserToGroup"] * 5 +
                               ["AttachUserPolicy"] * 5 + ["CreateAccessKey"] * 5)
                for op in onboard_seq:
                    ts = _random_ts(date, list(range(9, 17)))
                    write(_ct_event("svc_provisioning",
                                    ACTORS["svc_provisioning"]["uid"],
                                    ACTORS["svc_provisioning"]["ct"]["ip"],
                                    ACTORS["svc_provisioning"]["ct"]["region"],
                                    op, "iam-users", ts, True))
            elif day_offset in [1, 4, 9, 12]:
                # Occasional normal activity on other days
                normal_ct("svc_provisioning")

            # ── dave_keyrotation ─────────────────────────────────────────
            # Day 1: automated key rotation across 10 users
            if day_offset == 1:
                rotation_seq = (["CreateAccessKey"] * 10 +
                                ["UpdateAccessKey"] * 10 +
                                ["DeleteAccessKey"] * 10)
                for op in rotation_seq:
                    ts = _random_ts(date, list(range(9, 17)))
                    write(_ct_event("dave_keyrotation",
                                    ACTORS["dave_keyrotation"]["uid"],
                                    ACTORS["dave_keyrotation"]["ct"]["ip"],
                                    ACTORS["dave_keyrotation"]["ct"]["region"],
                                    op, "iam-users", ts, False))
            elif day_offset in [5, 10]:
                normal_ct("dave_keyrotation")

            # ── carol_pentest ─────────────────────────────────────────────
            # Days 0-1: authorized pentest from different IP, recon ops
            if day_offset <= 1:
                pentest_ops = ["DescribeInstances", "DescribeSecurityGroups",
                               "ListBuckets", "GetSecretValue",
                               "DescribeNetworkInterfaces", "DescribeVpcs",
                               "DescribeSubnets", "DescribeRouteTables"]
                for _ in range(80):
                    op  = random.choice(pentest_ops)
                    res = random.choice(["dev-server-1", "prod-server-1",
                                         "app-secrets", "vpc-main"])
                    ts  = _random_ts(date, list(range(9, 18)))
                    write(_ct_event("carol_pentest",
                                    ACTORS["carol_pentest"]["uid"],
                                    "91.100.200.50",  # pentest IP
                                    "us-east-1",
                                    op, res, ts, False))
            else:
                normal_ct("carol_pentest")

    return total


def generate_s3_incident() -> int:
    total = 0

    S3_NORMAL = {
        "petra_privesc", "oscar_ransomprep", "neil_c2",
        "svc_backup", "alice_hr", "carol_pentest",
        "svc_monitoring", "svc_alerts", "svc_metrics",
        "eng_01", "eng_02", "eng_03", "eng_04", "eng_05", "frank_pm",
    }

    for day_offset in range(INCIDENT_DAYS):
        date = INCIDENT_DAY + timedelta(days=day_offset)
        out  = _incident_path(day_offset) / "s3_accesslogs_ocsf.jsonl"

        with open(out, "w") as f:

            def write(ev: dict):
                nonlocal total
                f.write(json.dumps(ev) + "\n")
                total += 1

            def normal_s3(name: str):
                actor = ACTORS[name]
                s3 = actor.get("s3")
                if not s3:
                    return
                me, se = s3["daily_events"]
                mb, sb = s3["daily_bytes"]
                count = max(1, round(random.gauss(me, se)))
                for _ in range(count):
                    op      = random.choice(s3["ops"])
                    bucket  = random.choice(s3["buckets"])
                    ts      = _random_ts(date, actor["ct"]["active_hours"])
                    bytes_v = max(0, round(random.gauss(mb / me, sb / max(me, 1))))
                    write(_s3_event(name, s3["ip"], op, bucket, ts,
                                    bytes_v, actor["is_system"]))

            for name in S3_NORMAL:
                normal_s3(name)

            # ── james_dev ─────────────────────────────────────────────────
            # Days 0-2: mass exfiltration from external IP, 300 events, ~2GB
            if day_offset <= 2:
                count   = 300
                total_b = 2_000_000_000
                per_ev  = total_b // count
                exfil_buckets = ["finance-data", "hr-data", "backup-bucket", "ml-data"]
                for _ in range(count):
                    bucket  = random.choice(exfil_buckets)
                    ts      = _random_ts(date, [2, 3, 4])
                    bytes_v = max(0, round(random.gauss(per_ev, per_ev * 0.2)))
                    write(_s3_event("james_dev", "185.100.200.30",
                                    "GetObject", bucket, ts, bytes_v, False))

            # ── svc_data_pipeline ─────────────────────────────────────────
            # Days 0-13: 10x sustained elevation
            pipe_s3 = ACTORS["svc_data_pipeline"]["s3"]
            me, se  = pipe_s3["daily_events"]
            mb, _sb = pipe_s3["daily_bytes"]
            count   = max(1, round(random.gauss(me * 10, se * 3)))
            per_ev  = mb / me
            for _ in range(count):
                op      = random.choice(pipe_s3["ops"])
                bucket  = random.choice(pipe_s3["buckets"])
                ts      = _random_ts(date, ACTORS["svc_data_pipeline"]["ct"]["active_hours"])
                bytes_v = max(0, round(random.gauss(per_ev, per_ev * 0.2)))
                write(_s3_event("svc_data_pipeline", pipe_s3["ip"],
                                op, bucket, ts, bytes_v, True))

            # ── mallory_insider ───────────────────────────────────────────
            # Days 0-13: linear ramp 20→200 events/day
            mall_s3 = ACTORS["mallory_insider"]["s3"]
            count   = _mallory_s3_count(day_offset)
            mb, _sb = mall_s3["daily_bytes"]
            me_orig = ACTORS["mallory_insider"]["s3"]["daily_events"][0]
            per_ev  = mb / me_orig
            for _ in range(count):
                op      = random.choice(mall_s3["ops"])
                bucket  = random.choice(mall_s3["buckets"])
                ts      = _random_ts(date, ACTORS["mallory_insider"]["ct"]["active_hours"])
                bytes_v = max(0, round(random.gauss(per_ev, per_ev * 0.2)))
                write(_s3_event("mallory_insider", mall_s3["ip"],
                                op, bucket, ts, bytes_v, False))

            # ── sarah_finance ─────────────────────────────────────────────
            # Days 0-2: quarter-end spike 500 events, 150MB/day
            # Days 3-13: normal
            if day_offset <= 2:
                count  = 500
                per_ev = 150_000_000 // count
                sara_buckets = ["finance-data", "finance-reports"]
                for _ in range(count):
                    bucket  = random.choice(sara_buckets)
                    ts      = _random_ts(date, list(range(7, 20)))
                    bytes_v = max(0, round(random.gauss(per_ev, per_ev * 0.1)))
                    write(_s3_event("sarah_finance",
                                    ACTORS["sarah_finance"]["s3"]["ip"],
                                    "GetObject", bucket, ts, bytes_v, False))
            else:
                normal_s3("sarah_finance")

            # ── tom_devops ────────────────────────────────────────────────
            # Days 0-13: EU bucket (new) + normal US
            normal_s3("tom_devops")
            for _ in range(15):
                ts      = _random_ts(date, list(range(8, 18)))
                bytes_v = max(0, round(random.gauss(5_000_000, 1_000_000)))
                write(_s3_event("tom_devops",
                                "10.0.1.50",  # EU VPN IP
                                "PutObject", "eu-bucket", ts, bytes_v, False))

            # ── bob_analytics ─────────────────────────────────────────────
            # Days 0-13: new buckets ml-experiments/ai-models
            normal_s3("bob_analytics")
            bob_s3 = ACTORS["bob_analytics"]["s3"]
            for _ in range(15):
                bucket  = random.choice(["ml-experiments", "ai-models", "feature-store"])
                ts      = _random_ts(date, ACTORS["bob_analytics"]["ct"]["active_hours"])
                bytes_v = max(0, round(random.gauss(4_000_000, 800_000)))
                write(_s3_event("bob_analytics", bob_s3["ip"],
                                "GetObject", bucket, ts, bytes_v, False))

            # ── jenkins_ci ────────────────────────────────────────────────
            normal_s3("jenkins_ci")

            # ── svc_logging ───────────────────────────────────────────────
            normal_s3("svc_logging")

            # ── dave_keyrotation, svc_provisioning, alice_hr ──────────────
            # No S3 activity for these roles

    return total


def generate_vpc_incident() -> int:
    total = 0

    for day_offset in range(INCIDENT_DAYS):
        date = INCIDENT_DAY + timedelta(days=day_offset)
        out  = _incident_path(day_offset) / "vpcflow_ocsf.jsonl"

        with open(out, "w") as f:

            def write(ev: dict):
                nonlocal total
                f.write(json.dumps(ev) + "\n")
                total += 1

            def normal_vpc(name: str):
                actor = ACTORS[name]
                vpc = actor.get("vpc")
                if not vpc:
                    return
                mf, sf = vpc["daily_flows"]
                mb, sb = vpc["daily_bytes"]
                count  = max(1, round(random.gauss(mf, sf)))
                for _ in range(count):
                    dst_ip   = _weighted_choice(vpc["dst_ips"])
                    dst_port = _weighted_choice(vpc["dst_ports"])
                    ts       = _random_ts(date, vpc["active_hours"])
                    bytes_v  = max(0, round(random.gauss(mb / mf, sb / max(mf, 1))))
                    write(_vpc_event(vpc["src_ip"], vpc["src_eni"],
                                      dst_ip, dst_port, vpc["protocol"],
                                      ts, bytes_v))

            # ── svc_backup: normal (same as baseline) ─────────────────────
            normal_vpc("svc_backup")

            # ── tom_devops: normal US VPC + new EU VPC ────────────────────
            normal_vpc("tom_devops")
            # EU expansion VPC (new ENI, new destination IPs — FP for network exfil)
            for _ in range(20):
                dst_ip   = random.choice(["52.95.148.1", "52.95.150.1"])
                ts       = _random_ts(date, list(range(8, 18)))
                bytes_v  = max(0, round(random.gauss(2_500_000, 500_000)))
                write(_vpc_event("10.0.1.50", "eni-tom000002",
                                  dst_ip, 443, 6, ts, bytes_v))

            # ── james_dev: C2 exfiltration (days 0-2) ────────────────────
            if day_offset <= 2:
                count  = 200
                per_fl = 500_000_000 // count
                for _ in range(count):
                    dst_port = random.choice([4444, 8080])
                    ts       = _random_ts(date, [2, 3, 4])
                    bytes_v  = max(0, round(random.gauss(per_fl, per_fl * 0.2)))
                    write(_vpc_event("185.100.200.30", "eni-james00001",
                                      "91.200.50.10", dst_port, 6, ts, bytes_v))

            # ── svc_data_pipeline: C2 beaconing (days 0-13) ──────────────
            # Same ENI as baseline but NEW destination (91.100.50.20) — anomalous
            pipe_ct_hours = ACTORS["svc_data_pipeline"]["ct"]["active_hours"]
            # Existing legitimate flows (keep the baseline pattern going)
            normal_vpc("svc_data_pipeline")
            # Malicious C2 beaconing (regular small flows)
            for ts in _evenly_spaced_ts(date, 48, start_hour=0, end_hour=23):
                bytes_v = random.randint(500, 3_000)  # beaconing: tiny
                write(_vpc_event("10.0.0.20", "eni-pipeline001",
                                  "91.100.50.20", 4444, 6, ts, bytes_v))

            # ── mallory_insider: slow VPC drip to external (days 0-13) ───
            flow_count = random.choice([1, 2, 2, 3])
            for _ in range(flow_count):
                ts      = _random_ts(date, [17, 18])
                bytes_v = random.randint(5_000, 50_000)
                write(_vpc_event("203.10.1.110", "eni-mallory001",
                                  "185.200.100.10", 443, 6, ts, bytes_v))

            # ── neil_c2: C2 beaconing (days 0-13) ────────────────────────
            # Regular small flows at predictable intervals
            for ts in _evenly_spaced_ts(date, 30, start_hour=10, end_hour=18):
                bytes_v = random.randint(200, 1_500)  # tiny beaconing packets
                write(_vpc_event("203.10.1.130", "eni-neil00001",
                                  "185.150.100.30", 8443, 6, ts, bytes_v))

    return total


# ── Ground truth ──────────────────────────────────────────────────────────────

def save_ground_truth() -> None:
    gt = {
        "scenario": "Operation Quiet Harvest",
        "baseline_start": "2018-07-21",
        "baseline_days": BASELINE_DAYS,
        "incident_start": "2018-08-20",
        "incident_days": INCIDENT_DAYS,
        "detection_layers": {
            "ueba": "Behavioral deviation from baseline (new IP/region/ops, off-hours, volume)",
            "network_exfil": "VPC flow analysis — rare destinations, beaconing, large data out",
            "time_based_exfil": "Rolling S3 elevation — sustained increase, ramp, periodic spikes",
        },
        "actors": {
            # TRUE POSITIVES
            "james_dev": {
                "label": "MALICIOUS",
                "detectors": ["ueba", "network_exfil"],
                "days": "0-2 (acute), then quiet",
                "reason": (
                    "Stolen creds: external IP 185.100.200.30, region ap-southeast-1, "
                    "IAM ops (CreateUser/AttachUserPolicy/DeleteBucketPolicy), "
                    "300 S3 GetObject events (~2GB) at 2-4am, "
                    "C2 VPC to 91.200.50.10:4444/8080 (200 flows, ~500MB)"
                ),
                "expected_ueba_score_min": 0.60,
            },
            "svc_data_pipeline": {
                "label": "MALICIOUS",
                "detectors": ["time_based_exfil", "network_exfil"],
                "days": "0-13 (sustained)",
                "reason": (
                    "Compromised service account: 10x S3 event volume (1000/day vs 100 baseline), "
                    "C2 beaconing to 91.100.50.20:4444 via existing ENI eni-pipeline001 "
                    "(48 flows/day, 200-3000 bytes each — regular intervals)"
                ),
                "expected_timebased_detection": "sustained_elevation",
            },
            "mallory_insider": {
                "label": "MALICIOUS",
                "detectors": ["time_based_exfil", "network_exfil"],
                "days": "0-13 (gradual ramp)",
                "reason": (
                    "Insider exfiltration: S3 ramp from 20 to 200 events/day (linear), "
                    "slow VPC drip to 185.200.100.10:443 (1-3 flows/day, 5-50KB each), "
                    "same buckets/IP/ops as baseline — UEBA misses, time-based catches"
                ),
                "expected_timebased_detection": "ramp_up",
            },
            "petra_privesc": {
                "label": "MALICIOUS",
                "detectors": ["ueba"],
                "days": "0 (acute)",
                "reason": (
                    "Privilege escalation at 3am: DescribeInstances→CreateUser→"
                    "AttachUserPolicy→CreateAccessKey→DeleteTrail→StopLogging "
                    "all within 12 minutes. New ops: DeleteTrail, StopLogging, "
                    "CreateUser, AttachUserPolicy, CreateAccessKey (defense evasion + persistence)"
                ),
                "expected_ueba_score_min": 0.40,
            },
            "neil_c2": {
                "label": "MALICIOUS",
                "detectors": ["ueba", "network_exfil"],
                "days": "0-13",
                "reason": (
                    "C2 channel: 30 regular beaconing flows/day to 185.150.100.30:8443 "
                    "(200-1500 bytes each, low interval CV = regular timing). "
                    "UEBA: same CT ops but shifted to 2-4am (off-hours anomaly)"
                ),
                "expected_netexfil_detection": "c2_beaconing",
            },
            "oscar_ransomprep": {
                "label": "MALICIOUS",
                "detectors": ["ueba"],
                "days": "0-3",
                "reason": (
                    "Ransomware preparation: mass Describe/List recon burst (~65 events/day "
                    "vs baseline 10). New ops: DescribeDBInstances, DescribeNetworkInterfaces. "
                    "Mapping entire infra before deployment."
                ),
                "expected_ueba_score_min": 0.40,
            },
            # FALSE POSITIVES
            "sarah_finance": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["time_based_exfil"],
                "reason": "Quarter-end: 500 S3 reads on days 0-2 (normal annual spike for financial reporting)",
                "why_fp": "Legitimate seasonal business pattern, same buckets/IP as baseline",
            },
            "tom_devops": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["ueba", "network_exfil"],
                "reason": (
                    "EU expansion: new region eu-west-1, new IP 10.0.1.50 (EU VPN), "
                    "new resources (eu-server-*, eu-bucket), new ENI eni-tom000002, "
                    "large VPC bytes to EU S3 endpoints 52.95.148.1/52.95.150.1"
                ),
                "why_fp": "Authorized infrastructure expansion, documented change request",
            },
            "bob_analytics": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["ueba"],
                "reason": "Team transfer to ML team: accessing new buckets ml-experiments/ai-models/feature-store",
                "why_fp": "Authorized role change, new bucket access approved",
            },
            "svc_backup": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["network_exfil"],
                "reason": (
                    "Nightly backup VPC flows to S3 endpoint 52.219.100.1:443 "
                    "— 10 flows/day, ~50MB each. Large data transfer pattern looks suspicious."
                ),
                "why_fp": "Scheduled backup job, known destination in baseline VPC profile",
            },
            "jenkins_ci": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["ueba"],
                "reason": (
                    "CI/CD runs every day during incident (was every 2 days in baseline). "
                    "3-4am activity, 50 S3 events, 100MB — off-hours burst triggers UEBA."
                ),
                "why_fp": "Increased deployment cadence for release sprint, all known ops",
            },
            "alice_hr": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["ueba"],
                "reason": (
                    "Annual access review on days 3-5: ListUsers×5→GetUser×5→"
                    "ListAccessKeys×5→ListAttachedUserPolicies×5 per employee (20 employees). "
                    "Looks like IAM recon but is legitimate compliance activity."
                ),
                "why_fp": "Documented annual access review process",
            },
            "svc_provisioning": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["ueba"],
                "reason": (
                    "Onboarding burst on day 6: CreateUser×5→AddUserToGroup×5→"
                    "AttachUserPolicy×5→CreateAccessKey×5. "
                    "Looks like persistence mechanism but is normal HR onboarding."
                ),
                "why_fp": "5 new employee hires, authorized by HR",
            },
            "dave_keyrotation": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["ueba"],
                "reason": (
                    "Key rotation on day 1: CreateAccessKey×10→UpdateAccessKey×10→"
                    "DeleteAccessKey×10 across 10 users. "
                    "Triggers UEBA volume spike (3x normal CT events)."
                ),
                "why_fp": "Quarterly key rotation policy, automated script",
            },
            "carol_pentest": {
                "label": "FALSE_POSITIVE",
                "detectors_triggered": ["ueba"],
                "reason": (
                    "Authorized pentest days 0-1: from 91.100.200.50 (pentest IP), "
                    "heavy recon: DescribeInstances/DescribeSecurityGroups/ListBuckets/"
                    "GetSecretValue/DescribeNetworkInterfaces, 80 events/day. "
                    "Triggers UEBA (new IP, new ops) but authorized."
                ),
                "why_fp": "Signed SOW, approved change window, known pentest IP",
            },
            # BENIGN
            **{name: {"label": "BENIGN", "detectors_triggered": [],
                      "reason": "Normal recurring activity matching baseline profile"}
               for name in ["eng_01", "eng_02", "eng_03", "eng_04", "eng_05",
                             "svc_monitoring", "svc_logging", "svc_alerts",
                             "svc_metrics", "frank_pm"]},
        },
    }
    GROUND_TRUTH.parent.mkdir(parents=True, exist_ok=True)
    with open(GROUND_TRUTH, "w") as f:
        json.dump(gt, f, indent=2)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    incident_end = INCIDENT_DAY + timedelta(days=INCIDENT_DAYS - 1)
    print("=== Generating Advanced Dataset — Operation Quiet Harvest ===\n")
    print(f"  Baseline : {BASELINE_START:%Y-%m-%d} -> "
          f"{INCIDENT_DAY - timedelta(days=1):%Y-%m-%d} ({BASELINE_DAYS} days)")
    print(f"  Incident : {INCIDENT_DAY:%Y-%m-%d} -> {incident_end:%Y-%m-%d} "
          f"({INCIDENT_DAYS} days)")
    print(f"  Actors   : {len(ACTORS)} total "
          f"({sum(1 for a in ACTORS.values() if a['label'].startswith('TP'))} TP, "
          f"{sum(1 for a in ACTORS.values() if a['label'].startswith('FP'))} FP, "
          f"{sum(1 for a in ACTORS.values() if a['label'] == 'BENIGN')} benign)\n")

    n = generate_ct_baseline();  print(f"  CT  baseline : {n:>7,} events")
    n = generate_s3_baseline();  print(f"  S3  baseline : {n:>7,} events")
    n = generate_vpc_baseline(); print(f"  VPC baseline : {n:>7,} flows")
    print()
    n = generate_ct_incident();  print(f"  CT  incident : {n:>7,} events  ({INCIDENT_DAYS} days)")
    n = generate_s3_incident();  print(f"  S3  incident : {n:>7,} events  ({INCIDENT_DAYS} days)")
    n = generate_vpc_incident(); print(f"  VPC incident : {n:>7,} flows   ({INCIDENT_DAYS} days)")

    save_ground_truth()

    print(f"\nOutput -> {BASE_DIR}/")
    print(f"  OCSF data -> {OCSF_DIR}/")
    print(f"  Ground truth -> {GROUND_TRUTH}")
    print()
    print("Run pipeline:")
    print(f"  python3 run_ueba_v3.py \\")
    print(f"      --input  {OCSF_DIR} \\")
    print(f"      --output {BASE_DIR}/output \\")
    print(f"      --start  2018-08-20 --end 2018-09-02")


if __name__ == "__main__":
    main()
