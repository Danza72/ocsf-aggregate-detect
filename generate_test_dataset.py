#!/usr/bin/env python3
"""
generate_test_dataset.py

Generates a synthetic test dataset with a known attack storyline to validate
the UEBA pipeline. All output goes to test_data/.

Storyline: "Operation Data Grab — Extended"
  10 actors over 30-day baseline (Jul 21 – Aug 19).
  Incident window: 14 days (Aug 20 – Sep 2).

  Why 30 days?
    svc_monthly runs on Aug 1 (day 11). A 14-day baseline (Aug 6-19) misses
    it entirely → false positive on incident day.

  Actors:
    alice_m    — marketing analyst (credentials stolen, detected Day 1 by UEBA)
    dave_f     — finance analyst (unusual hours + new bucket, Day 1 UEBA)
    oscar_r    — developer (sequence attack Day 1 — UEBA misses, sequence layer catches)
    mallory_t  — compliance analyst (steady 3× S3 exfiltration — time-based catches)
    neil_k     — analytics engineer (gradual 1.5×→4× ramp — time-based catches)
    petra_v    — reporting analyst (periodic 5× spikes — time-based catches)
    bob_d      — DevOps engineer (benign throughout)
    carol_s    — data scientist (benign throughout)
    svc_backup — nightly backup job (benign)
    svc_monthly— monthly archival job (benign, captured in 30-day baseline)

Detection layer coverage:
  UEBA       : alice_m (stolen creds), dave_f (unusual hours/resource)
  Sequence   : oscar_r (recon→secret→key→exfil in 20-min window, all known ops)
  Time-based : mallory_t (steady), neil_k (ramp), petra_v (periodic spikes)
"""

import json
import random
from pathlib import Path
from datetime import datetime, timedelta, timezone

random.seed(42)

# ── Output paths ─────────────────────────────────────────────────────────────
BASE_DIR     = Path("test_data")
OCSF_DIR     = BASE_DIR / "ocsf_out"
INCIDENT_DIR = OCSF_DIR / "incident"
OCSF_DIR.mkdir(parents=True, exist_ok=True)

CT_BASELINE_OUT  = OCSF_DIR / "cloudtrail_synthetic_baseline.jsonl"
S3_BASELINE_OUT  = OCSF_DIR / "s3_synthetic_baseline.jsonl"
VPC_BASELINE_OUT = OCSF_DIR / "vpcflow_synthetic_baseline.jsonl"
GROUND_TRUTH_OUT = BASE_DIR / "ground_truth.json"

ACCOUNT_ID    = "111122223333"
BASELINE_START = datetime(2018, 7, 21, tzinfo=timezone.utc)
INCIDENT_DAY   = datetime(2018, 8, 20, tzinfo=timezone.utc)
DAYS           = 30
INCIDENT_DAYS  = 14

# Aug 1 = day 11 of the 30-day window (Jul 21 + 11 days).
MONTHLY_RUN_DAY = 11

# Days (0-indexed from Aug 20) where petra_v spikes
PETRA_SPIKE_DAYS = {0, 2, 5, 8, 11, 13}

# ── Actor baseline profiles ───────────────────────────────────────────────────
ACTORS = {
    "alice_m": {
        "is_system": False,
        "uid": "AIDA111ALICE111",
        "ct": {
            "ip":           "203.10.1.10",
            "region":       "us-east-1",
            "ops":          {"GetObject": 5, "ListBuckets": 3, "HeadObject": 2},
            "resources":    ["marketing-data", "marketing-reports"],
            "active_hours": [9, 10, 11, 12, 13, 14, 15, 16],
            "daily_mean":   15,
        },
        "s3": {
            "ops":          ["GetObject", "HeadObject"],
            "buckets":      ["marketing-data", "marketing-reports"],
            "ip":           "203.10.1.10",
            "daily_events": (20, 4),
            "daily_bytes":  (500_000, 80_000),
        },
        "vpc": None,
    },
    "bob_d": {
        "is_system": False,
        "uid": "AIDA111BOB1111",
        "ct": {
            "ip":           "203.10.1.20",
            "region":       "us-west-2",
            "ops":          {"DescribeInstances": 3, "StartInstances": 1,
                             "GetObject": 2, "PutObject": 1,
                             "DescribeSecurityGroups": 2, "StopInstances": 1},
            "resources":    ["devops-artifacts", "build-outputs", "prod-server-1"],
            "active_hours": [8, 9, 10, 11, 14, 15, 16, 17],
            "daily_mean":   30,
        },
        "s3": {
            "ops":          ["GetObject", "PutObject", "ListBuckets"],
            "buckets":      ["devops-artifacts", "build-outputs"],
            "ip":           "203.10.1.20",
            "daily_events": (25, 5),
            "daily_bytes":  (2_000_000, 400_000),
        },
        "vpc": {
            "src_ip":       "203.10.1.20",
            "src_eni":      "eni-bob000001",
            "dst_ips":      {"54.10.1.1": 4, "52.20.2.2": 3, "34.30.3.3": 3},
            "dst_ports":    {443: 6, 80: 3, 22: 1},
            "protocol":     6,
            "active_hours": list(range(8, 18)),
            "daily_flows":  (50, 8),
            "daily_bytes":  (5_000_000, 800_000),
        },
    },
    "carol_s": {
        "is_system": False,
        "uid": "AIDA111CAROL11",
        "ct": {
            "ip":           "203.10.1.30",
            "region":       "us-east-1",
            "ops":          {"GetObject": 6, "ListBuckets": 2,
                             "PutObject": 1, "HeadObject": 1},
            "resources":    ["ml-data", "raw-data", "processed-data"],
            "active_hours": [10, 11, 12, 13, 14, 15],
            "daily_mean":   20,
        },
        "s3": {
            "ops":          ["GetObject", "PutObject", "ListBuckets"],
            "buckets":      ["ml-data", "raw-data", "processed-data"],
            "ip":           "203.10.1.30",
            "daily_events": (40, 7),
            "daily_bytes":  (10_000_000, 2_000_000),
        },
        "vpc": None,
    },
    "dave_f": {
        "is_system": False,
        "uid": "AIDA111DAVE111",
        "ct": {
            "ip":           "203.10.1.40",
            "region":       "us-east-1",
            "ops":          {"GetObject": 6, "ListBuckets": 3, "HeadObject": 1},
            "resources":    ["finance-data"],
            "active_hours": [9, 10, 11, 12, 13, 14],
            "daily_mean":   10,
        },
        "s3": {
            "ops":          ["GetObject", "ListBuckets"],
            "buckets":      ["finance-data"],
            "ip":           "203.10.1.40",
            "daily_events": (10, 2),
            "daily_bytes":  (200_000, 40_000),
        },
        "vpc": None,
    },
    "svc_backup": {
        "is_system": True,
        "uid": "AIDA111SVC1111",
        "ct": {
            "ip":           "10.0.0.5",
            "region":       "us-east-1",
            "ops":          {"PutObject": 7, "ListBuckets": 3},
            "resources":    ["backup-bucket"],
            "active_hours": [2, 3],
            "daily_mean":   10,
        },
        "s3": {
            "ops":          ["PutObject", "ListBuckets"],
            "buckets":      ["backup-bucket"],
            "ip":           "10.0.0.5",
            "daily_events": (10, 1),
            "daily_bytes":  (50_000_000, 5_000_000),
        },
        "vpc": None,
    },
    "svc_monthly": {
        "is_system":      True,
        "uid":            "AIDA111MTHLY1",
        "run_day_offset": MONTHLY_RUN_DAY,
        "ct": {
            "ip":           "10.0.0.20",
            "region":       "us-east-1",
            "ops":          {"PutObject": 6, "CreateSnapshot": 2,
                             "DescribeSnapshots": 1, "ListBuckets": 1},
            "resources":    ["archive-bucket", "monthly-reports"],
            "active_hours": [1, 2],
            "daily_mean":   80,
        },
        "s3": {
            "ops":          ["PutObject", "ListBuckets"],
            "buckets":      ["archive-bucket", "monthly-reports"],
            "ip":           "10.0.0.20",
            "daily_events": (200, 20),
            "daily_bytes":  (500_000_000, 50_000_000),
        },
        "vpc": None,
    },

    # ── Time-based actors (slow/low exfiltration — UEBA misses each day) ─────

    "mallory_t": {
        "is_system": False,
        "uid": "AIDA111MALL111",
        "ct": {
            "ip":           "203.10.1.50",
            "region":       "us-east-1",
            "ops":          {"GetObject": 6, "HeadObject": 2, "ListBuckets": 2},
            "resources":    ["compliance-reports"],
            "active_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
            "daily_mean":   12,
        },
        "s3": {
            "ops":          ["GetObject", "HeadObject"],
            "buckets":      ["compliance-reports"],
            "ip":           "203.10.1.50",
            "daily_events": (15, 3),
            "daily_bytes":  (8_000_000, 1_500_000),
        },
        "vpc": None,
    },

    "neil_k": {
        "is_system": False,
        "uid": "AIDA111NEIL111",
        "ct": {
            "ip":           "203.10.1.60",
            "region":       "us-east-1",
            "ops":          {"GetObject": 5, "ListBuckets": 3, "DescribeInstances": 2},
            "resources":    ["analytics-data", "dev-server-2"],
            "active_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
            "daily_mean":   10,
        },
        "s3": {
            "ops":          ["GetObject", "ListBuckets"],
            "buckets":      ["analytics-data"],
            "ip":           "203.10.1.60",
            "daily_events": (12, 2),
            "daily_bytes":  (5_000_000, 1_000_000),
        },
        "vpc": None,
    },

    "petra_v": {
        "is_system": False,
        "uid": "AIDA111PETR111",
        "ct": {
            "ip":           "203.10.1.70",
            "region":       "us-east-1",
            "ops":          {"GetObject": 5, "PutObject": 3, "ListBuckets": 2},
            "resources":    ["reports-data", "report-exports"],
            "active_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
            "daily_mean":   8,
        },
        "s3": {
            "ops":          ["GetObject", "PutObject", "ListBuckets"],
            "buckets":      ["reports-data", "report-exports"],
            "ip":           "203.10.1.70",
            "daily_events": (10, 2),
            "daily_bytes":  (3_000_000, 500_000),
        },
        "vpc": None,
    },

    # ── Sequence actor (known ops/resources — UEBA misses, sequence layer catches)
    "oscar_r": {
        "is_system": False,
        "uid": "AIDA111OSCA111",
        "ct": {
            "ip":           "203.10.1.80",
            "region":       "us-east-1",
            # All ops below appear in baseline so none fire as new_operation
            "ops":          {"GetObject": 6, "ListBuckets": 3, "DescribeInstances": 2,
                             "GetSecretValue": 2, "PutObject": 1, "CreateAccessKey": 1},
            "resources":    ["analytics-data", "dev-exports", "dev-server-1", "app-secrets"],
            "active_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
            "daily_mean":   15,
        },
        "s3":  None,
        "vpc": None,
    },
}

TIME_BASED_ACTORS = {"mallory_t", "neil_k", "petra_v"}


# ── Incident day 0 overrides ─────────────────────────────────────────────────

ATTACKER = {
    "actor": "alice_m",
    "ct": {
        "ip":          "185.220.101.5",
        "region":      "ap-southeast-1",
        "ops":         ["CreateUser", "AttachUserPolicy", "ListUsers",
                        "GetObject", "DeleteBucketPolicy", "PutUserPolicy"],
        "resources":   ["marketing-data", "finance-data", "ml-data", "backup-bucket"],
        "hours":       [2, 3, 4],
        "event_count": 45,
    },
    "s3": {
        "ops":         ["GetObject", "ListBuckets"],
        "buckets":     ["finance-data", "ml-data", "backup-bucket"],
        "ip":          "185.220.101.5",
        "event_count": 200,
        "bytes_total": 500_000_000,
    },
    "vpc": {
        "src_ip":      "185.220.101.5",
        "src_eni":     "eni-atk000001",
        "dst_ips":     ["91.108.4.1", "91.108.56.1", "149.154.167.1"],
        "dst_ports":   [443, 8080, 4444],
        "protocol":    6,
        "hours":       [2, 3, 4],
        "flow_count":  500,
        "bytes_total": 800_000_000,
    },
}

INCIDENT_DAVE = {
    "ct": {
        "ip":          "203.10.1.40",
        "region":      "us-east-1",
        "ops":         ["GetObject", "ListBuckets", "PutObject"],
        "resources":   ["finance-data", "finance-exports"],
        "hours":       [1, 2, 3],
        "event_count": 15,
    },
    "s3": {
        "ops":         ["GetObject", "PutObject"],
        "buckets":     ["finance-data", "finance-exports"],
        "ip":          "203.10.1.40",
        "event_count": 20,
        "bytes_total": 800_000,
    },
}

INCIDENT_MONTHLY = {
    "ct": {
        "ops":         ["PutObject", "CreateSnapshot", "DescribeSnapshots", "ListBuckets"],
        "resources":   ["archive-bucket", "monthly-reports"],
        "hours":       [1, 2],
        "event_count": 80,
    },
    "s3": {
        "ops":         ["PutObject", "ListBuckets"],
        "buckets":     ["archive-bucket", "monthly-reports"],
        "event_count": 200,
        "bytes_total": 500_000_000,
    },
}

# oscar_r: tight 20-min sequence of known ops at 9am — sequence layer catches this
INCIDENT_OSCAR = {
    "ip":     "203.10.1.80",
    "region": "us-east-1",
    "hour":   9,
    "events": [
        {"op": "DescribeInstances",  "resource": "dev-server-1",   "minute_offset": 1},
        {"op": "GetSecretValue",     "resource": "app-secrets",    "minute_offset": 5},
        {"op": "CreateAccessKey",    "resource": "analytics-data", "minute_offset": 12},
        {"op": "PutObject",          "resource": "dev-exports",    "minute_offset": 19},
    ],
}


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def _ts(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _random_ts(base_date: datetime, hours: list) -> int:
    h = random.choice(hours)
    m = random.randint(0, 59)
    s = random.randint(0, 59)
    return _ts(base_date.replace(hour=h, minute=m, second=s))


def _weighted_choice(weights: dict):
    keys  = list(weights.keys())
    vals  = list(weights.values())
    total = sum(vals)
    r     = random.random() * total
    cum   = 0
    for k, v in zip(keys, vals):
        cum += v
        if r <= cum:
            return k
    return keys[-1]


def _baseline_days(actor: dict) -> list[int]:
    offset = actor.get("run_day_offset")
    if offset is not None:
        return [offset]
    return list(range(DAYS))


def _volume_mult(name: str, day: int) -> float:
    """Incident-day volume multiplier for time-based actors."""
    if name == "mallory_t":
        return 3.0
    if name == "neil_k":
        if day < 4: return 1.5
        if day < 8: return 2.5
        return 4.0
    if name == "petra_v":
        return 5.0 if day in PETRA_SPIKE_DAYS else 1.0
    return 1.0


def _incident_path(day_offset: int) -> Path:
    d = INCIDENT_DAY + timedelta(days=day_offset)
    p = INCIDENT_DIR / d.strftime("%Y-%m-%d")
    p.mkdir(parents=True, exist_ok=True)
    return p


# ── OCSF event builders ───────────────────────────────────────────────────────

def _ct_event(name: str, uid: str, ip: str, region: str,
              op: str, resource: str, ts: int, is_system: bool) -> dict:
    return {
        "category_uid": 6,
        "class_uid":    6003,
        "time":         ts,
        "actor": {
            "user": {
                "name":    name,
                "uid":     uid,
                "uid_alt": f"arn:aws:iam::{ACCOUNT_ID}:user/{name}",
                "type":    "AssumedRole" if is_system else "IAMUser",
            }
        },
        "api":          {"operation": op},
        "src_endpoint": {"ip": ip},
        "cloud":        {"provider": "AWS", "region": region,
                         "account": {"uid": ACCOUNT_ID}},
        "resources":    [{"name": resource}] if resource else [],
        "unmapped":     {"is_system_actor": is_system},
    }


def _s3_event(name: str, ip: str, op: str, bucket: str,
              ts: int, bytes_val: int, is_system: bool,
              response_code: int = 200) -> dict:
    return {
        "category_uid": 6,
        "class_uid":    6003,
        "time":         ts,
        "actor":        {"user": {"name": name}},
        "api":          {"operation": op,
                         "response": {"code": response_code}},
        "src_endpoint": {"ip": ip},
        "resources":    [{"name": bucket}],
        "unmapped":     {"bytes_sent": str(bytes_val),
                         "is_system_actor": is_system},
    }


def _vpc_event(src_ip: str, eni: str, dst_ip: str,
               dst_port: int, proto: int, ts: int,
               bytes_val: int, action: str = "ACCEPT") -> dict:
    return {
        "category_uid":    4,
        "class_uid":       4001,
        "time":            ts,
        "src_endpoint":    {"ip": src_ip, "interface_uid": eni,
                            "port": random.randint(1024, 65535)},
        "dst_endpoint":    {"ip": dst_ip, "port": dst_port},
        "connection_info": {"protocol_num": proto},
        "traffic":         {"bytes": bytes_val,
                            "packets": random.randint(1, 20)},
        "unmapped":        {"action": action, "is_system_actor": False},
    }


# ── Baseline generators ───────────────────────────────────────────────────────

def generate_ct_baseline() -> int:
    total = 0
    with open(CT_BASELINE_OUT, "w") as f:
        for name, actor in ACTORS.items():
            ct         = actor["ct"]
            op_weights = ct["ops"]
            for day in _baseline_days(actor):
                date  = BASELINE_START + timedelta(days=day)
                count = max(1, round(random.gauss(ct["daily_mean"],
                                                  ct["daily_mean"] * 0.2)))
                for _ in range(count):
                    op       = _weighted_choice(op_weights)
                    resource = random.choice(ct["resources"])
                    ts       = _random_ts(date, ct["active_hours"])
                    ev       = _ct_event(name, actor["uid"], ct["ip"],
                                         ct["region"], op, resource,
                                         ts, actor["is_system"])
                    f.write(json.dumps(ev) + "\n")
                    total += 1
    return total


def generate_s3_baseline() -> int:
    total = 0
    with open(S3_BASELINE_OUT, "w") as f:
        for name, actor in ACTORS.items():
            s3 = actor.get("s3")
            if not s3:
                continue
            mean_ev, std_ev = s3["daily_events"]
            mean_by, std_by = s3["daily_bytes"]
            for day in _baseline_days(actor):
                date  = BASELINE_START + timedelta(days=day)
                count = max(1, round(random.gauss(mean_ev, std_ev)))
                for _ in range(count):
                    op      = random.choice(s3["ops"])
                    bucket  = random.choice(s3["buckets"])
                    ts      = _random_ts(date, actor["ct"]["active_hours"])
                    bytes_v = max(0, round(random.gauss(
                                  mean_by / mean_ev, std_by / max(mean_ev, 1))))
                    ev      = _s3_event(name, s3["ip"], op, bucket, ts,
                                        bytes_v, actor["is_system"])
                    f.write(json.dumps(ev) + "\n")
                    total += 1
    return total


def generate_vpc_baseline() -> int:
    total = 0
    with open(VPC_BASELINE_OUT, "w") as f:
        for name, actor in ACTORS.items():
            vpc = actor.get("vpc")
            if not vpc:
                continue
            mean_fl, std_fl = vpc["daily_flows"]
            mean_by, std_by = vpc["daily_bytes"]
            for day in _baseline_days(actor):
                date  = BASELINE_START + timedelta(days=day)
                count = max(1, round(random.gauss(mean_fl, std_fl)))
                for _ in range(count):
                    dst_ip   = _weighted_choice(vpc["dst_ips"])
                    dst_port = _weighted_choice(vpc["dst_ports"])
                    ts       = _random_ts(date, vpc["active_hours"])
                    bytes_v  = max(0, round(random.gauss(
                                   mean_by / mean_fl, std_by / max(mean_fl, 1))))
                    ev       = _vpc_event(vpc["src_ip"], vpc["src_eni"],
                                          dst_ip, dst_port, vpc["protocol"],
                                          ts, bytes_v)
                    f.write(json.dumps(ev) + "\n")
                    total += 1
    return total


# ── Incident generators (14 days) ─────────────────────────────────────────────

# Actors handled separately per-day; skip them in the normal recurring loop
_CT_SKIP = {"alice_m", "dave_f", "svc_monthly", "oscar_r"} | TIME_BASED_ACTORS
_S3_SKIP = {"alice_m", "dave_f", "svc_monthly"} | TIME_BASED_ACTORS


def generate_ct_incident() -> int:
    total = 0
    for day_offset in range(INCIDENT_DAYS):
        incident_date = INCIDENT_DAY + timedelta(days=day_offset)
        out = _incident_path(day_offset) / "cloudtrail_ocsf.jsonl"

        with open(out, "w") as f:

            # Normal recurring actors — same behaviour as baseline
            for name, actor in ACTORS.items():
                if name in _CT_SKIP:
                    continue
                ct    = actor["ct"]
                count = max(1, round(random.gauss(ct["daily_mean"],
                                                  ct["daily_mean"] * 0.2)))
                for _ in range(count):
                    op       = _weighted_choice(ct["ops"])
                    resource = random.choice(ct["resources"])
                    ts       = _random_ts(incident_date, ct["active_hours"])
                    ev       = _ct_event(name, actor["uid"], ct["ip"],
                                         ct["region"], op, resource, ts,
                                         actor["is_system"])
                    f.write(json.dumps(ev) + "\n")
                    total += 1

            # Time-based actors — same ops/IP/region, elevated volume
            for name in TIME_BASED_ACTORS:
                actor = ACTORS[name]
                ct    = actor["ct"]
                mult  = _volume_mult(name, day_offset)
                count = max(1, round(random.gauss(ct["daily_mean"] * mult,
                                                  ct["daily_mean"] * 0.2)))
                for _ in range(count):
                    op       = _weighted_choice(ct["ops"])
                    resource = random.choice(ct["resources"])
                    ts       = _random_ts(incident_date, ct["active_hours"])
                    ev       = _ct_event(name, actor["uid"], ct["ip"],
                                         ct["region"], op, resource, ts,
                                         actor["is_system"])
                    f.write(json.dumps(ev) + "\n")
                    total += 1

            # Day 0 only — the acute incident
            if day_offset == 0:

                # Attacker using alice_m credentials
                atk = ATTACKER["ct"]
                for _ in range(atk["event_count"]):
                    op       = random.choice(atk["ops"])
                    resource = random.choice(atk["resources"])
                    ts       = _random_ts(incident_date, atk["hours"])
                    ev       = _ct_event(ATTACKER["actor"], ACTORS["alice_m"]["uid"],
                                          atk["ip"], atk["region"],
                                          op, resource, ts, False)
                    f.write(json.dumps(ev) + "\n")
                    total += 1

                # dave_f — unusual hours, new operations/resource
                dave_ct = INCIDENT_DAVE["ct"]
                for _ in range(dave_ct["event_count"]):
                    op       = random.choice(dave_ct["ops"])
                    resource = random.choice(dave_ct["resources"])
                    ts       = _random_ts(incident_date, dave_ct["hours"])
                    ev       = _ct_event("dave_f", ACTORS["dave_f"]["uid"],
                                          dave_ct["ip"], dave_ct["region"],
                                          op, resource, ts, False)
                    f.write(json.dumps(ev) + "\n")
                    total += 1

                # svc_monthly — on schedule, same ops/hours as baseline
                m  = ACTORS["svc_monthly"]
                mi = INCIDENT_MONTHLY["ct"]
                for _ in range(mi["event_count"]):
                    op       = random.choice(mi["ops"])
                    resource = random.choice(mi["resources"])
                    ts       = _random_ts(incident_date, mi["hours"])
                    ev       = _ct_event("svc_monthly", m["uid"],
                                          m["ct"]["ip"], m["ct"]["region"],
                                          op, resource, ts, True)
                    f.write(json.dumps(ev) + "\n")
                    total += 1

                # oscar_r — known ops in a tight 20-min recon→exfil sequence
                oscar = ACTORS["oscar_r"]
                io    = INCIDENT_OSCAR
                base_dt = incident_date.replace(hour=io["hour"], minute=0, second=0)
                for ev_def in io["events"]:
                    ev = _ct_event(
                        "oscar_r", oscar["uid"], io["ip"], io["region"],
                        ev_def["op"], ev_def["resource"],
                        _ts(base_dt + timedelta(minutes=ev_def["minute_offset"])),
                        False,
                    )
                    f.write(json.dumps(ev) + "\n")
                    total += 1

    return total


def generate_s3_incident() -> int:
    total = 0
    for day_offset in range(INCIDENT_DAYS):
        incident_date = INCIDENT_DAY + timedelta(days=day_offset)
        out = _incident_path(day_offset) / "s3_accesslogs_ocsf.jsonl"

        with open(out, "w") as f:

            # Normal recurring actors
            for name, actor in ACTORS.items():
                if name in _S3_SKIP or not actor.get("s3"):
                    continue
                s3          = actor["s3"]
                mean_ev, std_ev = s3["daily_events"]
                mean_by, std_by = s3["daily_bytes"]
                count = max(1, round(random.gauss(mean_ev, std_ev)))
                for _ in range(count):
                    op      = random.choice(s3["ops"])
                    bucket  = random.choice(s3["buckets"])
                    ts      = _random_ts(incident_date, actor["ct"]["active_hours"])
                    bytes_v = max(0, round(random.gauss(
                                  mean_by / mean_ev, std_by / max(mean_ev, 1))))
                    ev      = _s3_event(name, s3["ip"], op, bucket, ts,
                                        bytes_v, actor["is_system"])
                    f.write(json.dumps(ev) + "\n")
                    total += 1

            # Time-based actors — same ops/buckets/IP, elevated volume
            for name in TIME_BASED_ACTORS:
                actor = ACTORS[name]
                s3    = actor.get("s3")
                if not s3:
                    continue
                mean_ev, std_ev = s3["daily_events"]
                mean_by, std_by = s3["daily_bytes"]
                mult  = _volume_mult(name, day_offset)
                count = max(1, round(random.gauss(mean_ev * mult, std_ev)))
                per_ev_bytes = mean_by / mean_ev
                for _ in range(count):
                    op      = random.choice(s3["ops"])
                    bucket  = random.choice(s3["buckets"])
                    ts      = _random_ts(incident_date, actor["ct"]["active_hours"])
                    bytes_v = max(0, round(random.gauss(
                                  per_ev_bytes, std_by / max(mean_ev, 1))))
                    ev      = _s3_event(name, s3["ip"], op, bucket, ts,
                                        bytes_v, actor["is_system"])
                    f.write(json.dumps(ev) + "\n")
                    total += 1

            # Day 0 only
            if day_offset == 0:

                # Attacker S3 exfiltration
                atk    = ATTACKER["s3"]
                per_ev = atk["bytes_total"] // atk["event_count"]
                for _ in range(atk["event_count"]):
                    op      = random.choice(atk["ops"])
                    bucket  = random.choice(atk["buckets"])
                    ts      = _random_ts(incident_date, ATTACKER["ct"]["hours"])
                    bytes_v = max(0, round(random.gauss(per_ev, per_ev * 0.2)))
                    ev      = _s3_event(ATTACKER["actor"], atk["ip"],
                                         op, bucket, ts, bytes_v, False)
                    f.write(json.dumps(ev) + "\n")
                    total += 1

                # dave_f — new bucket
                dave_s3 = INCIDENT_DAVE["s3"]
                per_ev  = dave_s3["bytes_total"] // dave_s3["event_count"]
                for _ in range(dave_s3["event_count"]):
                    op      = random.choice(dave_s3["ops"])
                    bucket  = random.choice(dave_s3["buckets"])
                    ts      = _random_ts(incident_date, INCIDENT_DAVE["ct"]["hours"])
                    bytes_v = max(0, round(random.gauss(per_ev, per_ev * 0.1)))
                    ev      = _s3_event("dave_f", ACTORS["dave_f"]["s3"]["ip"],
                                         op, bucket, ts, bytes_v, False)
                    f.write(json.dumps(ev) + "\n")
                    total += 1

                # svc_monthly — same buckets/volume as baseline run
                m      = ACTORS["svc_monthly"]
                mi     = INCIDENT_MONTHLY["s3"]
                per_ev = mi["bytes_total"] // mi["event_count"]
                for _ in range(mi["event_count"]):
                    op      = random.choice(mi["ops"])
                    bucket  = random.choice(m["s3"]["buckets"])
                    ts      = _random_ts(incident_date, m["ct"]["active_hours"])
                    bytes_v = max(0, round(random.gauss(per_ev, per_ev * 0.1)))
                    ev      = _s3_event("svc_monthly", m["s3"]["ip"],
                                         op, bucket, ts, bytes_v, True)
                    f.write(json.dumps(ev) + "\n")
                    total += 1

    return total


def generate_vpc_incident() -> int:
    total = 0
    for day_offset in range(INCIDENT_DAYS):
        incident_date = INCIDENT_DAY + timedelta(days=day_offset)
        out = _incident_path(day_offset) / "vpcflow_ocsf.jsonl"

        with open(out, "w") as f:

            # bob_d — normal all 14 days
            bob_vpc         = ACTORS["bob_d"]["vpc"]
            mean_fl, std_fl = bob_vpc["daily_flows"]
            mean_by, std_by = bob_vpc["daily_bytes"]
            count = max(1, round(random.gauss(mean_fl, std_fl)))
            for _ in range(count):
                dst_ip   = _weighted_choice(bob_vpc["dst_ips"])
                dst_port = _weighted_choice(bob_vpc["dst_ports"])
                ts       = _random_ts(incident_date, bob_vpc["active_hours"])
                bytes_v  = max(0, round(random.gauss(
                               mean_by / mean_fl, std_by / max(mean_fl, 1))))
                ev       = _vpc_event(bob_vpc["src_ip"], bob_vpc["src_eni"],
                                       dst_ip, dst_port, bob_vpc["protocol"],
                                       ts, bytes_v)
                f.write(json.dumps(ev) + "\n")
                total += 1

            # Day 0 only — attacker VPC C2 traffic
            if day_offset == 0:
                atk    = ATTACKER["vpc"]
                per_fl = atk["bytes_total"] // atk["flow_count"]
                for _ in range(atk["flow_count"]):
                    dst_ip   = random.choice(atk["dst_ips"])
                    dst_port = random.choice(atk["dst_ports"])
                    ts       = _random_ts(incident_date, atk["hours"])
                    bytes_v  = max(0, round(random.gauss(per_fl, per_fl * 0.2)))
                    ev       = _vpc_event(atk["src_ip"], atk["src_eni"],
                                           dst_ip, dst_port, atk["protocol"],
                                           ts, bytes_v)
                    f.write(json.dumps(ev) + "\n")
                    total += 1

    return total


# ── Ground truth ──────────────────────────────────────────────────────────────

def save_ground_truth() -> None:
    gt = {
        "scenario":       "Operation Data Grab — Extended (3-layer detection)",
        "baseline_start": "2018-07-21",
        "baseline_days":  DAYS,
        "incident_start": "2018-08-20",
        "incident_days":  INCIDENT_DAYS,
        "monthly_job_note": (
            f"svc_monthly baseline run on day {MONTHLY_RUN_DAY} "
            f"({BASELINE_START + timedelta(days=MONTHLY_RUN_DAY):%Y-%m-%d}). "
            "Would be missed entirely with a 14-day baseline window."
        ),
        "detection_layers": {
            "ueba":      "Per-actor behavioral deviation — catches stolen creds, unusual hours/resources",
            "sequence":  "Intra-session API call chains — catches recon→escalation→exfil even with known ops",
            "time_based":"Rolling risk accumulation — catches slow/low patterns invisible to single-day scoring",
        },
        "actors": {
            "alice_m": {
                "label":              "MALICIOUS",
                "detection_layer":    "ueba",
                "reason":             "Stolen credentials — new region, new IP, IAM ops, mass S3 exfiltration, C2 VPC at 2–4am",
                "present_days":       [0],
                "expected_score_min": 0.60,
                "sources_expected":   ["cloudtrail", "s3", "vpc"],
                "dimensions_expected": {
                    "cloudtrail": ["new_operation", "new_region",
                                   "new_ip_known_region", "low_frequency_hour"],
                    "s3":         ["new_bucket", "new_src_ip",
                                   "bytes_zscore", "event_zscore"],
                    "vpc":        ["new_dst_ip", "new_dst_port",
                                   "bytes_zscore", "flow_zscore"],
                },
            },
            "dave_f": {
                "label":              "SUSPICIOUS",
                "detection_layer":    "ueba",
                "reason":             "Activity at 1–3am (normal: 9am–2pm), new bucket finance-exports, new CT operation PutObject",
                "present_days":       [0],
                "expected_score_min": 0.25,
                "expected_score_max": 0.70,
                "sources_expected":   ["cloudtrail", "s3"],
                "dimensions_expected": {
                    "cloudtrail": ["low_frequency_hour", "new_operation", "new_resource"],
                    "s3":         ["new_bucket"],
                },
            },
            "oscar_r": {
                "label":              "UEBA_MISS",
                "detection_layer":    "sequence",
                "reason":             (
                    "All ops (DescribeInstances→GetSecretValue→CreateAccessKey→PutObject) "
                    "are in baseline. UEBA sees no novelty. Sequence layer catches the "
                    "20-min recon→secret→key→exfil chain."
                ),
                "present_days":       [0],
                "expected_score_max": 0.20,
            },
            "mallory_t": {
                "label":              "UEBA_MISS",
                "detection_layer":    "time_based",
                "reason":             "Steady 3× S3 read volume every day. Same IP/ops/buckets — UEBA volume fires but score stays below threshold. Rolling accumulator catches sustained elevation.",
                "present_days":       "all",
                "expected_score_max_per_day": 0.45,
                "volume_pattern":     "constant_3x",
            },
            "neil_k": {
                "label":              "UEBA_MISS",
                "detection_layer":    "time_based",
                "reason":             "Gradual ramp: 1.5× (days 0–3) → 2.5× (days 4–7) → 4× (days 8–13). No single day crosses alert threshold. Trend/slope detection catches escalation.",
                "present_days":       "all",
                "expected_score_max_per_day": 0.45,
                "volume_pattern":     "ramp_1.5x_to_4x",
            },
            "petra_v": {
                "label":              "UEBA_MISS",
                "detection_layer":    "time_based",
                "reason":             f"5× spikes on days {sorted(PETRA_SPIKE_DAYS)}, baseline volume on other days. Each spike day scores below threshold individually. Cumulative anomaly detection catches the pattern.",
                "present_days":       "all",
                "expected_score_max_per_day": 0.45,
                "volume_pattern":     f"periodic_spikes_days_{sorted(PETRA_SPIKE_DAYS)}",
            },
            "bob_d": {
                "label":              "BENIGN",
                "detection_layer":    None,
                "reason":             "Normal DevOps — same IP, region, ops throughout all 14 days",
                "expected_score_max": 0.30,
            },
            "carol_s": {
                "label":              "BENIGN",
                "detection_layer":    None,
                "reason":             "Normal data science — same buckets, region, ops throughout",
                "expected_score_max": 0.30,
            },
            "svc_backup": {
                "label":              "BENIGN",
                "detection_layer":    None,
                "reason":             "Fully predictable daily system job",
                "expected_score_max": 0.20,
            },
            "svc_monthly": {
                "label":              "BENIGN",
                "detection_layer":    None,
                "reason":             "Monthly archival job on schedule — same ops, hours, volume as Aug 1 baseline run",
                "expected_score_max": 0.20,
            },
        },
    }
    with open(GROUND_TRUTH_OUT, "w") as f:
        json.dump(gt, f, indent=2)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    monthly_date   = BASELINE_START + timedelta(days=MONTHLY_RUN_DAY)
    incident_end   = INCIDENT_DAY + timedelta(days=INCIDENT_DAYS - 1)
    print("=== Generating Test Dataset (Operation Data Grab — Extended) ===\n")
    print(f"  Baseline : {BASELINE_START:%Y-%m-%d} → "
          f"{INCIDENT_DAY - timedelta(days=1):%Y-%m-%d} ({DAYS} days)")
    print(f"  Incident : {INCIDENT_DAY:%Y-%m-%d} → {incident_end:%Y-%m-%d} "
          f"({INCIDENT_DAYS} days)")
    print(f"  svc_monthly baseline run : {monthly_date:%Y-%m-%d} (day {MONTHLY_RUN_DAY})\n")

    n = generate_ct_baseline();  print(f"  CT  baseline : {n:>6} events")
    n = generate_s3_baseline();  print(f"  S3  baseline : {n:>6} events")
    n = generate_vpc_baseline(); print(f"  VPC baseline : {n:>6} flows")

    print()
    n = generate_ct_incident();  print(f"  CT  incident : {n:>6} events  ({INCIDENT_DAYS} days)")
    n = generate_s3_incident();  print(f"  S3  incident : {n:>6} events  ({INCIDENT_DAYS} days)")
    n = generate_vpc_incident(); print(f"  VPC incident : {n:>6} flows   ({INCIDENT_DAYS} days)")

    save_ground_truth()
    print(f"\nOutput → {BASE_DIR}/")
    print(f"  Incident files → {INCIDENT_DIR}/<date>/")
    print("Run:  python run_test_pipeline.py")


if __name__ == "__main__":
    main()
