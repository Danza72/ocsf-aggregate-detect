#!/usr/bin/env python3
"""
generate_synthetic_s3_vpc_baseline.py

Generates 14 days (Aug 6-19 2018) of synthetic S3 and VPC baseline events
for known actors, seeded from observed Aug 20 behavior patterns.

Outputs:
  ocsf_out/s3_synthetic_baseline.jsonl
  ocsf_out/vpcflow_synthetic_baseline.jsonl
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

OUT_DIR = Path("ocsf_out")
S3_OUT  = OUT_DIR / "s3_synthetic_baseline.jsonl"
VPC_OUT = OUT_DIR / "vpcflow_synthetic_baseline.jsonl"

START_DATE = datetime(2018, 8, 6, tzinfo=timezone.utc)
DAYS       = 14   # Aug 6 – Aug 19 inclusive

# ── S3 actor profiles ──────────────────────────────────────────────────────
# Seeded from Aug 20 real patterns (non-attack periods only).
# events_per_day / flows_per_day: (mean, std)
# bytes: (mean, std) — only applies to GET.OBJECT; PUT and GET.BUCKET send 0
S3_PROFILES: dict = {
    "splunk_access": {
        "src_ip":          "34.215.24.225",
        "is_system_actor": False,
        "events_per_day":  (6, 2),
        "operations":      {"REST.GET.OBJECT": 0.70, "REST.GET.BUCKET": 0.30},
        "buckets":         {"frothlyweblogs": 1.0},
        "bytes":           (32_000, 15_000),
        "active_hours":    [9, 10, 11, 12, 13],
        "response_code":   200,
    },
    "s3-log-delivery": {
        "src_ip":          None,
        "is_system_actor": True,
        "events_per_day":  (2, 1),
        "operations":      {"REST.PUT.OBJECT": 1.0},
        "buckets":         {"frothlyweblogs": 1.0},
        "bytes":           (0, 0),
        "active_hours":    [9, 10, 11, 12, 13],
        "response_code":   200,
    },
    "accesslogdelivery": {
        "src_ip":          None,
        "is_system_actor": True,
        "events_per_day":  (0.4, 0.4),
        "operations":      {"REST.PUT.OBJECT": 1.0},
        "buckets":         {"frothlyweblogs": 1.0},
        "bytes":           (0, 0),
        "active_hours":    [11, 12, 13],
        "response_code":   200,
    },
}

# ── VPC actor profiles ─────────────────────────────────────────────────────
VPC_PROFILES: dict = {
    "splunk_access": {
        "src_ip":          "34.215.24.225",
        "src_eni":         "eni-030548930b0c5f0b0",
        "is_system_actor": False,
        "flows_per_day":   (55, 15),
        "dst_ips":         {"172.16.0.178": 0.95, "172.16.0.127": 0.05},
        "dst_ports":       {8088: 0.66, 443: 0.18, 3306: 0.06, 80: 0.06, 123: 0.02, 11211: 0.02},
        "bytes":           (2_689, 5_000),
        "action":          "ACCEPT",
        "protocol":        6,
        "active_hours":    [9, 10, 14],
    },
}


# ── Helpers ────────────────────────────────────────────────────────────────

def _weighted_choice(weights: dict):
    keys  = list(weights.keys())
    probs = list(weights.values())
    return random.choices(keys, weights=probs, k=1)[0]


def _daily_count(mean: float, std: float) -> int:
    """Gaussian count, floored at 0. For rare events (mean < 1) uses Bernoulli."""
    if mean <= 0:
        return 0
    if mean < 1:
        return 1 if random.random() < mean else 0
    return max(0, round(random.gauss(mean, std)))


def _random_ts(date: datetime, active_hours: list) -> int:
    hour   = random.choice(active_hours)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return int(date.replace(hour=hour, minute=minute, second=second).timestamp() * 1000)


# ── S3 generation ──────────────────────────────────────────────────────────

def generate_s3() -> int:
    total = 0
    with open(S3_OUT, "w") as f:
        for actor, p in S3_PROFILES.items():
            for day_offset in range(DAYS):
                date = START_DATE + timedelta(days=day_offset)
                n    = _daily_count(*p["events_per_day"])
                for _ in range(n):
                    ts     = _random_ts(date, p["active_hours"])
                    op     = _weighted_choice(p["operations"])
                    bucket = _weighted_choice(p["buckets"])

                    if op == "REST.GET.OBJECT" and p["bytes"][0] > 0:
                        bytes_sent = str(max(0, round(random.gauss(*p["bytes"]))))
                    else:
                        bytes_sent = "-"

                    ev: dict = {
                        "category_uid":  6,
                        "category_name": "Application Activity",
                        "class_uid":     6003,
                        "class_name":    "API Activity",
                        "activity_id":   1,
                        "type_uid":      600301,
                        "severity_id":   1,
                        "status_id":     1,
                        "time":          ts,
                        "metadata": {
                            "product": {"name": "Amazon S3", "vendor_name": "AWS"},
                            "version": "1.1.0",
                            "uid": f"SYNTH-S3-{total:08d}",
                        },
                        "cloud": {"provider": "AWS"},
                        "actor": {"user": {"name": actor}},
                        "api": {
                            "operation": op,
                            "service":   {"name": "s3.amazonaws.com"},
                            "response":  {"code": p["response_code"]},
                        },
                        "resources": [{"name": bucket, "type": "bucket"}],
                        "unmapped": {
                            "bytes_sent":      bytes_sent,
                            "is_system_actor": p["is_system_actor"],
                        },
                    }
                    if p["src_ip"]:
                        ev["src_endpoint"] = {"ip": p["src_ip"]}

                    f.write(json.dumps(ev) + "\n")
                    total += 1
    return total


# ── VPC generation ─────────────────────────────────────────────────────────

def generate_vpc() -> int:
    total = 0
    with open(VPC_OUT, "w") as f:
        for actor, p in VPC_PROFILES.items():
            for day_offset in range(DAYS):
                date = START_DATE + timedelta(days=day_offset)
                n    = _daily_count(*p["flows_per_day"])
                for _ in range(n):
                    ts       = _random_ts(date, p["active_hours"])
                    dst_ip   = _weighted_choice(p["dst_ips"])
                    dst_port = int(_weighted_choice({str(k): v for k, v in p["dst_ports"].items()}))
                    b        = max(0, round(random.gauss(*p["bytes"])))

                    ev: dict = {
                        "category_uid":  4,
                        "category_name": "Network Activity",
                        "class_uid":     4001,
                        "class_name":    "Network Activity",
                        "activity_id":   6,
                        "type_uid":      400106,
                        "severity_id":   1,
                        "status_id":     1,
                        "time":          ts,
                        "start_time":    ts,
                        "end_time":      ts,
                        "metadata": {
                            "product": {
                                "name":        "VPC Flow Logs",
                                "vendor_name": "AWS",
                                "version":     "2",
                            },
                            "version": "1.1.0",
                        },
                        "cloud": {
                            "provider": "AWS",
                            "account":  {"uid": "622676721278"},
                        },
                        "src_endpoint": {
                            "ip":            p["src_ip"],
                            "port":          random.randint(1024, 65535),
                            "interface_uid": p["src_eni"],
                        },
                        "dst_endpoint": {
                            "ip":   dst_ip,
                            "port": dst_port,
                        },
                        "connection_info": {
                            "protocol_num": p["protocol"],
                            "direction_id": 0,
                        },
                        "traffic": {
                            "packets": random.randint(1, 10),
                            "bytes":   b,
                        },
                        "unmapped": {
                            "log_status":      "OK",
                            "action":          p["action"],
                            "is_system_actor": p["is_system_actor"],
                        },
                    }
                    f.write(json.dumps(ev) + "\n")
                    total += 1
    return total


# ── Entry point ────────────────────────────────────────────────────────────

def main() -> None:
    print(f"Generating synthetic S3 baseline ({DAYS} days: Aug 6–19 2018) ...")
    n_s3 = generate_s3()
    print(f"  {n_s3} events across {len(S3_PROFILES)} actors -> {S3_OUT}")

    print(f"Generating synthetic VPC baseline ({DAYS} days: Aug 6–19 2018) ...")
    n_vpc = generate_vpc()
    print(f"  {n_vpc} flows across {len(VPC_PROFILES)} actors -> {VPC_OUT}")


if __name__ == "__main__":
    main()
