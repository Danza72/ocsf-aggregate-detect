#!/usr/bin/env python3
"""
generate_synthetic_baseline.py

Produces two synthetic OCSF API Activity files for UEBA scorer development:

  ocsf_out/cloudtrail_synthetic_baseline.jsonl
      30-day behavioral baseline (2018-07-21 through 2018-08-19) for the four
      human actors found in cloudtrail_ocsf.jsonl. Used to train / warm-start
      the UEBA scorer's per-actor behavioral models.

  ocsf_out/cloudtrail_synthetic_test.jsonl
      3-day labeled test set (2018-08-21 through 2018-08-23) with known
      ground-truth anomaly labels. Used to measure TPR / FPR per dimension
      before trusting the scorer on the real BOTSv3 incident data.

Why synthetic data is needed
-----------------------------
The real BOTSv3 dataset spans only 09:00-15:27 UTC on 2018-08-20 -- entirely
within normal business hours. The UEBA scorer needs contrast: historical data
that includes both normal working-hours activity AND rare off-hours activity so
the time-of-day dimension produces meaningful scores; and labeled anomalous
operations (MFA abuse, persistence, account takeover) to test behavioral
dimensions that are independent of time.

Actors covered
--------------
Human actors where unmapped.is_system_actor == false in cloudtrail_ocsf.jsonl,
derived programmatically. Note: 'accesslogdelivery' appears only in
s3_accesslogs_ocsf.jsonl (no CloudTrail footprint) so it is naturally absent.

Invariants on every synthetic event
-------------------------------------
  unmapped.is_synthetic    = true   -- never confuse with real BOTSv3 data
  unmapped.is_system_actor = false  -- consistent with actor classification

Test-set events additionally carry:
  unmapped.is_anomalous   = true/false  -- ground-truth label
  unmapped.anomaly_type   = "off_hours" | "novel_operation" | "new_source_ip"
  unmapped.anomaly_subtype = "mfa_abuse" | "persistence" | "account_takeover"
                             (novel_operation events only)

These files must NEVER be merged into cloudtrail_ocsf.jsonl.

NOTE: "non-human identity", is_system_actor, and the heuristics used here are
project-level implementation choices, not industry-standard specifications.
"""

import json
import random
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

REAL_SRC      = "ocsf_out/cloudtrail_ocsf.jsonl"
BASELINE_OUT  = "ocsf_out/cloudtrail_synthetic_baseline.jsonl"
TEST_OUT      = "ocsf_out/cloudtrail_synthetic_test.jsonl"

# ---------------------------------------------------------------------------
# Date windows
# ---------------------------------------------------------------------------

# Baseline: 14 days immediately before the real incident (2018-08-20)
# Aug 6 – Aug 19 inclusive = 14 days
BASELINE_START = datetime(2018, 8,  6, tzinfo=timezone.utc)
BASELINE_END   = datetime(2018, 8, 19, tzinfo=timezone.utc)

# Test: 3 days immediately after (kept separate from the real incident day)
TEST_START = datetime(2018, 8, 21, tzinfo=timezone.utc)
TEST_END   = datetime(2018, 8, 23, tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Time-of-day windows (UTC hours as floats)
# ---------------------------------------------------------------------------

WORK_START    = 8.0    # 08:00 working hours begin
WORK_END      = 17.5   # 17:30 working hours end

# Off-hours sub-windows used in the baseline (~12% of baseline events)
EARLY_START, EARLY_END = 6.0, 8.0    # early morning
EVE_START,   EVE_END   = 17.5, 22.0  # evening

# Midnight window for off_hours test anomalies: hours unseen in the 30-day
# baseline so P(hour|actor) ≈ 0, producing unambiguous high anomaly scores
MIDNIGHT_START, MIDNIGHT_END = 0.0, 5.0

# ---------------------------------------------------------------------------
# Volume & anomaly parameters
# ---------------------------------------------------------------------------

# Fraction of baseline events placed outside working hours
BASELINE_OFF_HOURS_FRACTION = 0.12

# Target daily event volume per actor for both windows.
# See rationale in comments below each entry.
TARGET_DAILY: dict[str, int] = {
    # Real rate ~665/hr; capped at 600 to avoid over-inflating the synthetic
    # set (volume is dominated by automated config polling).
    "splunk_access": 600,
    # Real 646 events in 12 min = attack burst (RunInstances × 576).
    # Synthetic models normal admin provisioning, not the anomaly.
    "web_admin":     40,
    # Real rate ~109/hr; 100/day is a fair daily estimate.
    "bstoll":        100,
    # Real rate ~35/hr over a ~2h session; 60/day for synthetic.
    "btun":          60,
}

# ±20% daily jitter to avoid identical counts every day
JITTER_RANGE = (0.80, 1.20)

# Fraction of test-set events that are labeled anomalous (true positives)
ANOMALY_FRACTION = 0.20

# Of the anomalous 20%, how to split across anomaly types.
# 35% off-hours (time dimension), 40% novel ops (behavioral dimension),
# 25% new location -- new IP + region not in actor's baseline (geo dimension).
ANOMALY_TYPE_WEIGHTS = {
    "off_hours":       0.35,
    "novel_operation": 0.40,
    "new_location":    0.25,
}

# ---------------------------------------------------------------------------
# Anomalous operation catalog (all route to iam.amazonaws.com)
#
# Operations are grouped by attack category so anomaly_subtype is meaningful.
# These are real AWS IAM API names that legitimate actors rarely call, making
# them effective rare-operation anomaly signals.
# ---------------------------------------------------------------------------

ANOMALOUS_OPS_BY_CATEGORY: dict[str, list[str]] = {
    # MFA weakening / removal
    "mfa_abuse": [
        "DeactivateMFADevice",
        "DeleteVirtualMFADevice",
        "CreateVirtualMFADevice",   # creating MFA for a target user (takeover setup)
    ],
    # Establishing footholds: new users, keys, roles, policy attachments
    "persistence": [
        "CreateUser",
        "CreateAccessKey",
        "CreateLoginProfile",       # enables console access for a (possibly new) user
        "AttachUserPolicy",
        "AddUserToGroup",
        "CreateRole",
        "AttachRolePolicy",
        "PutUserPolicy",
    ],
    # Privilege escalation / account takeover
    "account_takeover": [
        "UpdateAccountPasswordPolicy",  # weakening password policy (min length, etc.)
        "UpdateLoginProfile",           # resetting another user's console password
        "DeleteLoginProfile",           # locking out a legitimate user
        "CreateGroup",
        "AttachGroupPolicy",
        "PutGroupPolicy",
    ],
}

# Flat list for quick sampling; subtype is looked up from the category mapping
_ALL_ANOMALOUS_OPS: list[str] = [
    op for ops in ANOMALOUS_OPS_BY_CATEGORY.values() for op in ops
]
_OP_TO_SUBTYPE: dict[str, str] = {
    op: sub
    for sub, ops in ANOMALOUS_OPS_BY_CATEGORY.items()
    for op in ops
}

# IPs for new_location anomalies. RFC 5737 TEST-NET ranges are guaranteed
# unroutable and safe for synthetic / documentation datasets -- they will
# never collide with any actor's real baseline IPs.
SYNTHETIC_SUSPICIOUS_IPS: list[str] = [
    "203.0.113.10",
    "203.0.113.42",
    "203.0.113.75",
    "198.51.100.7",
    "198.51.100.200",
]

# AWS regions that represent "new locations" for all four human actors.
# All actors baseline in us-west-1 / us-west-2 / us-east-1 / us-east-2.
# These regions are outside every actor's observed baseline, so a new_location
# event using one of these fires both the IP and the region novelty dimensions.
UNUSUAL_REGIONS: list[str] = [
    "eu-west-1",        # Ireland
    "eu-central-1",     # Frankfurt
    "ap-southeast-1",   # Singapore
    "ap-northeast-1",   # Tokyo
    "ap-south-1",       # Mumbai
    "me-south-1",       # Bahrain
    "sa-east-1",        # São Paulo
    "af-south-1",       # Cape Town
]

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RANDOM_SEED = 42

# Minimum times each real operation / IP must be representable in the sampling
# pool so that over 14 days it is virtually guaranteed to appear >= 2x in the
# synthetic output.  Pure proportional resampling under-samples rare real ops
# (real_count=1-2) because random draws may skip them entirely over 14 days.
# Setting pool_min=3 ensures P(appears 0x in 14 days) < 1% for every actor.
POOL_MIN_COUNT = 5

# For web_admin, RunInstances accounts for 89% of real ops because the real
# data captures an attack burst. Cap it at 20% in synthetic so the baseline
# reflects plausible normal provisioning, not the anomalous event.
OP_CAPS: dict[str, dict[str, float]] = {
    "web_admin": {"RunInstances": 0.20},
}

# The real Aug-20 data for web_admin contains 14 attack regions (RunInstances
# burst across all regions simultaneously). Restricting the baseline pool to
# us-east-1 — the only region with pre-attack activity — ensures the
# new_location dimension fires for all 14 attack regions at score time.
REGION_WHITELIST: dict[str, list[str]] = {
    "web_admin": ["us-east-1"],
}


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

def load_real_profiles() -> dict:
    """
    Read cloudtrail_ocsf.jsonl and build a sampling profile for each human
    actor. Returns {actor_name: profile_dict}.
    """
    raw: dict[str, list[dict]] = defaultdict(list)
    op_to_svc: dict[str, Counter] = defaultdict(Counter)
    is_system_map: dict[str, bool] = {}

    with open(REAL_SRC) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            u    = ev.get("actor", {}).get("user", {})
            name = u.get("name")
            if not name:
                continue

            sys_flag = bool(ev.get("unmapped", {}).get("is_system_actor", False))
            if name not in is_system_map:
                is_system_map[name] = sys_flag

            op  = ev.get("api", {}).get("operation") or ""
            svc = ev.get("api", {}).get("service", {}).get("name") or ""
            if op and svc:
                op_to_svc[op][svc] += 1

            ep  = ev.get("src_endpoint", {})
            ip  = ep.get("ip") or ep.get("svc_name") or ""
            raw[name].append({
                "op":       op,
                "region":   ev.get("cloud", {}).get("region") or "us-east-1",
                "ip":       ip,
                "uid":      u.get("uid") or "",
                "uid_alt":  u.get("uid_alt") or "",
                "uid_type": u.get("type") or "IAMUser",
                "agent":    ev.get("http_request", {}).get("user_agent") or "",
                "account":  (ev.get("cloud", {}).get("account", {}) or {}).get("uid") or "",
            })

    profiles: dict[str, dict] = {}
    for actor, events in raw.items():
        ops_ctr    = Counter(e["op"]     for e in events if e["op"])
        region_ctr = Counter(e["region"] for e in events)
        ip_ctr     = Counter(e["ip"]     for e in events if e["ip"])
        agent_ctr  = Counter(e["agent"]  for e in events if e["agent"])

        whitelist = REGION_WHITELIST.get(actor)
        if whitelist:
            region_ctr = Counter({r: c for r, c in region_ctr.items()
                                  if r in whitelist})
            if not region_ctr:
                region_ctr = Counter({"us-east-1": 1})

        raw_ops_pool = _apply_op_caps(list(ops_ctr.elements()), actor, ops_ctr)
        raw_ips_pool = list(ip_ctr.elements())

        profiles[actor] = {
            "ops_pool":       _ensure_min_pool_count(raw_ops_pool, ops_ctr),
            "regions":        list(region_ctr.elements()),
            "ips":            _ensure_min_pool_count(raw_ips_pool, ip_ctr),
            "agents":         list(agent_ctr.elements()),
            "op_to_svc":      op_to_svc,
            "is_system_actor": is_system_map.get(actor, False),
            "event_count":    len(events),
            # Stable per-actor IAM attributes (mode from real data)
            "uid":      (Counter(e["uid"]     for e in events if e["uid"])
                         .most_common(1) or [("", 0)])[0][0],
            "uid_alt":  (Counter(e["uid_alt"] for e in events if e["uid_alt"])
                         .most_common(1) or [("", 0)])[0][0],
            "uid_type": (Counter(e["uid_type"] for e in events)
                         .most_common(1) or [("IAMUser", 0)])[0][0],
            "account":  (Counter(e["account"] for e in events if e["account"])
                         .most_common(1) or [("", 0)])[0][0],
            # Set of operations seen in the real baseline (used for novel-op
            # detection: only inject ops NOT already in this set)
            "seen_ops": set(ops_ctr.keys()),
        }

    return profiles


def _ensure_min_pool_count(pool: list, source_ctr: Counter,
                           min_count: int = POOL_MIN_COUNT) -> list:
    """
    Guarantee every key in source_ctr appears at least min_count times in
    pool.  Adds extra copies for under-represented entries without touching
    entries that already meet the threshold.  The proportional weight of
    high-frequency entries is virtually unchanged; rare entries get a small
    absolute floor so they aren't lost to random sampling over 14 days.
    """
    pool = list(pool)
    current = Counter(pool)
    for key, _ in source_ctr.items():
        shortfall = min_count - current[key]
        if shortfall > 0:
            pool.extend([key] * shortfall)
    return pool


def _apply_op_caps(ops_pool: list, actor: str, ops_ctr: Counter) -> list:
    """Re-weight the ops sampling pool to enforce any caps in OP_CAPS."""
    caps = OP_CAPS.get(actor)
    if not caps:
        return ops_pool

    for cap_op, cap_frac in caps.items():
        if cap_op not in ops_ctr:
            continue
        total          = sum(ops_ctr.values())
        original_count = ops_ctr[cap_op]
        capped_count   = int(total * cap_frac)
        if original_count <= capped_count:
            continue

        other_total  = total - original_count
        cap_shortage = original_count - capped_count
        new_pool: list = []
        # Iterate over UNIQUE ops (not all pool entries) so each op's extra
        # copies are computed once, not multiplied by its real_count.
        for op, count in ops_ctr.items():
            if op == cap_op:
                new_pool.extend([op] * capped_count)
            else:
                extra = round((count / max(other_total, 1)) * cap_shortage)
                new_pool.extend([op] * (count + extra))

        ops_pool = new_pool

    return ops_pool


# ---------------------------------------------------------------------------
# Core event builder
# ---------------------------------------------------------------------------

def _guess_activity_id(op: str) -> int:
    if not op:
        return 0
    n = op.lower()
    if n.startswith(("create", "put", "run", "attach", "add", "register")):
        return 1
    if n.startswith(("describe", "get", "list", "lookup", "head")):
        return 2
    if n.startswith(("update", "modify", "set")):
        return 3
    if n.startswith(("delete", "remove", "terminate", "deactivate", "stop")):
        return 4
    return 99


def _make_base_event(actor: str, profile: dict, ts_ms: int,
                     op: str | None = None,
                     svc: str | None = None,
                     ip: str | None = None) -> dict:
    """
    Build one OCSF API Activity event. If op/svc/ip are None, they are
    sampled from the actor's real baseline distribution.
    """
    if op is None:
        op = random.choice(profile["ops_pool"])
    if svc is None:
        svc_ctr = profile["op_to_svc"].get(op)
        svc = svc_ctr.most_common(1)[0][0] if svc_ctr else "iam.amazonaws.com"
    if ip is None:
        ip = random.choice(profile["ips"]) if profile["ips"] else ""

    agent  = random.choice(profile["agents"]) if profile["agents"] else ""
    region = random.choice(profile["regions"])
    act_id = _guess_activity_id(op)

    ev: dict = {
        "category_uid":  6,
        "category_name": "Application Activity",
        "class_uid":     6003,
        "class_name":    "API Activity",
        "activity_id":   act_id,
        "type_uid":      6003 * 100 + act_id,
        "severity_id":   1,
        "status_id":     1,
        "time":          ts_ms,
        "metadata": {
            "product":    {"name": "CloudTrail", "vendor_name": "AWS"},
            "version":    "1.1.0",
            "event_code": "AwsApiCall",
            "uid":        str(uuid.uuid4()),
        },
        "cloud": {
            "provider": "AWS",
            "region":   region,
            "account":  {"uid": profile["account"]},
        },
        "actor": {
            "user": {
                "type":    profile["uid_type"],
                "name":    actor,
                "uid":     profile["uid"],
                "account": {"uid": profile["account"]},
            },
        },
        "api": {
            "operation": op,
            "service":   {"name": svc},
            "request":   {"uid": str(uuid.uuid4())},
        },
        "unmapped": {
            "raw_eventVersion": "1.08",
            "is_system_actor":  profile.get("is_system_actor", False),
            "is_synthetic":     True,
        },
    }

    if ip:
        ev["src_endpoint"] = ({"ip": ip} if IP_RE.match(ip)
                               else {"svc_name": ip})
    if agent:
        ev["http_request"] = {"user_agent": agent}
    if profile.get("uid_alt"):
        ev["actor"]["user"]["uid_alt"] = profile["uid_alt"]

    return ev


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _rand_ts(date: datetime, start_h: float, end_h: float) -> int:
    """Random epoch-ms strictly within [start_h, end_h) on the given UTC date."""
    lo = int(start_h * 3600)
    hi = int(end_h   * 3600) - 1
    return int((date.replace(hour=0, minute=0, second=0, microsecond=0)
                + timedelta(seconds=random.randint(lo, hi))).timestamp() * 1000)


def _is_working_hours(ts_ms: int) -> bool:
    dt   = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    mins = dt.hour * 60 + dt.minute
    return int(WORK_START * 60) <= mins < int(WORK_END * 60)


# ---------------------------------------------------------------------------
# Baseline generation
# ---------------------------------------------------------------------------

def generate_baseline_events(actor: str, profile: dict,
                              daily_target: int) -> list[dict]:
    """Generate normal synthetic events for the 30-day baseline window."""
    events: list[dict] = []
    date = BASELINE_START
    while date <= BASELINE_END:
        n_day  = max(2, int(daily_target * random.uniform(*JITTER_RANGE)))
        n_off  = max(1, round(n_day * BASELINE_OFF_HOURS_FRACTION))
        n_work = n_day - n_off

        for _ in range(n_work):
            ev = _make_base_event(actor, profile,
                                  _rand_ts(date, WORK_START, WORK_END))
            events.append(ev)

        for _ in range(n_off):
            if random.random() < 0.60:
                ts = _rand_ts(date, EARLY_START, EARLY_END)   # 06:00-08:00
            else:
                ts = _rand_ts(date, EVE_START, EVE_END)       # 17:30-22:00
            ev = _make_base_event(actor, profile, ts)
            events.append(ev)

        date += timedelta(days=1)
    return events


# ---------------------------------------------------------------------------
# Test-set anomaly helpers
# ---------------------------------------------------------------------------

def _novel_ops_for_actor(seen_ops: set) -> list[str]:
    """
    Return the subset of ANOMALOUS_OPS not already in the actor's baseline.
    Falls back to the most impactful ops if everything is already seen
    (unlikely, but handled gracefully).
    """
    novel = [op for op in _ALL_ANOMALOUS_OPS if op not in seen_ops]
    if not novel:
        # Every anomalous op is already normal for this actor — use the
        # most impactful ones anyway; they'll still be high-severity events.
        novel = ["DeactivateMFADevice", "UpdateAccountPasswordPolicy",
                 "DeleteLoginProfile"]
    return novel


def _make_off_hours_event(actor: str, profile: dict, date: datetime) -> dict:
    """
    True positive: normal operation from actor's usual IP at midnight hours.
    The time dimension fires; the operation and IP dimensions do not.
    """
    ts = _rand_ts(date, MIDNIGHT_START, MIDNIGHT_END)
    ev = _make_base_event(actor, profile, ts)
    ev["unmapped"]["is_anomalous"]  = True
    ev["unmapped"]["anomaly_type"]  = "off_hours"
    return ev


def _make_novel_op_event(actor: str, profile: dict, date: datetime) -> dict:
    """
    True positive: suspicious IAM write operation never seen in this actor's
    30-day baseline, during working hours, from actor's usual IP.
    The behavioral (novel operation) dimension fires; time and IP do not.
    """
    op      = random.choice(_novel_ops_for_actor(profile["seen_ops"]))
    subtype = _OP_TO_SUBTYPE[op]
    ts      = _rand_ts(date, WORK_START, WORK_END)
    ev      = _make_base_event(actor, profile, ts,
                                op=op, svc="iam.amazonaws.com")
    ev["unmapped"]["is_anomalous"]    = True
    ev["unmapped"]["anomaly_type"]    = "novel_operation"
    ev["unmapped"]["anomaly_subtype"] = subtype
    return ev


def _make_new_location_event(actor: str, profile: dict, date: datetime) -> dict:
    """
    True positive: normal operation from (a) a source IP not in this actor's
    baseline AND (b) an AWS region not in this actor's baseline -- simulating
    a login or API call from an entirely new geographic location.
    Time and operation dimensions do not fire; IP and region novelty both fire.
    """
    ts     = _rand_ts(date, WORK_START, WORK_END)
    new_ip = random.choice(SYNTHETIC_SUSPICIOUS_IPS)

    # Pick a region genuinely outside the actor's seen baseline
    actor_regions = set(profile.get("regions", []))
    novel_regions = [r for r in UNUSUAL_REGIONS if r not in actor_regions]
    new_region    = random.choice(novel_regions) if novel_regions else UNUSUAL_REGIONS[0]

    # Build the event with the actor's normal operation but foreign IP + region
    op  = random.choice(profile["ops_pool"])
    svc_ctr = profile["op_to_svc"].get(op)
    svc = svc_ctr.most_common(1)[0][0] if svc_ctr else "ec2.amazonaws.com"
    agent  = random.choice(profile["agents"]) if profile["agents"] else ""
    act_id = _guess_activity_id(op)

    ev: dict = {
        "category_uid":  6,
        "category_name": "Application Activity",
        "class_uid":     6003,
        "class_name":    "API Activity",
        "activity_id":   act_id,
        "type_uid":      6003 * 100 + act_id,
        "severity_id":   1,
        "status_id":     1,
        "time":          ts,
        "metadata": {
            "product":    {"name": "CloudTrail", "vendor_name": "AWS"},
            "version":    "1.1.0",
            "event_code": "AwsApiCall",
            "uid":        str(uuid.uuid4()),
        },
        "cloud": {
            "provider": "AWS",
            "region":   new_region,           # <-- novel region
            "account":  {"uid": profile["account"]},
        },
        "actor": {
            "user": {
                "type":    profile["uid_type"],
                "name":    actor,
                "uid":     profile["uid"],
                "account": {"uid": profile["account"]},
            },
        },
        "api": {
            "operation": op,
            "service":   {"name": svc},
            "request":   {"uid": str(uuid.uuid4())},
        },
        "src_endpoint": {"ip": new_ip},       # <-- novel IP
        "unmapped": {
            "raw_eventVersion": "1.08",
            "is_system_actor":  False,
            "is_synthetic":     True,
            "is_anomalous":     True,
            "anomaly_type":     "new_location",
        },
    }
    if agent:
        ev["http_request"] = {"user_agent": agent}
    if profile.get("uid_alt"):
        ev["actor"]["user"]["uid_alt"] = profile["uid_alt"]
    return ev


# ---------------------------------------------------------------------------
# Test-set generation
# ---------------------------------------------------------------------------

def generate_test_events(actor: str, profile: dict,
                         daily_target: int) -> list[dict]:
    """
    Generate labeled test events for the 3-day test window.
    Each event carries is_anomalous=true/false for ground-truth evaluation.
    """
    atype_keys    = list(ANOMALY_TYPE_WEIGHTS.keys())
    atype_weights = list(ANOMALY_TYPE_WEIGHTS.values())
    events: list[dict] = []
    date = TEST_START

    while date <= TEST_END:
        n_day      = max(2, int(daily_target * random.uniform(*JITTER_RANGE)))
        n_anomalous = max(1, round(n_day * ANOMALY_FRACTION))
        n_normal   = n_day - n_anomalous

        # True negatives: normal working-hours events
        for _ in range(n_normal):
            ts = _rand_ts(date, WORK_START, WORK_END)
            ev = _make_base_event(actor, profile, ts)
            ev["unmapped"]["is_anomalous"] = False
            events.append(ev)

        # True positives: one anomaly type per event, chosen by weight
        for _ in range(n_anomalous):
            atype = random.choices(atype_keys, weights=atype_weights, k=1)[0]
            if atype == "off_hours":
                ev = _make_off_hours_event(actor, profile, date)
            elif atype == "novel_operation":
                ev = _make_novel_op_event(actor, profile, date)
            else:
                ev = _make_new_location_event(actor, profile, date)
            events.append(ev)

        date += timedelta(days=1)

    return events


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _date_range_days(start: datetime, end: datetime) -> int:
    return (end - start).days + 1


def main() -> None:
    random.seed(RANDOM_SEED)

    print(f"Loading real actor profiles from {REAL_SRC} ...")
    profiles = load_real_profiles()

    actors = profiles
    if not actors:
        print("ERROR: no actors found.")
        return

    print(f"Actors: {sorted(actors)}\n")

    # ── Baseline ──────────────────────────────────────────────────────────
    n_baseline_days = _date_range_days(BASELINE_START, BASELINE_END)
    print(f"=== BASELINE  {BASELINE_START.date()} – {BASELINE_END.date()}"
          f"  ({n_baseline_days} days) ===")

    baseline_events: list[dict] = []
    for actor in sorted(actors):
        daily = TARGET_DAILY.get(actor) or max(2, actors[actor]["event_count"])
        evs       = generate_baseline_events(actor, actors[actor], daily)
        work_cnt  = sum(1 for e in evs if _is_working_hours(e["time"]))
        off_cnt   = len(evs) - work_cnt
        print(f"  {actor:20s}  total={len(evs):6d}  "
              f"work={work_cnt:6d}  off={off_cnt:4d}  "
              f"({100*off_cnt/max(len(evs),1):.1f}% off-hrs)")
        baseline_events.extend(evs)

    baseline_events.sort(key=lambda e: e["time"])
    Path(BASELINE_OUT).parent.mkdir(parents=True, exist_ok=True)
    with open(BASELINE_OUT, "w") as f:
        for ev in baseline_events:
            f.write(json.dumps(ev) + "\n")
    print(f"  -> {len(baseline_events)} events written to {BASELINE_OUT}\n")

    # ── Test set ──────────────────────────────────────────────────────────
    n_test_days = _date_range_days(TEST_START, TEST_END)
    print(f"=== TEST SET  {TEST_START.date()} – {TEST_END.date()}"
          f"  ({n_test_days} days) ===")

    test_events: list[dict] = []
    for actor in sorted(actors):
        daily = TARGET_DAILY.get(actor) or max(2, actors[actor]["event_count"])
        evs  = generate_test_events(actor, actors[actor], daily)
        tp   = [e for e in evs if e["unmapped"].get("is_anomalous")]
        tn   = [e for e in evs if not e["unmapped"].get("is_anomalous")]
        by_type: Counter = Counter(
            e["unmapped"].get("anomaly_type", "") for e in tp
        )
        by_sub: Counter = Counter(
            e["unmapped"].get("anomaly_subtype", "") for e in tp
            if e["unmapped"].get("anomaly_type") == "novel_operation"
        )
        print(f"  {actor:20s}  total={len(evs):4d}  "
              f"TP={len(tp):3d} ({100*len(tp)/max(len(evs),1):.0f}%)  "
              f"TN={len(tn):3d}")
        print(f"    anomaly breakdown -> {dict(by_type)}")
        if by_sub:
            print(f"    novel_op subtypes -> {dict(by_sub)}")
        test_events.extend(evs)

    test_events.sort(key=lambda e: e["time"])
    with open(TEST_OUT, "w") as f:
        for ev in test_events:
            f.write(json.dumps(ev) + "\n")
    print(f"  -> {len(test_events)} events written to {TEST_OUT}")

    # ── Spot-check samples ────────────────────────────────────────────────
    _print_sample("baseline (working hours)",
                  next((e for e in baseline_events if _is_working_hours(e["time"])), None))
    _print_sample("test true-negative (normal, working hours)",
                  next((e for e in test_events
                        if not e["unmapped"].get("is_anomalous")), None))
    _print_sample("test off_hours anomaly",
                  next((e for e in test_events
                        if e["unmapped"].get("anomaly_type") == "off_hours"), None))
    _print_sample("test novel_operation anomaly",
                  next((e for e in test_events
                        if e["unmapped"].get("anomaly_type") == "novel_operation"), None))
    _print_sample("test new_location anomaly (foreign IP + region)",
                  next((e for e in test_events
                        if e["unmapped"].get("anomaly_type") == "new_location"), None))


def _print_sample(label: str, ev: dict | None) -> None:
    print(f"\n--- Sample: {label} ---")
    if ev:
        # Print a compact subset of the key fields
        u   = ev.get("actor", {}).get("user", {})
        api = ev.get("api", {})
        ts  = datetime.fromtimestamp(ev["time"] / 1000, tz=timezone.utc)
        print(f"  actor:     {u.get('name')}  ({u.get('type')})")
        print(f"  time:      {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  operation: {api.get('operation')}  [{api.get('service',{}).get('name')}]")
        print(f"  src_ip:    {ev.get('src_endpoint',{})}")
        print(f"  unmapped:  {ev.get('unmapped')}")
    else:
        print("  (none found)")


if __name__ == "__main__":
    main()
