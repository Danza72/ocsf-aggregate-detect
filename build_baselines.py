#!/usr/bin/env python3
"""
build_baselines.py

Builds per-actor behavioral baselines from synthetic historical data (Jul 21 – Aug 19).
Covers three log sources: CloudTrail, S3, VPC.

All actors (human and system) use synthetic baseline data (Jul 21 – Aug 19).
S3 and VPC baselines cover actors observed in those log sources.

Output:
  baselines.json   — { "cloudtrail": {...}, "s3": {...}, "vpc": {...} }
"""

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
CT_BASELINE_FILE  = Path("ocsf_out/cloudtrail_synthetic_baseline.jsonl")
S3_BASELINE_FILE  = Path("ocsf_out/s3_synthetic_baseline.jsonl")
VPC_BASELINE_FILE = Path("ocsf_out/vpcflow_synthetic_baseline.jsonl")
OUTPUT            = Path("baselines.json")


# ── Helpers ────────────────────────────────────────────────────────────────

def _ts_to_dt(ts_ms: int) -> datetime:
    return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)


def _read_jsonl(path: Path) -> list[dict]:
    events: list[dict] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _stats(vals: list) -> dict:
    if len(vals) >= 2:
        return {"mean": statistics.mean(vals), "std": statistics.stdev(vals)}
    return {"mean": float(vals[0]) if vals else 0.0, "std": 0.0}


# ── CloudTrail baseline ────────────────────────────────────────────────────

def _accumulate(
    events:       list[dict],
    hour_of_day:  dict,
    hourly_slots: dict,
    daily_slots:  dict,
    ips:          dict,
    regions:      dict,
    op_counts:    dict,
    resources:    dict,
    is_system:    dict,
    ev_count:     dict,
) -> None:
    for event in events:
        actor = (event.get("actor") or {}).get("user", {}).get("name")
        if not actor:
            continue
        sys_flag = bool((event.get("unmapped") or {}).get("is_system_actor", False))

        ts = event.get("time")
        if ts:
            dt = _ts_to_dt(ts)
            hour_of_day[actor][dt.hour]                    += 1
            hourly_slots[actor][dt.strftime("%Y-%m-%d %H")] += 1
            daily_slots[actor][dt.strftime("%Y-%m-%d")]     += 1

        ip = (event.get("src_endpoint") or {}).get("ip")
        if ip: ips[actor].add(ip)

        region = (event.get("cloud") or {}).get("region")
        if region: regions[actor].add(region)

        op = (event.get("api") or {}).get("operation")
        if op: op_counts[actor][op] += 1

        for res in event.get("resources") or []:
            rname = (res or {}).get("name")
            if rname: resources[actor].add(rname)

        if actor not in is_system:
            is_system[actor] = sys_flag
        ev_count[actor] += 1


def _build_ct_profiles(
    hour_of_day:  dict,
    hourly_slots: dict,
    daily_slots:  dict,
    ips:          dict,
    regions:      dict,
    op_counts:    dict,
    resources:    dict,
    is_system:    dict,
    ev_count:     dict,
) -> dict:
    profiles: dict[str, dict] = {}
    for actor in ev_count:
        slot_vals  = list(hourly_slots[actor].values())
        daily_vals = list(daily_slots[actor].values())

        if len(slot_vals) >= 2:
            vol_mean = statistics.mean(slot_vals)
            vol_std  = statistics.stdev(slot_vals)
        elif slot_vals:
            vol_mean = float(slot_vals[0])
            vol_std  = 0.0
        else:
            vol_mean = 0.0
            vol_std  = 0.0

        profiles[actor] = {
            "is_system_actor":      is_system.get(actor, False),
            "baseline_event_count": ev_count[actor],
            "known_hours":          dict(hour_of_day[actor]),
            "known_ips":            sorted(ips[actor]),
            "known_regions":        sorted(regions[actor]),
            "known_operations":     dict(op_counts[actor]),
            "known_resources":      sorted(resources[actor]),
            # per-hour-slot volume (used by scorer for z-score)
            "volume_stats": {
                "mean":         round(vol_mean, 4),
                "std":          round(vol_std,  4),
                "active_slots": len(slot_vals),
            },
            # per-day event counts (used by report for volume comparison)
            "daily_events": _stats(daily_vals),
        }
    return profiles


def build_ct_baseline() -> dict:
    """All actors use the synthetic baseline (attack-free, 30 days)."""
    def _fresh():
        return (
            defaultdict(Counter), defaultdict(Counter), defaultdict(Counter),
            defaultdict(set), defaultdict(set),
            defaultdict(Counter), defaultdict(set),
            {}, defaultdict(int),
        )

    h = _fresh()
    _accumulate(_read_jsonl(CT_BASELINE_FILE), *h)
    profiles = _build_ct_profiles(*h)
    n_h = sum(1 for p in profiles.values() if not p["is_system_actor"])
    print(f"[ct_baseline]  {len(profiles)} actors ({n_h} human, {len(profiles)-n_h} system)")
    return profiles


# ── S3 baseline ────────────────────────────────────────────────────────────

def build_s3_baseline() -> dict:
    """
    Build per-actor S3 baseline from synthetic data.
    Tracks: known operations, buckets, source IPs, daily bytes/event distributions.
    """
    if not S3_BASELINE_FILE.exists():
        print(f"[s3_baseline]  {S3_BASELINE_FILE} not found, skipping.")
        return {}

    daily_bytes:  dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    daily_events: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    ops:          dict[str, set]            = defaultdict(set)
    buckets:      dict[str, set]            = defaultdict(set)
    src_ips:      dict[str, set]            = defaultdict(set)

    with open(S3_BASELINE_FILE) as f:
        for line in f:
            ev    = json.loads(line.strip())
            name  = (ev.get("actor") or {}).get("user", {}).get("name")
            if not name:
                continue
            ts    = ev.get("time")
            day   = _ts_to_dt(ts).strftime("%Y-%m-%d") if ts else "unknown"
            op    = (ev.get("api") or {}).get("operation")
            bucket= ((ev.get("resources") or [{}])[0] or {}).get("name")
            ip    = (ev.get("src_endpoint") or {}).get("ip")
            b_str = (ev.get("unmapped") or {}).get("bytes_sent", "-")
            b     = 0
            try:
                if b_str and b_str != "-":
                    b = int(b_str)
            except ValueError:
                pass

            daily_events[name][day] += 1
            daily_bytes[name][day]  += b
            if op:     ops[name].add(op)
            if bucket: buckets[name].add(bucket)
            if ip:     src_ips[name].add(ip)

    baseline: dict[str, dict] = {}
    for name in daily_events:
        baseline[name] = {
            "known_operations": sorted(ops[name]),
            "known_buckets":    sorted(buckets[name]),
            "known_ips":        sorted(src_ips[name]),
            "daily_events":     _stats(list(daily_events[name].values())),
            "daily_bytes":      _stats(list(daily_bytes[name].values())),
        }

    print(f"[s3_baseline]  {len(baseline)} actors profiled from synthetic data")
    return baseline


# ── VPC baseline ───────────────────────────────────────────────────────────

def build_vpc_baseline() -> dict:
    """
    Build per-actor VPC baseline from synthetic data.
    Tracks: known dst IPs, dst ports, protocols, daily bytes/flow distributions.

    Resolution order (VPC flows carry no identity):
      1. src IP  → actor (via CT baseline known IPs)
      2. ENI ID  → actor (derived from step 1; ready for future ENI metadata)
    """
    if not VPC_BASELINE_FILE.exists():
        print(f"[vpc_baseline] {VPC_BASELINE_FILE} not found, skipping.")
        return {}

    # Build IP → actor from CT baseline
    ip_to_actor: dict[str, str] = {}
    for ev in _read_jsonl(CT_BASELINE_FILE):
        name = (ev.get("actor") or {}).get("user", {}).get("name")
        ip   = (ev.get("src_endpoint") or {}).get("ip")
        if name and ip:
            ip_to_actor[ip] = name

    # Read VPC flows once, then build ENI → actor as a fallback
    vpc_events = _read_jsonl(VPC_BASELINE_FILE)

    eni_to_actor: dict[str, str] = {}
    for ev in vpc_events:
        src    = ev.get("src_endpoint") or {}
        eni    = src.get("interface_uid")
        src_ip = src.get("ip")
        if eni and src_ip and src_ip in ip_to_actor:
            eni_to_actor[eni] = ip_to_actor[src_ip]

    daily_bytes:  dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    daily_flows:  dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    dst_ips:      dict[str, set]            = defaultdict(set)
    dst_ports:    dict[str, set]            = defaultdict(set)
    dst_conns:    dict[str, set]            = defaultdict(set)
    protocols:    dict[str, set]            = defaultdict(set)

    skipped = 0
    for ev in vpc_events:
        src    = ev.get("src_endpoint") or {}
        src_ip = src.get("ip")
        eni    = src.get("interface_uid")
        name   = ip_to_actor.get(src_ip) or (eni_to_actor.get(eni) if eni else None) or eni
        if not name:
            skipped += 1
            continue
        ts       = ev.get("time")
        day      = _ts_to_dt(ts).strftime("%Y-%m-%d") if ts else "unknown"
        dst_ip   = (ev.get("dst_endpoint") or {}).get("ip")
        dst_port = (ev.get("dst_endpoint") or {}).get("port")
        proto    = (ev.get("connection_info") or {}).get("protocol_num")
        b        = (ev.get("traffic") or {}).get("bytes", 0) or 0

        daily_flows[name][day] += 1
        daily_bytes[name][day] += b
        if dst_ip:            dst_ips[name].add(dst_ip)
        if dst_port:          dst_ports[name].add(dst_port)
        if dst_ip and dst_port: dst_conns[name].add(f"{dst_ip}:{dst_port}")
        if proto is not None: protocols[name].add(proto)

    baseline: dict[str, dict] = {}
    for name in daily_flows:
        baseline[name] = {
            "known_dst_ips":   sorted(dst_ips[name]),
            "known_dst_ports": sorted(dst_ports[name]),
            "known_dst_conns": sorted(dst_conns[name]),
            "known_protocols": sorted(protocols[name]),
            "daily_flows":     _stats(list(daily_flows[name].values())),
            "daily_bytes":     _stats(list(daily_bytes[name].values())),
        }

    print(f"[vpc_baseline] {len(baseline)} actors profiled from synthetic data ({skipped} flows unresolved)")
    return baseline


# ── Entry point ────────────────────────────────────────────────────────────

def main() -> None:
    print("=== Building Behavioral Baselines (Jul 21 – Aug 19 2018) ===\n")

    print("Building CloudTrail baseline ...")
    ct_baseline = build_ct_baseline()

    print("Building S3 baseline ...")
    s3_baseline = build_s3_baseline()

    print("Building VPC baseline ...")
    vpc_baseline = build_vpc_baseline()

    baselines = {
        "cloudtrail": ct_baseline,
        "s3":         s3_baseline,
        "vpc":        vpc_baseline,
    }

    with open(OUTPUT, "w") as f:
        json.dump(baselines, f, indent=2)

    print(f"\nSaved baselines -> {OUTPUT}")
    print(f"  CloudTrail : {len(ct_baseline)} actors")
    print(f"  S3         : {len(s3_baseline)} actors")
    print(f"  VPC        : {len(vpc_baseline)} actors")


if __name__ == "__main__":
    main()
