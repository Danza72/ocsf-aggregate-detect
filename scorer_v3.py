#!/usr/bin/env python3
"""
scorer_v3.py
Unified per-actor risk scorer — v1 weights, max cross-source aggregation.

Loads pre-built baselines and incident profiles, then scores each actor's
incident-day behavior against their normal baseline.

CloudTrail : per-event UEBA (6 dimensions)
S3         : behavioral (6 dimensions vs S3 baseline)
VPC        : behavioral (6 dimensions vs VPC baseline)

Final score: max of available source scores.
Within-source weights unchanged from v1. Only cross-source aggregation changed:
mean → max so the strongest evidence channel drives the final score.
An actor missing a source is not penalised — only present sources contribute.

Inputs:
  baselines.json          (from build_baselines.py)
  incident_profiles.json  (from build_incident_profiles.py)
  ocsf_out/cloudtrail_ocsf.jsonl

Output:
  risk_scores.json
"""

import json
import math
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
BASELINES_FILE   = Path("baselines.json")
PROFILES_FILE    = Path("incident_profiles.json")
CLOUDTRAIL_FILE  = Path("ocsf_out/cloudtrail_ocsf.jsonl")
OUTPUT           = Path("risk_scores.json")

# ── CloudTrail dimension weights (must sum to 1.0) ─────────────────────────
#
#   new_operation        API call never seen in baseline.
#   new_resource         AWS resource never accessed before.
#   new_region           AWS region never used in baseline.
#   volume_zscore        Hourly event count is statistically abnormal.
#   new_ip_known_region  New source IP in a familiar region (IP rotation).
#   low_frequency_hour   Activity at an hour rare or absent in baseline.
#
CT_WEIGHTS: dict[str, float] = {
    "new_operation":        0.25,
    "new_resource":         0.20,
    "new_region":           0.20,
    "volume_zscore":        0.15,
    "new_ip_known_region":  0.10,
    "low_frequency_hour":   0.10,
}
assert abs(sum(CT_WEIGHTS.values()) - 1.0) < 1e-9

CT_DIMS = list(CT_WEIGHTS)

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


def _bytes_score(b: int | None) -> float:
    """Log-scale score: 0 → 0.0, 1 TB → 1.0."""
    if not b:
        return 0.0
    MAX = 1e12
    return min(math.log10(b + 1) / math.log10(MAX + 1), 1.0)


# ── Phase 1: CloudTrail scoring ────────────────────────────────────────────

def score_ct(ct_baseline: dict) -> dict[str, dict]:
    """Score every real CT event; return per-actor aggregated results."""
    real = _read_jsonl(CLOUDTRAIL_FILE)

    # Pre-pass: count events per (actor, hour-slot) for volume z-score dimension
    slot_counts: dict[tuple, int] = defaultdict(int)
    for ev in real:
        actor = (ev.get("actor") or {}).get("user", {}).get("name")
        ts    = ev.get("time")
        if actor and ts:
            slot_counts[(actor, _ts_to_dt(ts).strftime("%Y-%m-%d %H"))] += 1

    # Per-actor accumulators across all events
    actor_scores:  dict[str, list[float]]      = defaultdict(list)
    actor_dim_sum: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    for ev in real:
        actor  = (ev.get("actor") or {}).get("user", {}).get("name")
        ts     = ev.get("time")
        op     = (ev.get("api") or {}).get("operation") or ""
        ip     = (ev.get("src_endpoint") or {}).get("ip") or ""
        region = (ev.get("cloud") or {}).get("region") or ""
        res_names = [
            (r or {}).get("name")
            for r in (ev.get("resources") or [])
            if (r or {}).get("name")
        ]
        dt = _ts_to_dt(ts) if ts else None

        if not actor:
            continue
        # Skip actors with no CT baseline — can't score without a reference
        profile = ct_baseline.get(actor)
        if not profile or profile["baseline_event_count"] == 0:
            continue

        known_ops = profile["known_operations"]
        known_ips = set(profile["known_ips"])
        known_reg = set(profile["known_regions"])
        known_res = set(profile["known_resources"])
        hour_dist = profile["known_hours"]
        vol_mean  = profile["volume_stats"]["mean"]
        vol_std   = profile["volume_stats"]["std"]

        d_op  = 0.0 if op in known_ops else 1.0

        if not res_names:
            d_res = 0.0
        else:
            d_res = 1.0 if any(r not in known_res for r in res_names) else 0.0

        d_loc = 0.0 if (not region or region in known_reg) else 1.0

        if dt:
            # How many events this actor had in the same hour-slot on the incident day
            slot_count = slot_counts.get((actor, dt.strftime("%Y-%m-%d %H")), 0)
            if vol_std > 0:
                # Standard z-score: 3 stdevs above baseline mean → score 1.0
                d_vol = min(abs((slot_count - vol_mean) / vol_std) / 3.0, 1.0)
            elif slot_count > vol_mean:
                # Zero variance in baseline (actor always had identical counts):
                # any excess above the mean is proportionally penalised
                d_vol = min((slot_count - vol_mean) / max(vol_mean, 1.0), 1.0)
            else:
                d_vol = 0.0
        else:
            d_vol = 0.0

        # New IP but familiar region — targets IP rotation within known infrastructure.
        # A new IP in a new region is already caught by new_region; this catches
        # the subtler case of a different machine operating in the actor's normal region.
        d_ip = 1.0 if (ip and ip not in known_ips and region and region in known_reg) else 0.0

        if dt and hour_dist:
            max_freq = max(hour_dist.values())
            freq     = hour_dist.get(str(dt.hour), hour_dist.get(dt.hour, 0))
            # Busiest baseline hour → 0.0 (normal); unseen hour → 1.0 (suspicious)
            d_lfh = 1.0 - (freq / max_freq) if max_freq > 0 else 0.0
        else:
            d_lfh = 0.0

        composite = (
            CT_WEIGHTS["new_operation"]       * d_op  +
            CT_WEIGHTS["new_resource"]        * d_res +
            CT_WEIGHTS["new_region"]          * d_loc +
            CT_WEIGHTS["volume_zscore"]       * d_vol +
            CT_WEIGHTS["new_ip_known_region"] * d_ip  +
            CT_WEIGHTS["low_frequency_hour"]  * d_lfh
        )

        actor_scores[actor].append(composite)
        # Accumulate raw dimension values for per-actor averages
        for dim, val in zip(CT_DIMS, [d_op, d_res, d_loc, d_vol, d_ip, d_lfh]):
            actor_dim_sum[actor][dim] += val

    # Aggregate: mean composite score per actor; dimension values show
    # what fraction of events triggered each signal
    results: dict[str, dict] = {}
    for actor, scores in actor_scores.items():
        n = len(scores)
        results[actor] = {
            "score":       round(statistics.mean(scores), 4),
            "score_max":   round(max(scores), 4),  # worst single event
            "event_count": n,
            "dimensions":  {
                dim: round(actor_dim_sum[actor][dim] / n, 4)
                for dim in CT_DIMS
            },
        }

    print(f"[ct_scoring]   {sum(len(s) for s in actor_scores.values())} events "
          f"scored across {len(results)} actors")
    return results


# ── Phase 2: S3 scoring ────────────────────────────────────────────────────

def score_s3(profiles: dict, s3_baseline: dict) -> dict[str, dict]:
    """
    6 equal-weight dimensions (1/6 each):
      new_operation  — operation not seen in baseline
      new_bucket     — bucket not seen in baseline
      new_src_ip     — source IP not seen in baseline
      error_rate     — fraction of non-2xx responses
      bytes_zscore   — today's total bytes vs baseline daily distribution
      event_zscore   — today's event count vs baseline daily distribution
    """
    results: dict[str, dict] = {}

    for name, p in profiles.items():
        s3 = p.get("s3")
        if not s3:
            continue

        bl = s3_baseline.get(name)

        today_bytes   = s3["bytes_total"]
        today_events  = s3["event_count"]
        today_ops     = set(s3["known_operations"])
        today_buckets = set(s3["known_buckets"])
        today_ips     = {e["ip"] for e in s3.get("known_ips", [])}

        # Error rate: fraction of non-2xx responses (computed regardless of baseline)
        codes     = s3.get("response_codes", {})
        err_count = sum(cnt for code, cnt in codes.items()
                        if not str(code).startswith("2"))
        d_error   = err_count / today_events if today_events > 0 else 0.0

        if bl:
            known_ops     = set(bl["known_operations"])
            known_buckets = set(bl["known_buckets"])
            known_ips     = set(bl["known_ips"])

            d_new_op     = 1.0 if today_ops     - known_ops     else 0.0
            d_new_bucket = 1.0 if today_buckets - known_buckets else 0.0
            d_new_ip     = 1.0 if today_ips     - known_ips     else 0.0

            bm, bs = bl["daily_bytes"]["mean"], bl["daily_bytes"]["std"]
            if bs > 0:
                # Z-score: 3 stdevs above baseline mean → score 1.0
                d_bytes = min(abs((today_bytes - bm) / bs) / 3.0, 1.0)
            elif today_bytes > bm:
                # Zero variance: actor always transferred same bytes — penalise any excess
                d_bytes = min((today_bytes - bm) / max(bm, 1.0), 1.0)
            else:
                d_bytes = 0.0

            em, es = bl["daily_events"]["mean"], bl["daily_events"]["std"]
            if es > 0:
                # Z-score: 3 stdevs above baseline mean → score 1.0
                d_events = min(abs((today_events - em) / es) / 3.0, 1.0)
            elif today_events > em:
                # Zero variance: actor always had same event count — penalise any excess
                d_events = min((today_events - em) / max(em, 1.0), 1.0)
            else:
                d_events = 0.0
        else:
            # No baseline: all novelty dimensions fire at max; bytes uses
            # log-scale fallback since magnitude still matters without a reference
            d_new_op     = 1.0
            d_new_bucket = 1.0
            d_new_ip     = 1.0
            d_bytes      = _bytes_score(today_bytes)
            d_events     = 1.0

        score = (d_new_op + d_new_bucket + d_new_ip + d_error + d_bytes + d_events) / 6

        results[name] = {
            "score":        round(score, 4),
            "event_count":  today_events,
            "has_baseline": bl is not None,
            "dimensions": {
                "new_operation": round(d_new_op,     4),
                "new_bucket":    round(d_new_bucket, 4),
                "new_src_ip":    round(d_new_ip,     4),
                "error_rate":    round(d_error,       4),
                "bytes_zscore":  round(d_bytes,       4),
                "event_zscore":  round(d_events,      4),
            },
        }

    print(f"[s3_scoring]   {len(results)} actors scored")
    return results


# ── Phase 3: VPC scoring ───────────────────────────────────────────────────

def score_vpc(profiles: dict, vpc_baseline: dict) -> dict[str, dict]:
    """
    6 equal-weight dimensions (1/6 each):
      new_dst_ip    — destination IP not seen in baseline
      new_dst_port  — destination port not seen in baseline
      reject_ratio  — REJECT / total flows (baseline is 0 rejects)
      bytes_zscore  — today's total bytes vs baseline daily distribution
      flow_zscore   — today's flow count vs baseline daily distribution
      new_protocol  — protocol not seen in baseline
    """
    results: dict[str, dict] = {}

    for name, p in profiles.items():
        vpc = p.get("vpc")
        if not vpc:
            continue

        bl = vpc_baseline.get(name)

        actions        = vpc.get("actions", {})
        total_flows    = vpc["event_count"]
        reject_count   = actions.get("REJECT", 0)
        today_bytes    = vpc["bytes_total"]
        today_dst_ips  = {e["ip"] for e in vpc.get("dst_ips", [])}
        today_ports    = {int(pt) for pt in vpc.get("dst_ports", {}) if str(pt).isdigit()}
        today_protocols= set(vpc.get("protocols", []))

        d_reject = reject_count / total_flows if total_flows > 0 else 0.0

        if bl:
            known_dst_ips   = set(bl["known_dst_ips"])
            known_dst_ports = set(bl["known_dst_ports"])
            known_protocols = set(bl["known_protocols"])

            d_new_ip = 1.0 if today_dst_ips - known_dst_ips else 0.0

            bm, bs = bl["daily_bytes"]["mean"], bl["daily_bytes"]["std"]
            if bs > 0:
                d_bytes = min(abs((today_bytes - bm) / bs) / 3.0, 1.0)
            elif today_bytes > bm:
                d_bytes = min((today_bytes - bm) / max(bm, 1.0), 1.0)
            else:
                d_bytes = 0.0

            fm, fs = bl["daily_flows"]["mean"], bl["daily_flows"]["std"]
            if fs > 0:
                d_flows = min(abs((total_flows - fm) / fs) / 3.0, 1.0)
            elif total_flows > fm:
                d_flows = min((total_flows - fm) / max(fm, 1.0), 1.0)
            else:
                d_flows = 0.0

            d_new_port = 1.0 if today_ports - known_dst_ports else 0.0

            d_proto = 1.0 if today_protocols - known_protocols else 0.0
        else:
            # No baseline: all novelty dimensions fire at max
            d_new_ip   = 1.0
            d_new_port = 1.0
            d_bytes    = _bytes_score(today_bytes)
            d_flows    = 1.0
            d_proto    = 1.0

        score = (d_new_ip + d_new_port + d_reject + d_bytes + d_flows + d_proto) / 6

        results[name] = {
            "score":        round(score, 4),
            "event_count":  total_flows,
            "has_baseline": bl is not None,
            "dimensions":   {
                "new_dst_ip":   round(d_new_ip,   4),
                "new_dst_port": round(d_new_port, 4),
                "reject_ratio": round(d_reject,   4),
                "bytes_zscore": round(d_bytes,    4),
                "flow_zscore":  round(d_flows,    4),
                "new_protocol": round(d_proto,    4),
            },
        }

    print(f"[vpc_scoring]  {len(results)} actors scored")
    return results


# ── Phase 4: Combine ───────────────────────────────────────────────────────

def combine_scores(
    ct_scores:  dict[str, dict],
    s3_scores:  dict[str, dict],
    vpc_scores: dict[str, dict],
    profiles:   dict,
) -> dict:
    # Union of all actors across every source — an actor missing from a source
    # is not penalised; only present sources contribute to the final score
    all_actors = set(profiles) | set(ct_scores) | set(s3_scores) | set(vpc_scores)
    results: dict[str, dict] = {}

    for name in sorted(all_actors):
        ct  = ct_scores.get(name)
        s3  = s3_scores.get(name)
        vpc = vpc_scores.get(name)

        available = {k: v for k, v in
                     [("cloudtrail", ct), ("s3", s3), ("vpc", vpc)] if v}
        if not available:
            continue

        # Max across sources: the strongest evidence channel drives the final score
        final = max(v["score"] for v in available.values())
        p     = profiles.get(name, {})

        results[name] = {
            "final_score":     round(final, 4),
            "sources_used":    list(available.keys()),
            "is_system_actor": p.get("is_system_actor"),
            "cloudtrail":      ct,
            "s3":              s3,
            "vpc":             vpc,
        }

    return results


# ── Reporting ──────────────────────────────────────────────────────────────

def print_summary(results: dict) -> None:
    def _row(name: str, r: dict, tag: str) -> None:
        ct_s  = f"{r['cloudtrail']['score']:.4f}" if r["cloudtrail"] else "  —   "
        s3_s  = f"{r['s3']['score']:.4f}"         if r["s3"]         else "  —   "
        vpc_s = f"{r['vpc']['score']:.4f}"         if r["vpc"]        else "  —   "
        srcs  = "+".join(r["sources_used"])
        print(f"  {tag}{name:<42} {srcs:<22} {ct_s:>6} {s3_s:>6} {vpc_s:>6} "
              f"{r['final_score']:>7.4f}")

    header = f"  {'actor':<42} {'sources':<22} {'CT':>6} {'S3':>6} {'VPC':>6} {'FINAL':>7}"
    divider = "  " + "-" * 95

    def _has_any_baseline(r: dict) -> bool:
        # CT score only exists if a baseline was found (score_ct skips unknowns)
        if r["cloudtrail"]:
            return True
        if r["s3"]  and r["s3"].get("has_baseline"):
            return True
        if r["vpc"] and r["vpc"].get("has_baseline"):
            return True
        return False

    # Split into known actors (at least one baseline) vs first-seen entities
    known   = {n: r for n, r in results.items() if     _has_any_baseline(r)}
    unknown = {n: r for n, r in results.items() if not _has_any_baseline(r)}

    print("\n=== BEHAVIORAL ANOMALY SCORES (known actors) ===")
    print(header)
    print(divider)
    for name, r in sorted(known.items(), key=lambda x: -x[1]["final_score"]):
        tag = "*" if r["is_system_actor"] else " "
        _row(name, r, tag)
    print("  (* = system actor)")

    if unknown:
        print("\n=== FIRST-SEEN ENTITIES (no baseline — investigate separately) ===")
        print(header)
        print(divider)
        for name, r in sorted(unknown.items(), key=lambda x: -x[1]["final_score"]):
            tag = "E" if name.startswith("eni-") else "?"
            _row(name, r, tag)
        print("  (E = unresolved ENI, ? = actor seen for first time)")


# ── Entry point ────────────────────────────────────────────────────────────

def main() -> None:
    print("=== Unified Risk Scorer (CloudTrail + S3 + VPC) ===\n")

    baselines = json.loads(BASELINES_FILE.read_text())
    profiles  = json.loads(PROFILES_FILE.read_text())

    print("[Phase 1] Scoring CloudTrail events ...")
    ct_scores = score_ct(baselines["cloudtrail"])

    print("[Phase 2] Scoring S3 ...")
    s3_scores = score_s3(profiles, baselines["s3"])

    print("[Phase 3] Scoring VPC ...")
    vpc_scores = score_vpc(profiles, baselines["vpc"])

    print("[Phase 4] Combining scores ...")
    results = combine_scores(ct_scores, s3_scores, vpc_scores, profiles)

    with open(OUTPUT, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved {len(results)} actor risk scores -> {OUTPUT}")

    print_summary(results)


if __name__ == "__main__":
    main()
