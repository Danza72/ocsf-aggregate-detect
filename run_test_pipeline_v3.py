#!/usr/bin/env python3
"""
run_test_pipeline_v3.py

Same as run_test_pipeline.py but uses scorer_v3 (v1 weights + max cross-source).
Outputs to test_data_v3/ for side-by-side comparison.

Usage:
  python generate_test_dataset.py     # generate test data first (shared)
  python run_test_pipeline.py         # v1: mean aggregation  -> test_data/
  python run_test_pipeline_v2.py      # v2: two-track + max   -> test_data_v2/
  python run_test_pipeline_v3.py      # v3: v1 weights + max  -> test_data_v3/
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

TEST_DIR     = Path("test_data_v3")
OCSF_DIR     = Path("test_data/ocsf_out")
INCIDENT_DIR = OCSF_DIR / "incident"

INCIDENT_START = datetime(2018, 8, 20)
INCIDENT_DAYS  = 14


def _incident_date(day_offset: int) -> str:
    return (INCIDENT_START + timedelta(days=day_offset)).strftime("%Y-%m-%d")


def _check_inputs() -> bool:
    required = [
        OCSF_DIR / "cloudtrail_synthetic_baseline.jsonl",
        OCSF_DIR / "s3_synthetic_baseline.jsonl",
        OCSF_DIR / "vpcflow_synthetic_baseline.jsonl",
        Path("test_data") / "ground_truth.json",
    ]
    day0 = INCIDENT_DIR / "2018-08-20"
    required += [
        day0 / "cloudtrail_ocsf.jsonl",
        day0 / "s3_accesslogs_ocsf.jsonl",
        day0 / "vpcflow_ocsf.jsonl",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        print("Missing test data — run generate_test_dataset.py first:")
        for m in missing:
            print(f"  {m}")
        return False
    return True


def run_build_baselines() -> None:
    import build_baselines as bb
    bb.CT_BASELINE_FILE  = OCSF_DIR / "cloudtrail_synthetic_baseline.jsonl"
    bb.S3_BASELINE_FILE  = OCSF_DIR / "s3_synthetic_baseline.jsonl"
    bb.VPC_BASELINE_FILE = OCSF_DIR / "vpcflow_synthetic_baseline.jsonl"
    bb.OUTPUT            = TEST_DIR  / "baselines.json"
    bb.main()


def run_build_incident_profiles(day_dir: Path, date_str: str) -> None:
    import build_incident_profiles as bip
    bip.CLOUDTRAIL  = day_dir / "cloudtrail_ocsf.jsonl"
    bip.S3_LOGS     = day_dir / "s3_accesslogs_ocsf.jsonl"
    bip.VPC_LOGS    = day_dir / "vpcflow_ocsf.jsonl"
    bip.OUTPUT      = TEST_DIR / f"incident_profiles_{date_str}.json"
    bip.VPC_ENT_OUT = TEST_DIR / f"vpc_entities_{date_str}.json"
    bip.main()


def run_scorer(date_str: str, day_dir: Path) -> None:
    import scorer_v3 as sc
    sc.BASELINES_FILE  = TEST_DIR / "baselines.json"
    sc.PROFILES_FILE   = TEST_DIR / f"incident_profiles_{date_str}.json"
    sc.CLOUDTRAIL_FILE = day_dir  / "cloudtrail_ocsf.jsonl"
    sc.OUTPUT          = TEST_DIR / f"risk_scores_{date_str}.json"
    sc.main()


def run_report(date_str: str) -> None:
    import report as rp
    rp.SCORES_FILE   = TEST_DIR / f"risk_scores_{date_str}.json"
    rp.BASELINE_FILE = TEST_DIR / "baselines.json"
    rp.PROFILES_FILE = TEST_DIR / f"incident_profiles_{date_str}.json"
    rp.OUTPUT        = TEST_DIR / f"risk_report_{date_str}.html"
    rp.main()


def validate() -> None:
    day0_path = TEST_DIR / f"risk_scores_{_incident_date(0)}.json"
    if not day0_path.exists():
        print(f"[validate] {day0_path} not found")
        return

    day0 = json.loads(day0_path.read_text())

    print("\n" + "=" * 65)
    print("DAY 0 SCORES  (scorer_v3 — 2018-08-20)")
    print("=" * 65)
    print(f"  {'Actor':<14} {'v3 Score':>9}")
    print("  " + "-" * 30)

    for actor in ["alice_m", "dave_f", "oscar_r",
                  "bob_d", "carol_s", "svc_backup", "svc_monthly"]:
        r = day0.get(actor)
        score = f"{r['final_score']:.4f}" if r else "—"
        print(f"  {actor:<14} {score:>9}")

    print("\n" + "=" * 65)
    print("MULTI-DAY SCORES  (time-based actors — days 0-13)")
    print("=" * 65)

    time_based = ["mallory_t", "neil_k", "petra_v"]
    print(f"  {'Day':<12}" + "".join(f" {a:>10}" for a in time_based))
    print("  " + "-" * (12 + 11 * len(time_based)))

    for day_offset in range(INCIDENT_DAYS):
        date_str   = _incident_date(day_offset)
        score_path = TEST_DIR / f"risk_scores_{date_str}.json"
        row        = f"  {date_str:<12}"
        if score_path.exists():
            scores = json.loads(score_path.read_text())
            for actor in time_based:
                r = scores.get(actor)
                row += f" {r['final_score']:>10.4f}" if r else f" {'—':>10}"
        print(row)

    print("=" * 65)


def main() -> None:
    if not _check_inputs():
        sys.exit(1)

    TEST_DIR.mkdir(parents=True, exist_ok=True)

    print("\n=== Step 1: Building baselines (30-day, once) ===")
    run_build_baselines()

    for day_offset in range(INCIDENT_DAYS):
        date_str = _incident_date(day_offset)
        day_dir  = INCIDENT_DIR / date_str

        if not day_dir.exists():
            print(f"\n  Skipping {date_str} — incident folder not found")
            continue

        print(f"\n=== Day {day_offset:>2} ({date_str}) ===")
        print("  Building incident profiles ...")
        run_build_incident_profiles(day_dir, date_str)

        print("  Scoring (scorer_v3) ...")
        run_scorer(date_str, day_dir)

        if day_offset == 0:
            print("  Generating HTML report ...")
            run_report(date_str)

    validate()

    print(f"\nAll outputs saved to {TEST_DIR}/")
    print(f"  risk_report_2018-08-20.html  <- compare with test_data/ and test_data_v2/")


if __name__ == "__main__":
    main()
