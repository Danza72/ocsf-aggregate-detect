#!/usr/bin/env python3
"""
run_ueba_v3.py

Same as run_ueba.py but uses scorer_v3 (v1 weights + max cross-source aggregation).
Outputs to a separate directory for side-by-side comparison.

Usage:
  python run_ueba.py    --input ocsf_out_v2 --output output_v2_scored_v1  # v1: mean
  python run_ueba_v2.py --input ocsf_out_v2 --output output_v2_scored_v2  # v2: two-track + max
  python run_ueba_v3.py --input ocsf_out_v2 --output output_v2_scored_v3  # v3: v1 weights + max
"""

import argparse
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input",       default="ocsf_out_v2",        help="OCSF input directory")
    p.add_argument("--output",      default="output_v2_scored_v3", help="Output directory")
    p.add_argument("--start",       default=None,                  help="Start date (YYYY-MM-DD). Defaults to first available day.")
    p.add_argument("--end",         default=None,                  help="End date inclusive (YYYY-MM-DD). Defaults to last available day.")
    p.add_argument("--report-date", default=None,                  help="Date to generate HTML report for (YYYY-MM-DD). Defaults to first day in range.")
    return p.parse_args()


def run_build_baselines(ocsf_dir: Path, out_dir: Path) -> None:
    import build_baselines as bb
    bb.CT_BASELINE_FILE  = ocsf_dir / "cloudtrail_synthetic_baseline.jsonl"
    bb.S3_BASELINE_FILE  = ocsf_dir / "s3_synthetic_baseline.jsonl"
    bb.VPC_BASELINE_FILE = ocsf_dir / "vpcflow_synthetic_baseline.jsonl"
    bb.OUTPUT            = out_dir  / "baselines.json"
    bb.main()


def run_build_incident_profiles(day_dir: Path, out_dir: Path, date_str: str) -> None:
    import build_incident_profiles as bip
    bip.CLOUDTRAIL  = day_dir / "cloudtrail_ocsf.jsonl"
    bip.S3_LOGS     = day_dir / "s3_accesslogs_ocsf.jsonl"
    bip.VPC_LOGS    = day_dir / "vpcflow_ocsf.jsonl"
    bip.OUTPUT      = out_dir / f"incident_profiles_{date_str}.json"
    bip.VPC_ENT_OUT = out_dir / f"vpc_entities_{date_str}.json"
    bip.main()


def run_scorer(out_dir: Path, day_dir: Path, date_str: str) -> None:
    import scorer_v3 as sc
    sc.BASELINES_FILE  = out_dir / "baselines.json"
    sc.PROFILES_FILE   = out_dir / f"incident_profiles_{date_str}.json"
    sc.CLOUDTRAIL_FILE = day_dir / "cloudtrail_ocsf.jsonl"
    sc.OUTPUT          = out_dir / f"risk_scores_{date_str}.json"
    sc.main()


def run_exfil_detection(ocsf_dir: Path, out_dir: Path, range_start: str) -> None:
    import detect_low_slow_exfil as dls

    sources = []
    for fname in ["cloudtrail_synthetic_baseline.jsonl",
                  "s3_synthetic_baseline.jsonl",
                  "vpcflow_synthetic_baseline.jsonl"]:
        p = ocsf_dir / fname
        if p.exists():
            sources.append(str(p))

    incident_dir = ocsf_dir / "incident"
    if incident_dir.exists():
        sources.append(str(incident_dir))

    if not sources:
        print("  No sources for exfil detection, skipping.")
        return

    output_path  = str(out_dir / "exfil_alerts.csv")
    baseline_end = f"{range_start}T00:00:00Z"
    alerts = dls.run_detection(
        sources=sources,
        output_path=output_path,
        baseline_end=baseline_end,
        current_days=None,
        min_score=0,
    )
    print(f"  Exfil detection: {len(alerts)} alert(s) -> {output_path}")


def run_report(out_dir: Path, date_str: str,
               range_start: str = None, range_end: str = None,
               range_dates: list = None) -> None:
    import report as rp
    rp.SCORES_FILE       = out_dir / f"risk_scores_{date_str}.json"
    rp.BASELINE_FILE     = out_dir / "baselines.json"
    rp.PROFILES_FILE     = out_dir / f"incident_profiles_{date_str}.json"
    rp.OUTPUT            = out_dir / f"risk_report_{date_str}.html"
    rp.INCIDENT_DATE     = date_str
    rp.DATE_RANGE_START  = range_start
    rp.DATE_RANGE_END    = range_end
    rp.RANGE_DATES       = range_dates or []
    rp.OUT_DIR           = str(out_dir)
    exfil_path           = out_dir / "exfil_alerts.csv"
    rp.EXFIL_FILE        = str(exfil_path) if exfil_path.exists() else None
    rp.main()


def main() -> None:
    args     = parse_args()
    ocsf_dir = Path(args.input)
    out_dir  = Path(args.output)

    incident_dir = ocsf_dir / "incident"

    if not ocsf_dir.exists():
        print(f"Input directory not found: {ocsf_dir}")
        sys.exit(1)

    if not incident_dir.exists():
        print(f"No incident/ subfolder found in {ocsf_dir}")
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)

    all_day_dirs = sorted(d for d in incident_dir.iterdir() if d.is_dir())
    if not all_day_dirs:
        print(f"No incident day folders found in {incident_dir}")
        sys.exit(1)

    # Filter by date range
    start = args.start or all_day_dirs[0].name
    end   = args.end   or all_day_dirs[-1].name
    day_dirs = [d for d in all_day_dirs if start <= d.name <= end]
    if not day_dirs:
        print(f"No incident days found between {start} and {end}")
        sys.exit(1)

    print(f"\n=== UEBA Pipeline v3 (v1 weights + max aggregation) ===")
    print(f"  Input  : {ocsf_dir}")
    print(f"  Output : {out_dir}")
    print(f"  Range  : {start} -> {end}")
    print(f"  Days   : {len(day_dirs)} ({day_dirs[0].name} -> {day_dirs[-1].name})\n")

    print("=== Step 1: Building baselines ===")
    run_build_baselines(ocsf_dir, out_dir)

    report_date    = args.report_date or day_dirs[-1].name
    processed_dates = []

    for day_dir in day_dirs:
        date_str = day_dir.name
        print(f"\n=== {date_str} ===")

        print("  Building incident profiles ...")
        run_build_incident_profiles(day_dir, out_dir, date_str)

        print("  Scoring (scorer_v3) ...")
        run_scorer(out_dir, day_dir, date_str)

        processed_dates.append(date_str)

        if date_str == report_date:
            print("\n=== Step 3: Exfil detection (across full range) ===")
            run_exfil_detection(ocsf_dir, out_dir, start)

            print("\n=== Step 4: Generating HTML report ===")
            run_report(out_dir, date_str,
                       range_start=start, range_end=end,
                       range_dates=list(processed_dates))

    print(f"\nDone. Outputs saved to {out_dir}/")
    print(f"  risk_report_{report_date}.html  <- open in browser")


if __name__ == "__main__":
    main()
