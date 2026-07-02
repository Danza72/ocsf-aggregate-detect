#!/usr/bin/env python3
"""
run_analytics.py

Full threat detection pipeline:
  Step 1 — Build behavioural baselines from synthetic logs
  Step 2 — For each incident day: build profiles + UEBA score
  Step 3 — Low-and-slow exfil detection (network + time-based)
  Step 4 — Kill-chain / session sequence detection
  Step 5 — Generate HTML report

Usage:
  python run_analytics.py --input test_data_advanced/ocsf_out --output output_advanced
  python run_analytics.py --input ocsf_out_v2 --output output_v2_scored_v3
"""

import argparse
import glob as _glob
import json as _json
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input",       default="ocsf_out_v2",        help="OCSF input directory")
    p.add_argument("--output",      default="output_v2_scored_v3", help="Output directory")
    p.add_argument("--start",       default=None,                  help="Start date (YYYY-MM-DD)")
    p.add_argument("--end",         default=None,                  help="End date inclusive (YYYY-MM-DD)")
    p.add_argument("--report-date", default=None,                  help="Date for HTML report (YYYY-MM-DD)")
    p.add_argument("--skip-session", action="store_true",          help="Skip session/sequence detection")
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


def run_session_detection(ocsf_dir: Path, out_dir: Path) -> None:
    """Kill-chain sequence detection using session-level N-gram scoring."""
    sd_path = str(Path(__file__).parent / "session_detection")
    if sd_path not in sys.path:
        sys.path.insert(0, sd_path)

    from normalize_cloudtrail import load_cloudtrail, normalize_cloudtrail
    from build_sessions import sessionize_events, extract_session_features
    from train_global_session_baseline import build_global_baseline_model
    from score_sessions import score_sessions_against_global_baseline

    baseline_log = ocsf_dir / "cloudtrail_synthetic_baseline.jsonl"
    if not baseline_log.exists():
        print("  Session detection: baseline log not found, skipping.")
        return

    # Training phase
    print("  Building session baseline model ...")
    baseline_records = load_cloudtrail(str(baseline_log))
    baseline_events  = normalize_cloudtrail(baseline_records)
    if baseline_events.empty:
        print("  Session detection: baseline normalised to 0 events, skipping.")
        return
    baseline_sessions = extract_session_features(
        sessionize_events(baseline_events, gap_minutes=30)
    )
    model = build_global_baseline_model(baseline_sessions)
    print(f"  Baseline: {len(baseline_sessions)} sessions from {len(baseline_events)} events")

    # Scoring phase
    incident_logs = sorted(
        _glob.glob(str(ocsf_dir / "incident" / "*" / "cloudtrail_ocsf.jsonl"))
    )
    if not incident_logs:
        print("  Session detection: no incident logs found, skipping.")
        return

    new_records = []
    for p in incident_logs:
        new_records.extend(load_cloudtrail(p))
    new_events = normalize_cloudtrail(new_records)
    if new_events.empty:
        print("  Session detection: incident logs normalised to 0 events, skipping.")
        return

    new_sessions = extract_session_features(
        sessionize_events(new_events, gap_minutes=30)
    )
    scored = score_sessions_against_global_baseline(new_sessions, model)

    top_csv = out_dir / "top_risky_sessions.csv"
    scored.head(50)[[
        "session_id", "identity_id", "session_start", "session_end",
        "num_events", "duration_minutes",
        "session_risk_score", "sequence_rarity_score", "suspicious_chain_score",
        "timing_burst_score", "feature_deviation_score", "sensitive_action_score",
        "risk_explanation",
    ]].to_csv(str(top_csv), index=False)

    print(f"  Session detection: {len(scored)} sessions scored -> {top_csv}")
    top5 = scored[["identity_id", "session_risk_score"]].head(5)
    for _, row in top5.iterrows():
        print(f"    {row['identity_id']:30s}  session_risk={row['session_risk_score']:.1f}")


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

    exfil_path = out_dir / "exfil_alerts.csv"
    rp.EXFIL_FILE = str(exfil_path) if exfil_path.exists() else None

    session_path = out_dir / "top_risky_sessions.csv"
    rp.SESSION_FILE = str(session_path) if session_path.exists() else None

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

    start = args.start or all_day_dirs[0].name
    end   = args.end   or all_day_dirs[-1].name
    day_dirs = [d for d in all_day_dirs if start <= d.name <= end]
    if not day_dirs:
        print(f"No incident days found between {start} and {end}")
        sys.exit(1)

    print(f"\n=== Analytics Pipeline ===")
    print(f"  Input  : {ocsf_dir}")
    print(f"  Output : {out_dir}")
    print(f"  Range  : {start} -> {end}")
    print(f"  Days   : {len(day_dirs)} ({day_dirs[0].name} -> {day_dirs[-1].name})\n")

    print("=== Step 1: Building baselines ===")
    run_build_baselines(ocsf_dir, out_dir)

    report_date     = args.report_date or day_dirs[-1].name
    processed_dates = []

    for day_dir in day_dirs:
        date_str = day_dir.name
        print(f"\n=== {date_str} ===")

        print("  Building incident profiles ...")
        run_build_incident_profiles(day_dir, out_dir, date_str)

        print("  Scoring (UEBA v3) ...")
        run_scorer(out_dir, day_dir, date_str)

        processed_dates.append(date_str)

        if date_str == report_date:
            print("\n=== Step 3: Exfil detection (across full range) ===")
            run_exfil_detection(ocsf_dir, out_dir, start)

            if not args.skip_session:
                print("\n=== Step 4: Session / sequence detection ===")
                run_session_detection(ocsf_dir, out_dir)

            print("\n=== Step 5: Generating HTML report ===")
            run_report(out_dir, date_str,
                       range_start=start, range_end=end,
                       range_dates=list(processed_dates))

    print(f"\nDone. Outputs saved to {out_dir}/")
    print(f"  risk_report_{report_date}.html  <- open in browser")


if __name__ == "__main__":
    main()
