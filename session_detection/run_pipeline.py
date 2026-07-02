"""End-to-end MVP pipeline: baseline training + new-log scoring.

Baseline input : ocsf_out_v2/cloudtrail_synthetic_baseline.jsonl
New/incident input: ocsf_out_v2/incident/<date>/cloudtrail_ocsf.jsonl (all dates)

Outputs (under ../output/):
  normalized_baseline_events.parquet
  baseline_sessions.parquet
  global_session_baseline_model.json
  normalized_new_events.parquet
  scored_new_sessions.parquet
  top_risky_sessions.csv

Usage:
    python3 run_pipeline.py
"""
import glob
import json
import os

import pandas as pd

from normalize_cloudtrail import load_cloudtrail, normalize_cloudtrail
from build_sessions import sessionize_events, extract_session_features
from train_global_session_baseline import build_global_baseline_model
from score_sessions import score_sessions_against_global_baseline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # "ceb 2"
DATA_DIR = os.path.join(ROOT, "ocsf_out_v2")
OUT_DIR = os.path.join(ROOT, "output")

BASELINE_LOG = os.path.join(DATA_DIR, "cloudtrail_synthetic_baseline.jsonl")
INCIDENT_LOGS = sorted(glob.glob(os.path.join(DATA_DIR, "incident", "*", "cloudtrail_ocsf.jsonl")))

GAP_MINUTES = 30


def _load_many(paths):
    records = []
    for p in paths:
        records.extend(load_cloudtrail(p))
    return records


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    # ---- Training phase (baseline) ----
    print(f"Loading baseline log: {BASELINE_LOG}")
    baseline_records = load_cloudtrail(BASELINE_LOG)
    baseline_events = normalize_cloudtrail(baseline_records)
    baseline_events.to_parquet(os.path.join(OUT_DIR, "normalized_baseline_events.parquet"), index=False)
    print(f"Normalized {len(baseline_events)} baseline events")

    baseline_sessionized = sessionize_events(baseline_events, gap_minutes=GAP_MINUTES)
    baseline_sessions = extract_session_features(baseline_sessionized)
    baseline_sessions.to_parquet(os.path.join(OUT_DIR, "baseline_sessions.parquet"), index=False)
    print(f"Built {len(baseline_sessions)} baseline sessions")

    model = build_global_baseline_model(baseline_sessions)
    model_path = os.path.join(OUT_DIR, "global_session_baseline_model.json")
    with open(model_path, "w") as f:
        json.dump(model, f, indent=2)
    print(f"Built global baseline model -> {model_path}")

    # ---- Scoring phase (new / incident logs) ----
    print(f"\nLoading {len(INCIDENT_LOGS)} incident log files")
    new_records = _load_many(INCIDENT_LOGS)
    new_events = normalize_cloudtrail(new_records)
    new_events.to_parquet(os.path.join(OUT_DIR, "normalized_new_events.parquet"), index=False)
    print(f"Normalized {len(new_events)} new events")

    new_sessionized = sessionize_events(new_events, gap_minutes=GAP_MINUTES)
    new_sessions = extract_session_features(new_sessionized)
    print(f"Built {len(new_sessions)} new sessions")

    scored = score_sessions_against_global_baseline(new_sessions, model)
    scored.to_parquet(os.path.join(OUT_DIR, "scored_new_sessions.parquet"), index=False)

    top = scored.head(25)[[
        "session_id", "identity_id", "session_start", "session_end", "num_events",
        "duration_minutes", "session_risk_score", "sequence_rarity_score",
        "suspicious_chain_score", "timing_burst_score", "feature_deviation_score",
        "sensitive_action_score", "risk_explanation",
    ]]
    top_csv = os.path.join(OUT_DIR, "top_risky_sessions.csv")
    top.to_csv(top_csv, index=False)

    print(f"\nScored {len(scored)} new sessions -> scored_new_sessions.parquet")
    print(f"Top risky sessions -> {top_csv}")
    print("\nTop 10 risk scores:")
    print(scored[["session_id", "identity_id", "session_risk_score"]].head(10).to_string(index=False))


if __name__ == "__main__":
    main()
