"""Score new sessions against the global session baseline model and produce
a risk score (0-100) plus a human-readable explanation per session.

Scoring is global, not per-identity: identity_id is reported but never used
to decide whether a chain is normal -- only the baseline model (built across
all identities) is consulted.

Usage:
    python3 score_sessions.py <new_session_features.parquet> <model.json> <scored_sessions.parquet> <top_risky.csv>
"""
import json
import sys
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np
import pandas as pd

# (category_a, category_b) chains that are suspicious when b follows a in a session.
SUSPICIOUS_CATEGORY_CHAINS: List[Tuple[str, str]] = [
    ("Discovery", "PermissionChange"),
    ("Discovery", "CredentialAccess"),
    ("Discovery", "DataAccess"),
    ("PermissionChange", "CredentialAccess"),
    ("PermissionChange", "DataAccess"),
]

SUSPICIOUS_TRIPLES: List[Tuple[str, str, str]] = [
    ("Auth", "Discovery", "DataAccess"),
    ("Auth", "Discovery", "PermissionChange"),
]

# (event_a, event_b) raw-event chains, checked anywhere a precedes b in the session.
SUSPICIOUS_EVENT_PAIRS: List[Tuple[str, str]] = [
    ("GetBucketPolicy", "PutBucketPolicy"),
    ("ListRoles", "AssumeRole"),
    ("CreateAccessKey", "GetObject"),
    ("StopLogging", "GetObject"),
    ("DeleteTrail", "GetObject"),
    ("PutBucketPolicy", "GetObject"),
    ("PutBucketAcl", "GetObject"),
]

DEFENSE_EVASION_FOLLOWUP_WEIGHT = 8.0


def _ngrams(seq: Sequence[str], n: int) -> List[tuple]:
    if len(seq) < n:
        return []
    return [tuple(seq[i:i + n]) for i in range(len(seq) - n + 1)]


def _sequence_rarity_score(row: pd.Series, model: Dict[str, Any]) -> Tuple[float, List[str]]:
    """0-25. Rare action-category 2-grams/3-grams relative to the baseline raise risk."""
    cats = list(row["ordered_action_categories"])
    bigrams = _ngrams(cats, 2)
    trigrams = _ngrams(cats, 3)

    bigram_freq = model["category_2gram_freq"]
    trigram_freq = model["category_3gram_freq"]

    reasons = []
    if not bigrams and not trigrams:
        return 0.0, reasons

    rarity_vals = []
    rare_examples = []
    for bg in bigrams:
        key = " -> ".join(bg)
        freq = bigram_freq.get(key, 0.0)
        rarity_vals.append(1.0 - freq)
        if freq == 0.0:
            rare_examples.append(key)
    for tg in trigrams:
        key = " -> ".join(tg)
        freq = trigram_freq.get(key, 0.0)
        rarity_vals.append(1.0 - freq)
        if freq == 0.0:
            rare_examples.append(key)

    avg_rarity = float(np.mean(rarity_vals)) if rarity_vals else 0.0
    score = min(avg_rarity * 25.0, 25.0)

    if rare_examples:
        sample = ", ".join(rare_examples[:3])
        reasons.append(f"contains rare action chain(s) never seen in baseline: {sample}")
    return score, reasons


def _suspicious_chain_score(row: pd.Series) -> Tuple[float, List[str]]:
    """0-30. Known attacker-pattern chains."""
    cats = list(row["ordered_action_categories"])
    events = list(row["ordered_event_sequence"])
    score = 0.0
    reasons: List[str] = []

    cat_positions: Dict[str, List[int]] = {}
    for i, c in enumerate(cats):
        cat_positions.setdefault(c, []).append(i)

    for a, b in SUSPICIOUS_CATEGORY_CHAINS:
        if a in cat_positions and b in cat_positions:
            if min(cat_positions[a]) < max(cat_positions[b]):
                score += 6.0
                reasons.append(f"{a} -> {b} chain present")

    for a, b, c in SUSPICIOUS_TRIPLES:
        if a in cat_positions and b in cat_positions and c in cat_positions:
            if min(cat_positions[a]) < min(cat_positions[b]) < max(cat_positions[c]):
                score += 4.0
                reasons.append(f"{a} -> {b} -> {c} chain present")

    event_positions: Dict[str, List[int]] = {}
    for i, e in enumerate(events):
        event_positions.setdefault(e, []).append(i)

    for a, b in SUSPICIOUS_EVENT_PAIRS:
        if a in event_positions and b in event_positions:
            if min(event_positions[a]) < max(event_positions[b]):
                score += 5.0
                reasons.append(f"{a} followed by {b}")

    if "ListBuckets" in event_positions:
        first_list = min(event_positions["ListBuckets"])
        getobjects_after = sum(1 for i in event_positions.get("GetObject", []) if i > first_list)
        if getobjects_after >= 5:
            score += 6.0
            reasons.append(f"ListBuckets followed by {getobjects_after} GetObject calls (bulk access)")

    if cats and cats[0] == "DefenseEvasion" and len(cats) > 1:
        score += DEFENSE_EVASION_FOLLOWUP_WEIGHT
        reasons.append("DefenseEvasion action occurred before other activity in the session")

    return min(score, 30.0), reasons


def _timing_burst_score(row: pd.Series, model: Dict[str, Any]) -> Tuple[float, List[str]]:
    """0-20. Unusually fast/dense sessions, or fast progression to sensitive actions."""
    score = 0.0
    reasons: List[str] = []
    dist = model["feature_distributions"]

    for feature, weight in [("events_per_minute", 7.0), ("max_events_in_5min", 7.0)]:
        p95 = dist[feature]["p95"]
        val = row[feature]
        if p95 > 0 and val > p95:
            ratio = min(val / p95, 3.0)
            add = weight * (ratio - 1.0) / 2.0
            score += max(add, 0.0)
            reasons.append(f"{feature}={val:.2f} exceeds baseline p95 ({p95:.2f})")

    for col, label, threshold_min in [
        ("minutes_discovery_to_permission_change", "Discovery to PermissionChange", 10),
        ("minutes_discovery_to_credential_access", "Discovery to CredentialAccess", 10),
        ("minutes_discovery_to_data_access", "Discovery to DataAccess", 10),
    ]:
        val = row.get(col)
        if pd.notna(val) and val <= threshold_min:
            score += 6.0
            reasons.append(f"fast progression from {label} in {val:.1f} minutes")

    return min(score, 20.0), reasons


def _feature_deviation_score(row: pd.Series, model: Dict[str, Any]) -> Tuple[float, List[str]]:
    """0-15. z-score style deviation across key numeric features."""
    dist = model["feature_distributions"]
    z_scores = []
    reasons: List[str] = []
    for feature in ["num_events", "duration_minutes", "unique_services",
                     "num_getobject_events", "num_sensitive_actions", "failed_event_ratio"]:
        mean, std = dist[feature]["mean"], dist[feature]["std"]
        val = row[feature]
        z = abs((val - mean) / std) if std else 0.0
        z_scores.append(z)
        if z > 3:
            reasons.append(f"{feature}={val:.2f} is far from baseline (z={z:.1f})")

    avg_z = float(np.mean(z_scores)) if z_scores else 0.0
    score = min(avg_z / 4.0 * 15.0, 15.0)
    return score, reasons


def _sensitive_action_score(row: pd.Series) -> Tuple[float, List[str]]:
    """0-10. Raw presence/volume of sensitive categories."""
    score = 0.0
    reasons: List[str] = []

    weights = {
        "num_permission_change_actions": 3.0,
        "num_credential_access_actions": 3.0,
        "num_persistence_actions": 2.0,
        "num_defense_evasion_actions": 3.0,
    }
    for col, w in weights.items():
        count = row[col]
        if count > 0:
            score += min(count * w, w * 2)
            reasons.append(f"{count} {col.replace('num_', '').replace('_actions', '')} action(s)")

    if row["num_data_access_actions"] >= 20:
        score += 2.0
        reasons.append(f"high-volume data access ({row['num_data_access_actions']} events)")

    return min(score, 10.0), reasons


def generate_risk_explanation(row: pd.Series, component_scores: Dict[str, Tuple[float, List[str]]]) -> str:
    """Build a human-readable explanation from the per-component scores/reasons."""
    all_reasons: List[str] = []
    for _, reasons in component_scores.values():
        all_reasons.extend(reasons)

    if not all_reasons:
        return "This session matches normal baseline behavior; no notable risk signals."

    risk_level = "high" if row["session_risk_score"] >= 70 else (
        "medium" if row["session_risk_score"] >= 35 else "low")

    duration = row["duration_minutes"]
    body = "; ".join(all_reasons[:5])
    return (
        f"This session is {risk_level} risk because it {body}, "
        f"within a {duration:.1f}-minute window ({row['num_events']} events)."
    )


def score_sessions_against_global_baseline(
    new_session_features_df: pd.DataFrame, baseline_model: Dict[str, Any]
) -> pd.DataFrame:
    """Score every session in new_session_features_df against baseline_model.

    Returns the input df with added score columns, a session_risk_score
    capped in [0, 100], and a risk_explanation column. Computation never
    references identity-specific history -- only the global baseline_model.
    """
    df = new_session_features_df.copy()

    rarity_scores, chain_scores, timing_scores, deviation_scores, sensitive_scores = [], [], [], [], []
    explanations = []

    for _, row in df.iterrows():
        rarity = _sequence_rarity_score(row, baseline_model)
        chain = _suspicious_chain_score(row)
        timing = _timing_burst_score(row, baseline_model)
        deviation = _feature_deviation_score(row, baseline_model)
        sensitive = _sensitive_action_score(row)

        total = rarity[0] + chain[0] + timing[0] + deviation[0] + sensitive[0]
        total = float(np.clip(total, 0.0, 100.0))

        rarity_scores.append(rarity[0])
        chain_scores.append(chain[0])
        timing_scores.append(timing[0])
        deviation_scores.append(deviation[0])
        sensitive_scores.append(sensitive[0])

        scored_row = row.copy()
        scored_row["session_risk_score"] = total
        explanations.append(generate_risk_explanation(scored_row, {
            "sequence_rarity": rarity, "suspicious_chain": chain,
            "timing_burst": timing, "feature_deviation": deviation,
            "sensitive_action": sensitive,
        }))

    df["sequence_rarity_score"] = rarity_scores
    df["suspicious_chain_score"] = chain_scores
    df["timing_burst_score"] = timing_scores
    df["feature_deviation_score"] = deviation_scores
    df["sensitive_action_score"] = sensitive_scores
    df["session_risk_score"] = (
        df["sequence_rarity_score"] + df["suspicious_chain_score"] + df["timing_burst_score"]
        + df["feature_deviation_score"] + df["sensitive_action_score"]
    ).clip(0, 100)
    df["risk_explanation"] = explanations

    return df.sort_values("session_risk_score", ascending=False).reset_index(drop=True)


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(1)
    sessions_path, model_path, out_parquet, out_csv = sys.argv[1:5]

    sessions = pd.read_parquet(sessions_path)
    with open(model_path) as f:
        model = json.load(f)

    scored = score_sessions_against_global_baseline(sessions, model)
    scored.to_parquet(out_parquet, index=False)

    top = scored.head(20)[[
        "session_id", "identity_id", "session_start", "session_end", "num_events",
        "duration_minutes", "session_risk_score", "sequence_rarity_score",
        "suspicious_chain_score", "timing_burst_score", "feature_deviation_score",
        "sensitive_action_score", "risk_explanation",
    ]]
    top.to_csv(out_csv, index=False)

    print(f"Scored {len(scored)} sessions -> {out_parquet}")
    print(f"Top risky sessions -> {out_csv}")


if __name__ == "__main__":
    main()
