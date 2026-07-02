"""Build a global (identity-agnostic) baseline model of normal session
behavior from baseline session features.

The model is explainable statistics, not ML:
  - action-category 2-gram / 3-gram frequencies
  - raw event-name 2-gram frequencies
  - category -> category transition probabilities
  - global distributions (mean/std/percentiles) for key numeric features
  - common normal patterns (most frequent category/event sequences)

Every session contributes equally regardless of identity_id -- the baseline
is deliberately not user-specific.

Usage:
    python3 train_global_session_baseline.py <baseline_session_features.parquet> <model.json>
"""
import json
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, List, Sequence

import numpy as np
import pandas as pd

NUMERIC_FEATURES = [
    "num_events", "duration_minutes", "events_per_minute", "unique_services",
    "num_getobject_events", "num_sensitive_actions", "failed_event_ratio",
    "max_events_in_5min",
]


def _ngrams(seq: Sequence[str], n: int) -> List[tuple]:
    if len(seq) < n:
        return []
    return [tuple(seq[i:i + n]) for i in range(len(seq) - n + 1)]


def _build_ngram_freqs(sequences: pd.Series, n: int, top_k: int = 200) -> Dict[str, float]:
    counter: Counter = Counter()
    for seq in sequences:
        counter.update(_ngrams(list(seq), n))
    total = sum(counter.values()) or 1
    most_common = counter.most_common(top_k)
    return {" -> ".join(k): v / total for k, v in most_common}


def _build_transition_probs(cat_sequences: pd.Series) -> Dict[str, Dict[str, float]]:
    counts: Dict[str, Counter] = defaultdict(Counter)
    for seq in cat_sequences:
        for a, b in zip(seq, seq[1:]):
            counts[a][b] += 1
    probs: Dict[str, Dict[str, float]] = {}
    for src, dest_counts in counts.items():
        total = sum(dest_counts.values())
        probs[src] = {dest: c / total for dest, c in dest_counts.items()}
    return probs


def _feature_distributions(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    dist: Dict[str, Dict[str, float]] = {}
    for col in NUMERIC_FEATURES:
        values = df[col].astype(float)
        dist[col] = {
            "mean": float(values.mean()),
            "std": float(values.std(ddof=0)) or 1e-6,
            "p50": float(values.quantile(0.50)),
            "p90": float(values.quantile(0.90)),
            "p95": float(values.quantile(0.95)),
            "p99": float(values.quantile(0.99)),
            "min": float(values.min()),
            "max": float(values.max()),
        }
    return dist


def _common_patterns(df: pd.DataFrame, top_k: int = 15) -> Dict[str, Any]:
    cat_seq_counts = Counter(tuple(s) for s in df["ordered_action_categories"])
    event_seq_counts = Counter(tuple(s) for s in df["ordered_event_sequence"])
    service_combo_counts = Counter(
        tuple(sorted(set(s))) for s in df["ordered_event_sequence"]
    )
    return {
        "frequent_category_sequences": [
            {"sequence": list(k), "count": v} for k, v in cat_seq_counts.most_common(top_k)
        ],
        "frequent_event_sequences": [
            {"sequence": list(k), "count": v} for k, v in event_seq_counts.most_common(top_k)
        ],
    }


def build_global_baseline_model(session_features_df: pd.DataFrame) -> Dict[str, Any]:
    """Construct the global baseline model dict, ready to json.dump.

    Deliberately ignores identity_id when computing frequencies/distributions
    -- every session contributes equally to the global model regardless of
    who produced it.
    """
    df = session_features_df

    model: Dict[str, Any] = {
        "num_baseline_sessions": int(len(df)),
        "category_2gram_freq": _build_ngram_freqs(df["ordered_action_categories"], 2),
        "category_3gram_freq": _build_ngram_freqs(df["ordered_action_categories"], 3),
        "event_2gram_freq": _build_ngram_freqs(df["ordered_event_sequence"], 2),
        "transition_probabilities": _build_transition_probs(df["ordered_action_categories"]),
        "feature_distributions": _feature_distributions(df),
        "common_patterns": _common_patterns(df),
    }
    return model


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    in_path, out_path = sys.argv[1], sys.argv[2]

    df = pd.read_parquet(in_path)
    model = build_global_baseline_model(df)

    with open(out_path, "w") as f:
        json.dump(model, f, indent=2)
    print(f"Built global baseline model from {len(df)} sessions -> {out_path}")


if __name__ == "__main__":
    main()
