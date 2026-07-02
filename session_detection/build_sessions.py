"""Group normalized events into short sessions and extract session-level
sequence/timing features.

Session definition: for each identity_id, sort events by event_time; start a
new session whenever the gap since the previous event for that identity
exceeds `gap_minutes` (default 30). identity_id is used ONLY for grouping
events into sessions and for reporting -- it is never used to decide whether
a session's chain of actions is normal. That judgment is made globally,
against the baseline model built across all identities.

Usage:
    python3 build_sessions.py <normalized_events.parquet> <session_features.parquet>
"""
import sys
from typing import Any, Dict, List

import numpy as np
import pandas as pd


def sessionize_events(df: pd.DataFrame, gap_minutes: int = 30) -> pd.DataFrame:
    """Assign a session_id to every event.

    Sessions are formed per identity_id with a `gap_minutes` inactivity
    cutoff. Returns a copy of df with a new `session_id` column.
    """
    if df.empty:
        out = df.copy()
        out["session_id"] = []
        return out

    df = df.sort_values(["identity_id", "event_time"]).copy()
    gap = pd.Timedelta(minutes=gap_minutes)

    time_diff = df.groupby("identity_id")["event_time"].diff()
    new_session = time_diff.isna() | (time_diff > gap)
    df["_session_seq"] = new_session.groupby(df["identity_id"]).cumsum()
    df["session_id"] = (
        df["identity_id"].astype(str) + "_s" + df["_session_seq"].astype(int).astype(str)
    )
    df = df.drop(columns=["_session_seq"])
    return df.sort_values("event_time").reset_index(drop=True)


def _max_events_in_5min(times: pd.Series) -> int:
    if len(times) <= 1:
        return len(times)
    times = times.sort_values().reset_index(drop=True)
    window = pd.Timedelta(minutes=5)
    max_count = 0
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        max_count = max(max_count, end - start + 1)
    return max_count


def _time_between_key_actions(g: pd.DataFrame) -> Dict[str, float]:
    """Minutes between the first Discovery action and the first
    PermissionChange / CredentialAccess / DataAccess action in the session,
    when both are present and in order."""
    out: Dict[str, float] = {}
    cats = g["action_category"]
    times = g["event_time"]

    def first_time(cat):
        mask = cats == cat
        return times[mask].min() if mask.any() else None

    disc_t = first_time("Discovery")
    for target, key in [
        ("PermissionChange", "minutes_discovery_to_permission_change"),
        ("CredentialAccess", "minutes_discovery_to_credential_access"),
        ("DataAccess", "minutes_discovery_to_data_access"),
    ]:
        target_t = first_time(target)
        if disc_t is not None and target_t is not None and target_t >= disc_t:
            out[key] = (target_t - disc_t).total_seconds() / 60.0
        else:
            out[key] = np.nan
    return out


def _session_row(session_id: str, g: pd.DataFrame) -> Dict[str, Any]:
    g = g.sort_values("event_time")
    start, end = g["event_time"].iloc[0], g["event_time"].iloc[-1]
    duration_minutes = max((end - start).total_seconds() / 60.0, 1e-6)
    num_events = len(g)

    event_seq = g["event_name"].tolist()
    cat_seq = g["action_category"].tolist()

    cat_counts = g["action_category"].value_counts()
    num_failed = int(g["is_failed"].sum())

    row = {
        "session_id": session_id,
        "identity_id": g["identity_id"].iloc[0],
        "session_start": start,
        "session_end": end,
        "duration_minutes": duration_minutes,
        "num_events": num_events,
        "events_per_minute": num_events / duration_minutes,
        "ordered_event_sequence": event_seq,
        "ordered_action_categories": cat_seq,
        "unique_services": g["event_source"].nunique(),
        "unique_regions": g["aws_region"].nunique(),
        "unique_source_ips": g["source_ip"].nunique(),
        "num_discovery_actions": int(cat_counts.get("Discovery", 0)),
        "num_data_access_actions": int(cat_counts.get("DataAccess", 0)),
        "num_permission_change_actions": int(cat_counts.get("PermissionChange", 0)),
        "num_credential_access_actions": int(cat_counts.get("CredentialAccess", 0)),
        "num_persistence_actions": int(cat_counts.get("Persistence", 0)),
        "num_defense_evasion_actions": int(cat_counts.get("DefenseEvasion", 0)),
        "num_failed_events": num_failed,
        "failed_event_ratio": num_failed / num_events,
        "num_getobject_events": int((g["event_name"] == "GetObject").sum()),
        "num_sensitive_actions": int(g["is_sensitive"].sum()),
        "max_events_in_5min": _max_events_in_5min(g["event_time"]),
    }
    row.update(_time_between_key_actions(g))
    return row


def extract_session_features(sessionized_df: pd.DataFrame) -> pd.DataFrame:
    """Compute one feature row per session_id from a sessionized event table."""
    if sessionized_df.empty:
        return pd.DataFrame()

    rows: List[Dict[str, Any]] = [
        _session_row(sid, g) for sid, g in sessionized_df.groupby("session_id", sort=False)
    ]
    feats = pd.DataFrame(rows).sort_values("session_start").reset_index(drop=True)
    return feats


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    in_path, out_path = sys.argv[1], sys.argv[2]

    events = pd.read_parquet(in_path)
    sessionized = sessionize_events(events, gap_minutes=30)
    features = extract_session_features(sessionized)
    features.to_parquet(out_path, index=False)
    print(f"Built {len(features)} sessions from {len(events)} events -> {out_path}")


if __name__ == "__main__":
    main()
