
#!/usr/bin/env python3
"""
Low-and-slow exfiltration detector for OCSF-normalized AWS logs.

Supports:
  - JSONL: one JSON event per line
  - JSON: a list of JSON events
  - CSV: already-flattened OCSF fields
  - Multiple input files, folders, or shell globs

Examples:
  python detect_low_slow_exfil.py --input ocsf_logs.jsonl --output alerts.csv

  python detect_low_slow_exfil.py \
    --input logs/cloudtrail.jsonl logs/s3_access.jsonl logs/vpc_flow.jsonl \
    --output alerts.csv

  python detect_low_slow_exfil.py --input "logs/*.jsonl" --output alerts.csv

Optional:
  python detect_low_slow_exfil.py --input ocsf_logs.jsonl --baseline-end 2026-06-15T00:00:00Z44

Output scoring:
  - network_risk_score: repeated small network egress / destination-based behavior
  - time_based_risk_score: sustained elevation, ramp-up, periodic spikes, cumulative excess
  - combined_risk_score: max(network_risk_score, time_based_risk_score)
  - risk_score: backwards-compatible alias of combined_risk_score
  
  python .\detect_low_slow_exfil_v2.py --input .\logs\realistic_attack_logs\ocsf_out\ --baseline-end 2018-08-20T10:40:00Z --output .\alerts.csv
  python .\detect_low_slow_exfil_v2.py --input .\logs\realistic_attack_logs\bots_like_low_slow_ocsf\plain_like_bots_no_actor_in_vpcflow\ --baseline-end 2018-08-20T10:40:00Z --output .\alerts.csv
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd


# -----------------------------
# Tuning knobs
# -----------------------------

SMALL_TRANSFER_BYTES = 20 * 1024 * 1024       # <= 20 MB is considered "small"
MIN_TOTAL_BYTES_OUT = 100 * 1024 * 1024       # total over observation period
MIN_EVENT_COUNT = 20
MIN_DURATION_HOURS = 6
MIN_SMALL_TRANSFER_RATIO = 0.80
REGULAR_INTERVAL_CV = 0.25                    # lower = more regular
JITTERED_INTERVAL_CV = 0.35
INTERVAL_BAND_TOLERANCE = 0.35
MIN_INTERVAL_BAND_RATIO = 0.80
ALERT_SCORE_THRESHOLD = 60
MAX_NETWORK_RAW_SCORE = 170
MAX_TIME_BASED_RAW_SCORE = 155

# Time-based S3/data-access analytics.
SUSTAINED_RATIO_THRESHOLD = 2.5              # Mallory-style steady elevation
SUSTAINED_MIN_DAYS = 7                       # elevated days in current window
RAMP_FINAL_RATIO_THRESHOLD = 3.0             # Neil-style final ratio
RAMP_MIN_DAYS = 7
RAMP_MIN_SLOPE_PER_DAY = 0.12                # ratio increase per day
PERIODIC_SPIKE_RATIO_THRESHOLD = 4.0         # Petra-style spike days
PERIODIC_SPIKE_MIN_DAYS = 4
CUMULATIVE_EXCESS_RATIO_THRESHOLD = 2.0
CUMULATIVE_EXCESS_MIN_BYTES = 100 * 1024 * 1024


def normalize_score(raw_score: float, max_score: float) -> float:
    if max_score <= 0:
        return 0.0
    return round(min(max(float(raw_score), 0.0), max_score) / max_score * 100.0, 2)


def interval_median_band_ratio(values: pd.Series) -> float:
    median = values.median()
    if pd.isna(median) or median <= 0:
        return np.nan
    lower = median * (1 - INTERVAL_BAND_TOLERANCE)
    upper = median * (1 + INTERVAL_BAND_TOLERANCE)
    return float(values.between(lower, upper, inclusive="both").mean())



# -----------------------------
# OCSF field candidates
# -----------------------------

FIELD_CANDIDATES = {
    "log_source": [
        "log_source",
        "metadata.log_name",
        "metadata.product.name",
        "metadata.product.feature.name",
        "metadata.source",
        "class_name",
    ],
    "time": [
        "time",
        "start_time",
        "event_time",
        "metadata.event_time",
    ],
    "account": [
        "cloud.account.uid",
        "cloud.account.account_id",
        "cloud.account.name",
    ],
    "principal": [
        "actor.user.uid",
        "actor.user.name",
        "actor.session.uid",
        "actor.user.account.uid",
        "user.uid",
        "user.name",
    ],
    "src_ip": [
        "src_endpoint.ip",
        "src_endpoint.ip_addr",
        # Keep endpoint UID out of src_ip when possible; use src_uid/interface_uid fallbacks below instead.
    ],
    "src_uid": [
        "src_endpoint.uid",
        "src_endpoint.instance_uid",
        "src_endpoint.instance.uid",
        "src_endpoint.hostname",
        "src_endpoint.name",
    ],
    "interface_uid": [
        "src_endpoint.interface_uid",
        "network_interface.uid",
        "network_interface.interface_uid",
        "interface.uid",
        "interface_uid",
    ],
    "dst_ip": [
        "dst_endpoint.ip",
        "dst_endpoint.ip_addr",
    ],
    "dst_port": [
        "dst_endpoint.port",
        "dst_port",
        "network.dst_port",
    ],
    "protocol": [
        "connection_info.protocol_name",
        "protocol_name",
        "network.protocol",
        "traffic.protocol_name",
    ],
    "dst_domain": [
        "dst_endpoint.domain",
        "dst_endpoint.hostname",
        "dst_endpoint.name",
        "url.domain",
        "http_request.url.hostname",
    ],
    "bytes_out": [
        "traffic.bytes_out",
        "traffic.bytes",
        "bytes_out",
        "network.bytes_out",
    ],
    "bytes_in": [
        "traffic.bytes_in",
        "bytes_in",
        "network.bytes_in",
    ],
    "api_operation": [
        "api.operation",
        "api.operation_name",
        "activity_name",
        "operation",
    ],
    "api_service": [
        "api.service.name",
        "cloud.service.name",
        "service.name",
    ],
    "user_agent": [
        "http_request.user_agent",
        "user_agent",
        "src_endpoint.user_agent",
    ],
    "resource": [
        "resources.0.name",
        "resource.name",
        "object.name",
        "bucket.name",
    ],
}


# -----------------------------
# Loading
# -----------------------------

SUPPORTED_SUFFIXES = {".jsonl", ".ndjson", ".json", ".csv"}


def infer_log_source(path: Path) -> str:
    """Best-effort source label from filename when OCSF metadata is absent."""
    name = path.name.lower()
    if "cloudtrail" in name:
        return "cloudtrail"
    if "vpc" in name and "flow" in name:
        return "vpc_flow"
    if "s3" in name and ("access" in name or "server" in name):
        return "s3_access"
    if "s3" in name:
        return "s3"
    return path.stem


def expand_sources(inputs: Sequence[str]) -> list[Path]:
    """Accept files, folders, and shell globs; return supported files."""
    files: list[Path] = []

    for item in inputs:
        # Support quoted globs like --input "logs/*.jsonl".
        matches = [Path(m) for m in glob.glob(item)]
        candidates = matches if matches else [Path(item)]

        for candidate in candidates:
            if candidate.is_dir():
                for suffix in SUPPORTED_SUFFIXES:
                    files.extend(candidate.rglob(f"*{suffix}"))
            elif candidate.is_file():
                files.append(candidate)
            else:
                raise FileNotFoundError(f"Input path not found: {candidate}")

    # Dedupe while preserving deterministic order.
    unique = sorted({p.resolve() for p in files})
    supported = [p for p in unique if p.suffix.lower() in SUPPORTED_SUFFIXES]

    if not supported:
        raise ValueError("No supported input files found. Use .jsonl, .ndjson, .json, or .csv")

    return supported


def load_many_events(sources: Sequence[str]) -> pd.DataFrame:
    frames = []
    for path in expand_sources(sources):
        frame = load_events(path)
        frame["input_file"] = str(path)
        if "log_source" not in frame.columns:
            frame["log_source"] = infer_log_source(path)
        frames.append(frame)

    return pd.concat(frames, ignore_index=True, sort=False)


def load_events(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".csv":
        return pd.read_csv(path)

    if suffix in {".jsonl", ".ndjson"}:
        rows: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON on line {line_no}: {exc}") from exc
        return pd.json_normalize(rows, sep=".")

    if suffix == ".json":
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            # Common patterns: {"events": [...]} or {"data": [...]}
            for key in ["events", "data", "records", "Records"]:
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break

        if not isinstance(data, list):
            raise ValueError("JSON input must be a list of events, or a dict containing an events/data/records list.")

        return pd.json_normalize(data, sep=".")

    raise ValueError(f"Unsupported file type: {suffix}. Use .jsonl, .ndjson, .json, or .csv")


# -----------------------------
# Normalization helpers
# -----------------------------

def first_existing_column(df: pd.DataFrame, candidates: Iterable[str]) -> str | None:
    for col in candidates:
        if col in df.columns:
            return col
    return None


def make_series(df: pd.DataFrame, candidates: Iterable[str], default: Any = np.nan) -> pd.Series:
    col = first_existing_column(df, candidates)
    if col is None:
        return pd.Series([default] * len(df), index=df.index)
    return df[col]


def coalesce_columns(df: pd.DataFrame, candidates: Iterable[str], default: Any = "unknown") -> pd.Series:
    out = pd.Series([np.nan] * len(df), index=df.index)

    for col in candidates:
        if col in df.columns:
            out = out.combine_first(df[col])

    return out.fillna(default)


def parse_event_time(series: pd.Series) -> pd.Series:
    """
    Parse OCSF time fields safely.

    Real OCSF/AWS-normalized logs often store time as epoch milliseconds
    such as 1534755721000. Pandas would interpret bare integers as
    nanoseconds if no unit is supplied, which incorrectly turns 2018 events
    into 1970 events.
    """
    numeric = pd.to_numeric(series, errors="coerce")
    parsed = pd.Series(pd.NaT, index=series.index, dtype="datetime64[ns, UTC]")

    numeric_mask = numeric.notna()
    if numeric_mask.any():
        abs_numeric = numeric[numeric_mask].abs()
        median_value = abs_numeric.median()

        if median_value >= 1e14:
            unit = "us"      # epoch microseconds
        elif median_value >= 1e11:
            unit = "ms"      # epoch milliseconds
        else:
            unit = "s"       # epoch seconds

        parsed.loc[numeric_mask] = pd.to_datetime(
            numeric.loc[numeric_mask],
            unit=unit,
            utc=True,
            errors="coerce",
        )

    text_mask = ~numeric_mask
    if text_mask.any():
        parsed.loc[text_mask] = pd.to_datetime(
            series.loc[text_mask],
            utc=True,
            errors="coerce",
        )

    return parsed


def is_meaningful(value: Any) -> bool:
    if value is None:
        return False
    if pd.isna(value):
        return False
    text = str(value).strip()
    if not text:
        return False
    return text.lower() not in {
        "unknown",
        "unknown_account",
        "unknown_principal",
        "unknown_src",
        "unknown_src_uid",
        "unknown_interface",
        "unknown_destination",
        "nan",
        "none",
        "null",
    }


def build_detection_entity(row: pd.Series) -> tuple[str, str]:
    """
    Choose the best available entity for grouping.

    Priority:
      1. AWS account + IAM principal/session
      2. IAM principal/session only
      3. AWS account + source endpoint/ENI/IP
      4. Source endpoint/ENI/IP only
      5. Unknown entity
    """
    account = str(row.get("cloud_account", "unknown_account"))
    principal = str(row.get("principal", "unknown_principal"))
    src_ip = str(row.get("src_ip", "unknown_src"))
    src_uid = str(row.get("src_uid", "unknown_src_uid"))
    interface_uid = str(row.get("interface_uid", "unknown_interface"))

    has_account = is_meaningful(account)
    has_principal = is_meaningful(principal)
    has_src_uid = is_meaningful(src_uid)
    has_interface = is_meaningful(interface_uid)
    has_src_ip = is_meaningful(src_ip)

    if has_account and has_principal:
        return f"principal:{account}:{principal}", "principal"
    if has_principal:
        return f"principal:unknown_account:{principal}", "principal"

    if has_account and has_src_uid:
        return f"endpoint:{account}:{src_uid}", "endpoint"
    if has_account and has_interface:
        return f"interface:{account}:{interface_uid}", "interface"
    if has_account and has_src_ip:
        return f"host:{account}:{src_ip}", "host"

    if has_src_uid:
        return f"endpoint:unknown_account:{src_uid}", "endpoint"
    if has_interface:
        return f"interface:unknown_account:{interface_uid}", "interface"
    if has_src_ip:
        return f"host:unknown_account:{src_ip}", "host"

    return "unknown_entity", "unknown"


def extract_resource_from_raw(row: pd.Series) -> str:
    """
    Handles cases where the original OCSF 'resources' field stayed as a list
    instead of being flattened into resources.0.name.
    """
    existing = row.get("resource")
    if pd.notna(existing) and str(existing).strip():
        return str(existing)

    resources = row.get("resources")
    if isinstance(resources, list) and resources:
        names = []
        for item in resources:
            if isinstance(item, dict):
                value = item.get("name") or item.get("uid") or item.get("type")
                if value:
                    names.append(str(value))
        if names:
            return "|".join(names)

    return "unknown"


def normalize_ocsf(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    out["log_source"] = coalesce_columns(out, FIELD_CANDIDATES["log_source"], default="unknown_source")

    out["event_time"] = make_series(out, FIELD_CANDIDATES["time"])
    out["event_time"] = parse_event_time(out["event_time"])
    out = out.dropna(subset=["event_time"])

    out["cloud_account"] = coalesce_columns(out, FIELD_CANDIDATES["account"], default="unknown_account")
    out["principal"] = coalesce_columns(out, FIELD_CANDIDATES["principal"], default="unknown_principal")

    out["src_ip"] = coalesce_columns(out, FIELD_CANDIDATES["src_ip"], default="unknown_src")
    out["src_uid"] = coalesce_columns(out, FIELD_CANDIDATES["src_uid"], default="unknown_src_uid")
    out["interface_uid"] = coalesce_columns(out, FIELD_CANDIDATES["interface_uid"], default="unknown_interface")

    out["dst_ip"] = coalesce_columns(out, FIELD_CANDIDATES["dst_ip"], default=np.nan)
    out["dst_domain"] = coalesce_columns(out, FIELD_CANDIDATES["dst_domain"], default=np.nan)
    out["dst_port"] = coalesce_columns(out, FIELD_CANDIDATES["dst_port"], default=np.nan)
    out["protocol"] = coalesce_columns(out, FIELD_CANDIDATES["protocol"], default=np.nan)

    # Prefer domain when present; fall back to IP. Include port when available so
    # repeated traffic to the same IP on different services does not collapse together.
    out["destination"] = out["dst_domain"].combine_first(out["dst_ip"]).fillna("unknown_destination")
    has_port = out["dst_port"].apply(is_meaningful)
    out.loc[has_port, "destination"] = (
        out.loc[has_port, "destination"].astype(str)
        + ":"
        + out.loc[has_port, "dst_port"].astype(str)
    )

    out["bytes_out"] = pd.to_numeric(
        make_series(out, FIELD_CANDIDATES["bytes_out"], default=0),
        errors="coerce",
    ).fillna(0)

    out["bytes_in"] = pd.to_numeric(
        make_series(out, FIELD_CANDIDATES["bytes_in"], default=0),
        errors="coerce",
    ).fillna(0)

    out["api_operation"] = coalesce_columns(out, FIELD_CANDIDATES["api_operation"], default="unknown_operation")
    out["api_service"] = coalesce_columns(out, FIELD_CANDIDATES["api_service"], default="unknown_service")
    out["user_agent"] = coalesce_columns(out, FIELD_CANDIDATES["user_agent"], default="unknown_user_agent")

    out["resource"] = coalesce_columns(out, FIELD_CANDIDATES["resource"], default=np.nan)
    out["resource"] = out.apply(extract_resource_from_raw, axis=1)

    # Entity key for alert grouping. This now works even when username/cloud account
    # are missing, which is common for VPC Flow records.
    entity_parts = out.apply(build_detection_entity, axis=1)
    out["entity_key"] = [item[0] for item in entity_parts]
    out["entity_type"] = [item[1] for item in entity_parts]

    out = out.sort_values("event_time").reset_index(drop=True)
    return out

# -----------------------------
# Feature engineering
# -----------------------------

def split_baseline_current(
    df: pd.DataFrame,
    baseline_end: str | None = None,
    current_days: int | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    If baseline_end is provided:
      baseline = events before baseline_end
      current = events at/after baseline_end

    Else if current_days is provided:
      current = last N days
      baseline = everything before that

    Else:
      use the full dataset for scoring, and use the first 70% of time as baseline.
    """
    df = df.sort_values("event_time").copy()

    if df.empty:
        return df.copy(), df.copy()

    if baseline_end:
        cutoff = pd.to_datetime(baseline_end, utc=True)
        baseline = df[df["event_time"] < cutoff].copy()
        current = df[df["event_time"] >= cutoff].copy()
        return baseline, current

    if current_days:
        cutoff = df["event_time"].max() - pd.Timedelta(days=current_days)
        baseline = df[df["event_time"] < cutoff].copy()
        current = df[df["event_time"] >= cutoff].copy()
        return baseline, current

    min_t = df["event_time"].min()
    max_t = df["event_time"].max()
    cutoff = min_t + (max_t - min_t) * 0.70

    baseline = df[df["event_time"] < cutoff].copy()
    current = df[df["event_time"] >= cutoff].copy()

    # If the dataset is tiny, avoid empty current.
    if current.empty:
        current = df.copy()

    return baseline, current


def build_baseline_profiles(baseline: pd.DataFrame) -> dict[str, Any]:
    """
    Returns known destinations/resources/user agents and per-entity baseline p95s.
    """
    profiles: dict[str, Any] = {}

    if baseline.empty:
        profiles["known_destinations"] = {}
        profiles["known_user_agents"] = {}
        profiles["known_resources"] = {}
        profiles["entity_p95_total_bytes"] = {}
        profiles["entity_p95_event_count"] = {}
        return profiles

    profiles["known_destinations"] = (
        baseline.groupby("entity_key")["destination"]
        .apply(lambda x: set(x.dropna().astype(str)))
        .to_dict()
    )

    profiles["known_user_agents"] = (
        baseline.groupby("entity_key")["user_agent"]
        .apply(lambda x: set(x.dropna().astype(str)))
        .to_dict()
    )

    profiles["known_resources"] = (
        baseline.groupby("entity_key")["resource"]
        .apply(lambda x: set(x.dropna().astype(str)))
        .to_dict()
    )

    # Daily entity baseline for basic anomaly comparison.
    daily = (
        baseline.set_index("event_time")
        .groupby(["entity_key", pd.Grouper(freq="1D")])
        .agg(
            daily_bytes_out=("bytes_out", "sum"),
            daily_event_count=("bytes_out", "count"),
        )
        .reset_index()
    )

    profiles["entity_p95_total_bytes"] = (
        daily.groupby("entity_key")["daily_bytes_out"]
        .quantile(0.95)
        .to_dict()
    )

    profiles["entity_p95_event_count"] = (
        daily.groupby("entity_key")["daily_event_count"]
        .quantile(0.95)
        .to_dict()
    )

    return profiles


def add_rarity_flags(current: pd.DataFrame, profiles: dict[str, Any]) -> pd.DataFrame:
    out = current.copy()

    known_destinations = profiles.get("known_destinations", {})
    known_user_agents = profiles.get("known_user_agents", {})
    known_resources = profiles.get("known_resources", {})

    out["rare_destination"] = out.apply(
        lambda r: str(r["destination"]) not in known_destinations.get(r["entity_key"], set()),
        axis=1,
    )

    out["rare_user_agent"] = out.apply(
        lambda r: str(r["user_agent"]) not in known_user_agents.get(r["entity_key"], set()),
        axis=1,
    )

    out["rare_resource"] = out.apply(
        lambda r: str(r["resource"]) not in known_resources.get(r["entity_key"], set()),
        axis=1,
    )

    return out


def network_features(current: pd.DataFrame) -> pd.DataFrame:
    net = current[current["bytes_out"] > 0].copy()

    if net.empty:
        return pd.DataFrame()

    net["is_small_transfer"] = net["bytes_out"] <= SMALL_TRANSFER_BYTES

    group_cols = [
        "cloud_account",
        "principal",
        "entity_key",
        "entity_type",
        "src_ip",
        "src_uid",
        "interface_uid",
        "destination",
    ]

    features = (
        net.groupby(group_cols)
        .agg(
            first_seen=("event_time", "min"),
            last_seen=("event_time", "max"),
            total_bytes_out=("bytes_out", "sum"),
            total_bytes_in=("bytes_in", "sum"),
            event_count=("bytes_out", "count"),
            avg_bytes_out=("bytes_out", "mean"),
            median_bytes_out=("bytes_out", "median"),
            max_bytes_out=("bytes_out", "max"),
            small_transfer_count=("is_small_transfer", "sum"),
            rare_destination_event_count=("rare_destination", "sum"),
            rare_user_agent_event_count=("rare_user_agent", "sum"),
            distinct_user_agents=("user_agent", "nunique"),
            log_sources=("log_source", lambda x: "|".join(sorted(set(x.dropna().astype(str))))),
        )
        .reset_index()
    )

    features["duration_hours"] = (
        features["last_seen"] - features["first_seen"]
    ).dt.total_seconds() / 3600

    features["small_transfer_ratio"] = (
        features["small_transfer_count"] / features["event_count"]
    ).fillna(0)

    features["rare_destination_ratio"] = (
        features["rare_destination_event_count"] / features["event_count"]
    ).fillna(0)

    features["rare_user_agent_ratio"] = (
        features["rare_user_agent_event_count"] / features["event_count"]
    ).fillna(0)

    return features


def timing_features(current: pd.DataFrame) -> pd.DataFrame:
    net = current[current["bytes_out"] > 0].copy()
    if net.empty:
        return pd.DataFrame()

    group_cols = [
        "cloud_account",
        "principal",
        "entity_key",
        "entity_type",
        "src_ip",
        "src_uid",
        "interface_uid",
        "destination",
    ]

    net = net.sort_values(group_cols + ["event_time"])
    net["previous_time"] = net.groupby(group_cols)["event_time"].shift(1)
    net["delta_seconds"] = (net["event_time"] - net["previous_time"]).dt.total_seconds()

    deltas = net.dropna(subset=["delta_seconds"])
    if deltas.empty:
        return pd.DataFrame()

    features = (
        deltas.groupby(group_cols)
        .agg(
            mean_interval_seconds=("delta_seconds", "mean"),
            std_interval_seconds=("delta_seconds", "std"),
            median_interval_seconds=("delta_seconds", "median"),
            min_interval_seconds=("delta_seconds", "min"),
            max_interval_seconds=("delta_seconds", "max"),
            interval_count=("delta_seconds", "count"),
            interval_median_band_ratio=("delta_seconds", interval_median_band_ratio),
        )
        .reset_index()
    )

    features["interval_cv"] = (
        features["std_interval_seconds"] / features["mean_interval_seconds"]
    ).replace([np.inf, -np.inf], np.nan)

    features["interval_band_tolerance"] = INTERVAL_BAND_TOLERANCE

    return features


def s3_features(current: pd.DataFrame) -> pd.DataFrame:
    """
    S3-like object access features. This depends on how your normalized OCSF data
    represents CloudTrail data events.
    """
    operations = current["api_operation"].astype(str).str.lower()
    services = current["api_service"].astype(str).str.lower()

    s3_like = current[
        services.str.contains("s3", na=False)
        | operations.isin(["getobject", "listbucket", "get object", "list bucket", "rest.get.object", "rest.get.bucket"])
        | operations.str.contains("getobject|listbucket|get.object|get.bucket|rest.get", na=False)
    ].copy()

    if s3_like.empty:
        return pd.DataFrame(columns=[
            "cloud_account",
            "principal",
            "entity_key",
            "s3_event_count",
            "get_object_count",
            "list_bucket_count",
            "distinct_resources",
            "rare_resource_event_count",
            "first_s3_seen",
            "last_s3_seen",
        ])

    s3_like["op_lower"] = s3_like["api_operation"].astype(str).str.lower()

    features = (
        s3_like.groupby(["cloud_account", "principal", "entity_key"])
        .agg(
            first_s3_seen=("event_time", "min"),
            last_s3_seen=("event_time", "max"),
            s3_event_count=("api_operation", "count"),
            get_object_count=("op_lower", lambda x: x.str.contains("getobject|get object|get.object|rest.get.object", na=False).sum()),
            list_bucket_count=("op_lower", lambda x: x.str.contains("listbucket|list bucket|get.bucket|rest.get.bucket", na=False).sum()),
            distinct_resources=("resource", "nunique"),
            rare_resource_event_count=("rare_resource", "sum"),
            s3_log_sources=("log_source", lambda x: "|".join(sorted(set(x.dropna().astype(str))))),
        )
        .reset_index()
    )

    features["s3_duration_hours"] = (
        features["last_s3_seen"] - features["first_s3_seen"]
    ).dt.total_seconds() / 3600

    return features



# -----------------------------
# Time-based S3/data-access analytics
# -----------------------------

def s3_read_mask(df: pd.DataFrame) -> pd.Series:
    """
    Identify S3 read-style events for time-based data-access analytics.

    This intentionally focuses on read/download style operations because the
    Mallory/Neil/Petra scenarios are about gradual data access/exfil volume,
    not necessarily a new destination or a suspicious session sequence.
    """
    if df.empty:
        return pd.Series([], dtype=bool, index=df.index)

    operations = df["api_operation"].astype(str).str.lower()
    services = df["api_service"].astype(str).str.lower()
    log_sources = df["log_source"].astype(str).str.lower()

    op_is_read = (
        operations.str.contains("getobject|get object|get.object|rest.get.object", na=False)
        | operations.str.contains("download|read", na=False)
    )

    source_is_s3 = (
        services.str.contains("s3", na=False)
        | log_sources.str.contains("s3", na=False)
    )

    return source_is_s3 & op_is_read


def add_access_volume_column(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create a data_access_bytes field.

    Different OCSF mappings use traffic.bytes, traffic.bytes_out, or
    traffic.bytes_in differently. For S3 read events, use the larger of
    bytes_out and bytes_in as the observed data-access volume.
    """
    out = df.copy()
    bytes_out = pd.to_numeric(out.get("bytes_out", 0), errors="coerce").fillna(0).clip(lower=0)
    bytes_in = pd.to_numeric(out.get("bytes_in", 0), errors="coerce").fillna(0).clip(lower=0)
    out["data_access_bytes"] = np.maximum(bytes_out, bytes_in)
    return out


def daily_s3_read_aggregation(events: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate S3 read activity into daily buckets.

    Output rows represent:
      principal/entity + day -> daily bytes/read count/resource breadth

    This is the core representation needed for time-based analytics:
      - sustained elevation
      - ramping increase
      - periodic spikes
      - cumulative excess
    """
    if events.empty:
        return pd.DataFrame()

    s3_reads = events[s3_read_mask(events)].copy()
    if s3_reads.empty:
        return pd.DataFrame()

    s3_reads = add_access_volume_column(s3_reads)
    s3_reads["access_day"] = s3_reads["event_time"].dt.floor("D")

    if "rare_resource" not in s3_reads.columns:
        s3_reads["rare_resource"] = False

    group_cols = [
        "cloud_account",
        "principal",
        "entity_key",
        "entity_type",
        "access_day",
    ]

    daily = (
        s3_reads.groupby(group_cols)
        .agg(
            first_seen=("event_time", "min"),
            last_seen=("event_time", "max"),
            daily_s3_read_bytes=("data_access_bytes", "sum"),
            daily_s3_read_events=("api_operation", "count"),
            daily_distinct_resources=("resource", "nunique"),
            daily_rare_resource_events=("rare_resource", "sum"),
            log_sources=("log_source", lambda x: "|".join(sorted(set(x.dropna().astype(str))))),
        )
        .reset_index()
    )

    return daily


def build_time_baseline_profiles(baseline: pd.DataFrame) -> pd.DataFrame:
    """
    Build per-entity baseline profiles from clean baseline days.

    Uses daily S3 read bytes and daily read-event counts. Event counts are kept
    because some datasets do not populate byte fields reliably.
    """
    base_daily = daily_s3_read_aggregation(baseline)
    if base_daily.empty:
        return pd.DataFrame()

    group_cols = ["cloud_account", "principal", "entity_key", "entity_type"]

    profiles = (
        base_daily.groupby(group_cols)
        .agg(
            baseline_days=("access_day", "nunique"),
            baseline_avg_daily_bytes=("daily_s3_read_bytes", "mean"),
            baseline_p95_daily_bytes=("daily_s3_read_bytes", lambda x: x.quantile(0.95)),
            baseline_std_daily_bytes=("daily_s3_read_bytes", "std"),
            baseline_avg_daily_events=("daily_s3_read_events", "mean"),
            baseline_p95_daily_events=("daily_s3_read_events", lambda x: x.quantile(0.95)),
            baseline_total_bytes=("daily_s3_read_bytes", "sum"),
            baseline_total_events=("daily_s3_read_events", "sum"),
        )
        .reset_index()
    )

    profiles["baseline_std_daily_bytes"] = profiles["baseline_std_daily_bytes"].fillna(0)
    return profiles


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator is None or pd.isna(denominator) or denominator <= 0:
        return np.nan
    return float(numerator) / float(denominator)


def _trend_slope(days: pd.Series, ratios: pd.Series) -> float:
    """
    Return a simple linear trend slope of ratio per day.
    """
    if len(days) < 2:
        return 0.0

    x = (days - days.min()).dt.days.astype(float).to_numpy()
    y = pd.to_numeric(ratios, errors="coerce").fillna(0).astype(float).to_numpy()

    if len(set(x)) < 2:
        return 0.0

    try:
        return float(np.polyfit(x, y, 1)[0])
    except Exception:
        return 0.0


def _json_safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or pd.isna(value):
            return default
        return float(value)
    except Exception:
        return default


def time_based_s3_volume_features(
    baseline: pd.DataFrame,
    current: pd.DataFrame,
) -> pd.DataFrame:
    """
    Create one time-based feature row per entity.

    Designed to catch:
      - Mallory: sustained 2.5x-3x elevation across many days
      - Neil: gradual ramp from lower ratio to higher ratio
      - Petra: repeated spike days with normal days in between
      - Cumulative excess: total incident access far above expected baseline
    """
    profiles = build_time_baseline_profiles(baseline)
    current_daily = daily_s3_read_aggregation(current)

    if profiles.empty or current_daily.empty:
        return pd.DataFrame()

    group_cols = ["cloud_account", "principal", "entity_key", "entity_type"]

    daily = current_daily.merge(profiles, on=group_cols, how="left")
    daily = daily[daily["baseline_days"].fillna(0) > 0].copy()

    if daily.empty:
        return pd.DataFrame()

    daily["bytes_ratio"] = daily.apply(
        lambda r: _safe_ratio(r["daily_s3_read_bytes"], r["baseline_avg_daily_bytes"]),
        axis=1,
    )

    daily["event_ratio"] = daily.apply(
        lambda r: _safe_ratio(r["daily_s3_read_events"], r["baseline_avg_daily_events"]),
        axis=1,
    )

    # Use whichever signal is available/stronger. Bytes are preferred when present,
    # but event-count ratios keep the detector useful when byte fields are zero.
    daily["activity_ratio"] = daily[["bytes_ratio", "event_ratio"]].max(axis=1, skipna=True)

    rows: list[dict[str, Any]] = []

    for keys, group in daily.groupby(group_cols):
        cloud_account, principal, entity_key, entity_type = keys
        g = group.sort_values("access_day").copy()

        current_days = int(g["access_day"].nunique())
        if current_days == 0:
            continue

        ratios = pd.to_numeric(g["activity_ratio"], errors="coerce").fillna(0)
        bytes_ratios = pd.to_numeric(g["bytes_ratio"], errors="coerce")
        event_ratios = pd.to_numeric(g["event_ratio"], errors="coerce")

        elevated_days = int((ratios >= SUSTAINED_RATIO_THRESHOLD).sum())
        spike_days = int((ratios >= PERIODIC_SPIKE_RATIO_THRESHOLD).sum())

        first_seen = g["first_seen"].min()
        last_seen = g["last_seen"].max()
        duration_days = max(1, (last_seen.floor("D") - first_seen.floor("D")).days + 1)

        early3_avg_ratio = float(ratios.head(3).mean()) if len(ratios) else 0.0
        final3_avg_ratio = float(ratios.tail(3).mean()) if len(ratios) else 0.0
        avg_activity_ratio = float(ratios.mean()) if len(ratios) else 0.0
        max_activity_ratio = float(ratios.max()) if len(ratios) else 0.0
        trend_slope = _trend_slope(g["access_day"], ratios)

        baseline_avg_daily_bytes = float(g["baseline_avg_daily_bytes"].iloc[0] or 0)
        expected_current_bytes = baseline_avg_daily_bytes * current_days
        total_current_bytes = float(g["daily_s3_read_bytes"].sum())
        cumulative_excess_bytes = total_current_bytes - expected_current_bytes
        cumulative_ratio = _safe_ratio(total_current_bytes, expected_current_bytes)

        baseline_avg_daily_events = float(g["baseline_avg_daily_events"].iloc[0] or 0)
        expected_current_events = baseline_avg_daily_events * current_days
        total_current_events = int(g["daily_s3_read_events"].sum())
        cumulative_event_ratio = _safe_ratio(total_current_events, expected_current_events)

        day_rows: list[dict[str, Any]] = []
        for _, day_row in g.iterrows():
            activity_ratio = _json_safe_float(day_row.get("activity_ratio"))
            day_flags: list[str] = []
            if activity_ratio >= SUSTAINED_RATIO_THRESHOLD:
                day_flags.append("elevated")
            if activity_ratio >= PERIODIC_SPIKE_RATIO_THRESHOLD:
                day_flags.append("spike")
            if int(day_row.get("daily_rare_resource_events", 0) or 0) > 0:
                day_flags.append("rare_resources")

            daily_bytes = _json_safe_float(day_row.get("daily_s3_read_bytes"))
            daily_events = int(day_row.get("daily_s3_read_events", 0) or 0)
            day_rows.append({
                "date": pd.Timestamp(day_row["access_day"]).strftime("%Y-%m-%d"),
                "activity_ratio": round(activity_ratio, 2),
                "bytes_ratio": round(_json_safe_float(day_row.get("bytes_ratio")), 2),
                "event_ratio": round(_json_safe_float(day_row.get("event_ratio")), 2),
                "bytes": int(daily_bytes),
                "expected_bytes": int(baseline_avg_daily_bytes),
                "excess_bytes": int(max(0, daily_bytes - baseline_avg_daily_bytes)),
                "events": daily_events,
                "expected_events": round(baseline_avg_daily_events, 2),
                "distinct_resources": int(day_row.get("daily_distinct_resources", 0) or 0),
                "rare_resource_events": int(day_row.get("daily_rare_resource_events", 0) or 0),
                "flags": day_flags,
            })

        elevated_day_rows = [d for d in day_rows if "elevated" in d["flags"]]
        spike_day_rows = [d for d in day_rows if "spike" in d["flags"]]
        final_window_rows = day_rows[-3:]
        top_activity_rows = sorted(day_rows, key=lambda d: d["activity_ratio"], reverse=True)[:5]

        contributing_dates = {
            d["date"]
            for d in elevated_day_rows
            + spike_day_rows
            + ([d for d in final_window_rows if final3_avg_ratio >= RAMP_FINAL_RATIO_THRESHOLD])
            + top_activity_rows[:3]
        }
        contributing_day_rows = [d for d in day_rows if d["date"] in contributing_dates]

        evidence_bits: list[str] = []
        if elevated_day_rows:
            evidence_bits.append(
                f"{len(elevated_day_rows)} elevated day(s): "
                f"{', '.join(d['date'] for d in elevated_day_rows[:8])}"
            )
        if spike_day_rows:
            evidence_bits.append(
                f"{len(spike_day_rows)} spike day(s): "
                f"{', '.join(d['date'] for d in spike_day_rows[:8])}"
            )
        if final3_avg_ratio >= RAMP_FINAL_RATIO_THRESHOLD:
            evidence_bits.append(
                "final 3-day window stayed high: "
                f"{', '.join(d['date'] for d in final_window_rows)}"
            )
        if top_activity_rows:
            top = top_activity_rows[0]
            evidence_bits.append(f"peak day {top['date']} reached {top['activity_ratio']:.2f}x baseline")

        rows.append({
            "alert_type": "time_based_low_and_slow_exfiltration",
            "cloud_account": cloud_account,
            "principal": principal,
            "entity_key": entity_key,
            "entity_type": entity_type,
            "src_ip": "not_applicable_time_based",
            "src_uid": "not_applicable_time_based",
            "interface_uid": "not_applicable_time_based",
            "destination": "s3_data_access_time_series",
            "log_sources": "|".join(sorted(set(g["log_sources"].dropna().astype(str)))),
            "s3_log_sources": "|".join(sorted(set(g["log_sources"].dropna().astype(str)))),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_hours": (last_seen - first_seen).total_seconds() / 3600,
            "duration_days": duration_days,
            "baseline_days": int(g["baseline_days"].iloc[0]),
            "current_days": current_days,
            "elevated_days": elevated_days,
            "spike_days": spike_days,
            "baseline_avg_daily_bytes": baseline_avg_daily_bytes,
            "baseline_p95_daily_bytes": float(g["baseline_p95_daily_bytes"].iloc[0] or 0),
            "baseline_avg_daily_events": baseline_avg_daily_events,
            "total_current_bytes": total_current_bytes,
            "total_current_events": total_current_events,
            "expected_current_bytes": expected_current_bytes,
            "cumulative_excess_bytes": cumulative_excess_bytes,
            "cumulative_ratio": cumulative_ratio,
            "cumulative_event_ratio": cumulative_event_ratio,
            "avg_activity_ratio": avg_activity_ratio,
            "max_activity_ratio": max_activity_ratio,
            "early3_avg_ratio": early3_avg_ratio,
            "final3_avg_ratio": final3_avg_ratio,
            "trend_slope_ratio_per_day": trend_slope,
            "total_distinct_resource_day_count": int(g["daily_distinct_resources"].sum()),
            "rare_resource_event_count": int(g["daily_rare_resource_events"].sum()),
            "contributing_day_count": len(contributing_day_rows),
            "contributing_days": "|".join(d["date"] for d in contributing_day_rows),
            "elevated_day_dates": "|".join(d["date"] for d in elevated_day_rows),
            "spike_day_dates": "|".join(d["date"] for d in spike_day_rows),
            "final_window_days": "|".join(d["date"] for d in final_window_rows),
            "top_activity_days": "|".join(
                f"{d['date']}:{d['activity_ratio']:.2f}x" for d in top_activity_rows
            ),
            "time_evidence_summary": "; ".join(evidence_bits),
            "daily_evidence_json": json.dumps(day_rows, separators=(",", ":")),
            "contributing_day_evidence_json": json.dumps(contributing_day_rows, separators=(",", ":")),
            "daily_ratios": ",".join(f"{x:.2f}" for x in ratios.tolist()),
            "daily_bytes": ",".join(str(int(x)) for x in g["daily_s3_read_bytes"].tolist()),
        })

    return pd.DataFrame(rows)


def score_time_based_alerts(features: pd.DataFrame) -> pd.DataFrame:
    """
    Score time-based low-and-slow exfiltration features.

    This produces a dedicated time_based_risk_score instead of mixing
    time-series S3/data-access anomalies with network-flow anomalies.
    risk_score is kept as a backwards-compatible alias for combined_risk_score.
    """
    if features.empty:
        return features

    out = features.copy()
    scores: list[int] = []
    reasons: list[str] = []
    detection_types: list[str] = []

    for _, row in out.iterrows():
        score = 0
        row_reasons: list[str] = []
        row_types: list[str] = []

        current_days = int(row.get("current_days", 0) or 0)
        elevated_days = int(row.get("elevated_days", 0) or 0)
        spike_days = int(row.get("spike_days", 0) or 0)
        avg_ratio = float(row.get("avg_activity_ratio", 0) or 0)
        max_ratio = float(row.get("max_activity_ratio", 0) or 0)
        final3 = float(row.get("final3_avg_ratio", 0) or 0)
        early3 = float(row.get("early3_avg_ratio", 0) or 0)
        slope = float(row.get("trend_slope_ratio_per_day", 0) or 0)
        cumulative_ratio = row.get("cumulative_ratio", np.nan)
        cumulative_event_ratio = row.get("cumulative_event_ratio", np.nan)
        cumulative_excess = float(row.get("cumulative_excess_bytes", 0) or 0)

        sustained = (
            current_days >= SUSTAINED_MIN_DAYS
            and elevated_days >= SUSTAINED_MIN_DAYS
            and avg_ratio >= SUSTAINED_RATIO_THRESHOLD
        )

        if sustained:
            score += 40
            row_types.append("sustained_elevation")
            row_reasons.append(
                f"sustained elevation: {elevated_days}/{current_days} days >= {SUSTAINED_RATIO_THRESHOLD:.1f}x baseline"
            )

        if avg_ratio >= SUSTAINED_RATIO_THRESHOLD:
            score += 15
            row_reasons.append(f"average incident activity is {avg_ratio:.2f}x baseline")

        ramp = (
            current_days >= RAMP_MIN_DAYS
            and slope >= RAMP_MIN_SLOPE_PER_DAY
            and final3 >= RAMP_FINAL_RATIO_THRESHOLD
            and final3 > max(early3 * 1.5, early3 + 0.75)
        )

        if ramp:
            score += 35
            row_types.append("ramp_up")
            row_reasons.append(
                f"ramping increase: slope={slope:.2f} ratio/day, early3={early3:.2f}x, final3={final3:.2f}x"
            )

        if final3 >= RAMP_FINAL_RATIO_THRESHOLD:
            score += 15
            row_reasons.append(f"final 3-day average is {final3:.2f}x baseline")

        periodic = (
            current_days >= 7
            and spike_days >= PERIODIC_SPIKE_MIN_DAYS
            and spike_days < current_days
            and max_ratio >= PERIODIC_SPIKE_RATIO_THRESHOLD
        )

        if periodic:
            score += 35
            row_types.append("periodic_spikes")
            row_reasons.append(
                f"periodic/repeated spikes: {spike_days} days >= {PERIODIC_SPIKE_RATIO_THRESHOLD:.1f}x baseline"
            )

        cumulative_ratio_signal = (
            (pd.notna(cumulative_ratio) and cumulative_ratio >= CUMULATIVE_EXCESS_RATIO_THRESHOLD)
            or (pd.notna(cumulative_event_ratio) and cumulative_event_ratio >= CUMULATIVE_EXCESS_RATIO_THRESHOLD)
        )

        if cumulative_ratio_signal and cumulative_excess >= CUMULATIVE_EXCESS_MIN_BYTES:
            score += 25
            row_types.append("cumulative_excess")
            row_reasons.append(
                f"cumulative excess: {int(cumulative_excess)} bytes over expected baseline"
            )

        if row.get("total_distinct_resource_day_count", 0) >= 50:
            score += 10
            row_reasons.append(
                f"broad resource access over time: {int(row['total_distinct_resource_day_count'])} resource-days"
            )

        if row.get("rare_resource_event_count", 0) >= 10:
            score += 10
            row_reasons.append(
                f"rare resource accesses over time: {int(row['rare_resource_event_count'])}"
            )

        if current_days >= 10:
            score += 5
            row_reasons.append(f"long observation window: {current_days} active days")

        scores.append(score)
        reasons.append("; ".join(row_reasons))
        detection_types.append("|".join(row_types) if row_types else "time_anomaly_weak_signal")

    out["alert_family"] = "time_based"
    out["time_based_risk_score"] = [
        normalize_score(score, MAX_TIME_BASED_RAW_SCORE) for score in scores
    ]
    out["network_risk_score"] = 0
    out["combined_risk_score"] = out[["network_risk_score", "time_based_risk_score"]].max(axis=1)
    out["risk_score"] = out["combined_risk_score"]  # backwards-compatible alias
    out["alert_reasons"] = reasons
    out["time_detection_types"] = detection_types

    return out.sort_values("time_based_risk_score", ascending=False)


def join_features(net: pd.DataFrame, timing: pd.DataFrame, s3: pd.DataFrame) -> pd.DataFrame:
    if net.empty:
        return pd.DataFrame()

    join_cols = ["cloud_account", "principal", "entity_key", "entity_type", "src_ip", "src_uid", "interface_uid", "destination"]

    combined = net.merge(timing, on=join_cols, how="left")

    combined = combined.merge(
        s3,
        on=["cloud_account", "principal", "entity_key"],
        how="left",
    )

    fill_zero_cols = [
        "s3_event_count",
        "get_object_count",
        "list_bucket_count",
        "distinct_resources",
        "rare_resource_event_count",
        "s3_duration_hours",
        "interval_count",
    ]
    for col in fill_zero_cols:
        if col in combined.columns:
            combined[col] = combined[col].fillna(0)

    return combined


# -----------------------------
# Scoring
# -----------------------------

def score_alerts(features: pd.DataFrame, profiles: dict[str, Any]) -> pd.DataFrame:
    if features.empty:
        return features

    out = features.copy()
    p95_bytes = profiles.get("entity_p95_total_bytes", {})
    p95_events = profiles.get("entity_p95_event_count", {})

    scores = []
    reasons = []

    for _, row in out.iterrows():
        score = 0
        row_reasons = []

        baseline_bytes = p95_bytes.get(row["entity_key"], 0)
        baseline_events = p95_events.get(row["entity_key"], 0)

        if row["event_count"] >= MIN_EVENT_COUNT:
            score += 15
            row_reasons.append(f"high repeated event count: {int(row['event_count'])}")

        if row["small_transfer_ratio"] >= MIN_SMALL_TRANSFER_RATIO:
            score += 15
            row_reasons.append(f"mostly small transfers: {row['small_transfer_ratio']:.2f}")

        if row["duration_hours"] >= MIN_DURATION_HOURS:
            score += 10
            row_reasons.append(f"spread over {row['duration_hours']:.1f} hours")

        if row["total_bytes_out"] >= MIN_TOTAL_BYTES_OUT:
            score += 20
            row_reasons.append(f"meaningful accumulated egress: {int(row['total_bytes_out'])} bytes")

        if baseline_bytes and row["total_bytes_out"] > baseline_bytes:
            score += 15
            row_reasons.append(f"bytes_out above entity daily p95 baseline: {int(baseline_bytes)}")

        if baseline_events and row["event_count"] > baseline_events:
            score += 10
            row_reasons.append(f"event_count above entity daily p95 baseline: {int(baseline_events)}")

        if row.get("rare_destination_ratio", 0) >= 0.50:
            score += 20
            row_reasons.append("destination is new/rare for this entity")

        if row.get("rare_user_agent_ratio", 0) >= 0.50:
            score += 10
            row_reasons.append("user agent is new/rare for this entity")

        interval_cv = row.get("interval_cv")
        interval_count = row.get("interval_count", 0)
        interval_band_ratio = row.get("interval_median_band_ratio")
        if pd.notna(interval_cv) and interval_count >= 10 and interval_cv <= REGULAR_INTERVAL_CV:
            score += 15
            row_reasons.append(f"regular timing pattern, interval_cv={interval_cv:.2f}")
        elif (
            pd.notna(interval_cv)
            and interval_count >= 10
            and interval_cv <= JITTERED_INTERVAL_CV
            and pd.notna(interval_band_ratio)
            and interval_band_ratio >= MIN_INTERVAL_BAND_RATIO
        ):
            score += 15
            median_interval = row.get("median_interval_seconds")
            median_minutes = float(median_interval) / 60 if pd.notna(median_interval) else 0
            row_reasons.append(
                "jittered regular timing pattern: "
                f"median_interval={median_minutes:.1f} min, "
                f"interval_cv={interval_cv:.2f}, "
                f"{interval_band_ratio:.0%} within +/-{INTERVAL_BAND_TOLERANCE:.0%} of median"
            )

        if row.get("get_object_count", 0) >= 50:
            score += 15
            row_reasons.append(f"many S3 GetObject-like events: {int(row['get_object_count'])}")

        if row.get("distinct_resources", 0) >= 50:
            score += 15
            row_reasons.append(f"many distinct resources accessed: {int(row['distinct_resources'])}")

        if row.get("rare_resource_event_count", 0) >= 10:
            score += 10
            row_reasons.append(f"many rare resource accesses: {int(row['rare_resource_event_count'])}")

        scores.append(score)
        reasons.append("; ".join(row_reasons))

    out["alert_family"] = "network"
    out["network_risk_score"] = [
        normalize_score(score, MAX_NETWORK_RAW_SCORE) for score in scores
    ]
    out["time_based_risk_score"] = 0
    out["combined_risk_score"] = out[["network_risk_score", "time_based_risk_score"]].max(axis=1)
    out["risk_score"] = out["combined_risk_score"]  # backwards-compatible alias
    out["alert_reasons"] = reasons
    out["alert_type"] = "possible_low_and_slow_exfiltration"

    return out.sort_values("network_risk_score", ascending=False)


def format_output(alerts: pd.DataFrame) -> pd.DataFrame:
    wanted = [
        "alert_type",
        "alert_family",
        "combined_risk_score",
        "network_risk_score",
        "time_based_risk_score",
        "risk_score",
        "entity_type",
        "entity_key",
        "cloud_account",
        "principal",
        "src_ip",
        "src_uid",
        "interface_uid",
        "destination",
        "log_sources",
        "s3_log_sources",
        "first_seen",
        "last_seen",
        "duration_hours",
        "total_bytes_out",
        "event_count",
        "median_bytes_out",
        "small_transfer_ratio",
        "rare_destination_ratio",
        "rare_user_agent_ratio",
        "interval_cv",
        "median_interval_seconds",
        "interval_median_band_ratio",
        "interval_band_tolerance",
        "s3_event_count",
        "get_object_count",
        "list_bucket_count",
        "distinct_resources",
        "rare_resource_event_count",
        "alert_reasons",
        # Time-based S3/data-access fields.
        "time_detection_types",
        "baseline_days",
        "current_days",
        "elevated_days",
        "spike_days",
        "duration_days",
        "baseline_avg_daily_bytes",
        "baseline_p95_daily_bytes",
        "baseline_avg_daily_events",
        "total_current_bytes",
        "total_current_events",
        "expected_current_bytes",
        "cumulative_excess_bytes",
        "cumulative_ratio",
        "cumulative_event_ratio",
        "avg_activity_ratio",
        "max_activity_ratio",
        "early3_avg_ratio",
        "final3_avg_ratio",
        "trend_slope_ratio_per_day",
        "total_distinct_resource_day_count",
        "contributing_day_count",
        "contributing_days",
        "elevated_day_dates",
        "spike_day_dates",
        "final_window_days",
        "top_activity_days",
        "time_evidence_summary",
        "contributing_day_evidence_json",
        "daily_evidence_json",
        "daily_ratios",
        "daily_bytes",
    ]

    # Keep preferred columns first, then preserve any extra columns returned by
    # future modules instead of silently dropping them.
    existing = [c for c in wanted if c in alerts.columns]
    extras = [c for c in alerts.columns if c not in existing]
    return alerts[existing + extras].copy()


# -----------------------------
# Main
# -----------------------------

def run_detection(
    sources: Sequence[str],
    output_path: str,
    baseline_end: str | None,
    current_days: int | None,
    min_score: int,
) -> pd.DataFrame:
    raw = load_many_events(sources)
    df = normalize_ocsf(raw)

    baseline, current = split_baseline_current(
        df,
        baseline_end=baseline_end,
        current_days=current_days,
    )

    profiles = build_baseline_profiles(baseline)
    current = add_rarity_flags(current, profiles)

    # Layer 1: existing network/trickle detector.
    net = network_features(current)
    timing = timing_features(current)
    s3 = s3_features(current)

    combined = join_features(net, timing, s3)
    scored_network = score_alerts(combined, profiles)

    if "network_risk_score" not in scored_network.columns:
        scored_network["network_risk_score"] = pd.Series(dtype="int")
    if "time_based_risk_score" not in scored_network.columns:
        scored_network["time_based_risk_score"] = 0
    if "combined_risk_score" not in scored_network.columns:
        scored_network["combined_risk_score"] = scored_network["network_risk_score"]
    if "risk_score" not in scored_network.columns:
        scored_network["risk_score"] = scored_network["combined_risk_score"]

    network_alerts = scored_network[scored_network["network_risk_score"] >= min_score].copy()
    network_output = format_output(network_alerts)

    # Layer 2: new time-based S3/data-access detector.
    time_features = time_based_s3_volume_features(baseline, current)
    scored_time = score_time_based_alerts(time_features)

    if "time_based_risk_score" not in scored_time.columns:
        scored_time["time_based_risk_score"] = pd.Series(dtype="int")
    if "network_risk_score" not in scored_time.columns:
        scored_time["network_risk_score"] = 0
    if "combined_risk_score" not in scored_time.columns:
        scored_time["combined_risk_score"] = scored_time["time_based_risk_score"]
    if "risk_score" not in scored_time.columns:
        scored_time["risk_score"] = scored_time["combined_risk_score"]

    time_alerts = scored_time[scored_time["time_based_risk_score"] >= min_score].copy()
    time_output = format_output(time_alerts)

    outputs = [df_part for df_part in [network_output, time_output] if not df_part.empty]
    if outputs:
        output = pd.concat(outputs, ignore_index=True, sort=False)
        sort_cols = [c for c in ["combined_risk_score", "time_based_risk_score", "network_risk_score"] if c in output.columns]
        if sort_cols:
            output = output.sort_values(sort_cols, ascending=[False] * len(sort_cols)).reset_index(drop=True)
    else:
        output = pd.DataFrame()

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(output_path, index=False)

    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect possible low-and-slow exfiltration in OCSF-normalized AWS logs."
    )
    parser.add_argument(
        "--input",
        required=True,
        nargs="+",
        help="One or more paths to OCSF logs. Accepts files, folders, or globs: .jsonl, .ndjson, .json, or .csv",
    )
    parser.add_argument("--output", default="alerts.csv", help="Output CSV path. Default: alerts.csv")
    parser.add_argument(
        "--baseline-end",
        default=None,
        help="Timestamp separating baseline from current detection period, e.g. 2026-06-15T00:00:00Z",
    )
    parser.add_argument(
        "--current-days",
        type=int,
        default=None,
        help="Use the last N days as current detection period; earlier events become baseline.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=ALERT_SCORE_THRESHOLD,
        help=f"Minimum risk score to alert. Default: {ALERT_SCORE_THRESHOLD}",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    alerts_df = run_detection(
        sources=args.input,
        output_path=args.output,
        baseline_end=args.baseline_end,
        current_days=args.current_days,
        min_score=args.min_score,
    )

    if alerts_df.empty:
        print("No alerts generated.")
    else:
        print(f"Generated {len(alerts_df)} alert(s).")
        print(alerts_df.to_string(index=False))
        print(f"\nSaved alerts to: {args.output}")
