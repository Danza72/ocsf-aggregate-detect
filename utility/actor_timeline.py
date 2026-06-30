#!/usr/bin/env python3
"""
actor_timeline.py

Diagnostic: shows each distinct actor's event count and first/last
activity timestamp across the mapped OCSF CloudTrail and S3 access log
files. Used to sanity-check a baseline/scoring time-window split before
committing to one -- e.g. to confirm a candidate cutoff time doesn't
awkwardly split a real user's session in half.

Usage:
    python3 actor_timeline.py <ocsf_out_dir>

Example:
    python3 actor_timeline.py .\ocsf_out
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def get_actor(ev: dict) -> str:
    a = ev.get("actor", {}).get("user", {})
    return a.get("name") or a.get("uid_alt") or a.get("uid") or "UNKNOWN"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ocsf_out_dir>")
        sys.exit(1)

    out_dir = Path(sys.argv[1])
    files = ["cloudtrail_ocsf.jsonl", "s3_accesslogs_ocsf.jsonl"]

    actors = defaultdict(list)

    for fname in files:
        fpath = out_dir / fname
        if not fpath.exists():
            print(f"SKIP: {fpath} not found")
            continue
        with open(fpath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ev = json.loads(line)
                t = ev.get("time")
                if t:
                    actors[get_actor(ev)].append(t)

    print(f"{'actor':35s} {'count':>6s} {'first':>10s} {'last':>10s}")
    for actor, times in sorted(actors.items(), key=lambda x: -len(x[1])):
        first = datetime.fromtimestamp(min(times) / 1000, tz=timezone.utc).strftime("%H:%M:%S")
        last = datetime.fromtimestamp(max(times) / 1000, tz=timezone.utc).strftime("%H:%M:%S")
        print(f"{actor:35s} {len(times):6d} {first:>10s} {last:>10s}")


if __name__ == "__main__":
    main()