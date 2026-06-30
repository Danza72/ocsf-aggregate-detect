#!/usr/bin/env python3
"""
extract_botsv3_aws_v2.py

Unified extractor for BOTSv3 AWS-relevant log sources, covering all 4
formats confirmed by direct inspection of the dataset:

  - aws:cloudtrail              (JSON)
  - aws:cloudwatch:guardduty    (JSON)
  - aws:cloudwatchlogs:vpcflow  (space-delimited, AWS VPC Flow Log v2 format)
  - aws:s3:accesslogs           (space-delimited + quoted sub-fields,
                                  AWS S3 server access log format)

Unlike v1 (extract_botsv3_aws.py), this version does NOT rely solely on
brace-matching for JSON. It instead anchors on the literal `sourcetype::X`
marker Splunk embeds in the raw journal stream, then parses the text
immediately following that marker according to the known shape for that
sourcetype. This is more robust because:
  1. It correctly handles non-JSON formats (VPC Flow, S3 access logs).
  2. It avoids false positives from JSON blobs belonging to OTHER
     sourcetypes that happen to share key names.

Usage:
    python3 extract_botsv3_aws_v2.py /path/to/extracted/botsv3 ./aws_raw_out
"""

import json
import os
import re
import sys
import zlib
from pathlib import Path

# ---- Regexes -----------------------------------------------------------

SOURCETYPE_MARKER_RE = re.compile(r"sourcetype::([A-Za-z0-9:_\-./]+)")

# VPC Flow Log v2 fields, in order.
VPCFLOW_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log_status",
]
# A VPC flow record line: version(int) account-id(12 digits) eni-xxxx ip ip port port proto packets bytes start end ACTION STATUS
VPCFLOW_LINE_RE = re.compile(
    r"(?P<version>\d)\s+"
    r"(?P<account_id>\d{12})\s+"
    r"(?P<interface_id>eni-[0-9a-f]+)\s+"
    r"(?P<srcaddr>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<dstaddr>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<srcport>\d+)\s+"
    r"(?P<dstport>\d+)\s+"
    r"(?P<protocol>\d+)\s+"
    r"(?P<packets>\d+)\s+"
    r"(?P<bytes>\d+)\s+"
    r"(?P<start>\d{9,11})\s+"
    r"(?P<end>\d{9,11})\s+"
    r"(?P<action>ACCEPT|REJECT)\s+"
    r"(?P<log_status>OK|NODATA|SKIPDATA)"
)

# S3 access log line (standard AWS format). Bucket owner is a 64-char hex
# canonical ID; timestamp is bracketed; remaining fields are space
# separated except the quoted HTTP request line, referer, and user-agent.
S3_ACCESSLOG_LINE_RE = re.compile(
    r"(?P<bucket_owner>[0-9a-f]{32,64})\s+"
    r"(?P<bucket>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"(?P<remote_ip>\S+)\s+"
    r"(?P<requester>\S+)\s+"
    r"(?P<request_id>\S+)\s+"
    r"(?P<operation>\S+)\s+"
    r"(?P<key>\S+)\s+"
    r'"(?P<request_uri>[^"]*)"\s+'
    r"(?P<http_status>\S+)\s+"
    r"(?P<error_code>\S+)\s+"
    r"(?P<bytes_sent>\S+)\s+"
    r"(?P<object_size>\S+)\s+"
    r"(?P<total_time>\S+)\s+"
    r"(?P<turnaround_time>\S+)\s+"
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"\s+'
    r"(?P<version_id>[A-Za-z0-9\-_.]*)"
)


JSON_OBJECT_START_RE = re.compile(r'\{\s*"[A-Za-z_][A-Za-z0-9_]*"\s*:')


def find_all_json_objects(text: str):
    """
    Yield every well-formed top-level JSON object found anywhere in text.

    Only attempts brace-matching at positions that look like the real start
    of a JSON object (a '{' followed by a quoted key and a colon). This is
    essential because Splunk's binary metadata noise can contain stray
    '{', '}', and '"' bytes that would otherwise corrupt depth-tracking if
    we tried to brace-match starting from EVERY '{' in the raw text.
    """
    n = len(text)
    i = 0
    while i < n:
        m = JSON_OBJECT_START_RE.match(text, i)
        if not m:
            i += 1
            continue

        depth = 0
        j = i
        in_str = False
        esc = False
        found_end = None
        while j < n:
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        found_end = j + 1
                        break
            j += 1

        if found_end is not None:
            candidate = text[i:found_end]
            try:
                obj = json.loads(candidate)
                yield obj
            except (json.JSONDecodeError, ValueError):
                pass
            i = found_end
        else:
            i += 1


def iter_journal_text_chunks(journal_path: Path):
    with open(journal_path, "rb") as f:
        data = f.read()
    offset = 0
    total = len(data)
    while offset < total:
        if data[offset:offset + 2] != b"\x1f\x8b":
            nxt = data.find(b"\x1f\x8b", offset + 1)
            if nxt == -1:
                break
            offset = nxt
            continue
        d = zlib.decompressobj(zlib.MAX_WBITS | 16)
        try:
            chunk = d.decompress(data[offset:])
        except zlib.error:
            nxt = data.find(b"\x1f\x8b", offset + 1)
            if nxt == -1:
                break
            offset = nxt
            continue
        consumed = len(data[offset:]) - len(d.unused_data)
        if consumed <= 0:
            break
        yield chunk.decode("latin-1", errors="ignore")
        offset += consumed


def classify_json(obj: dict):
    """Return 'cloudtrail', 'guardduty', or None based on JSON shape alone."""
    if not isinstance(obj, dict):
        return None
    if "eventVersion" in obj and "eventSource" in obj and "eventName" in obj:
        return "cloudtrail"
    if "schemaVersion" in obj and "type" in obj and "accountId" in obj and "region" in obj:
        return "guardduty"
    return None


def extract_from_chunk(text: str, results: dict, dedup: dict):
    """
    Scan one decompressed chunk of text for all four target record types.

    IMPORTANT: Splunk does not repeat the `sourcetype::` marker before every
    individual raw event in a slice -- it's typically written once per
    slice/segment, followed by many packed records. So extraction must NOT
    be limited to "the first match right after a marker" (that silently
    drops almost all records). Instead:

      - CloudTrail / GuardDuty: scan the WHOLE chunk for JSON objects,
        classify each by shape independently.
      - VPC Flow / S3 access logs: scan the WHOLE chunk with finditer for
        ALL matching lines, not just the first one after a marker. The
        sourcetype marker is only used as a presence check (see caller),
        not as a per-record anchor.
    """
    # --- JSON-shaped sourcetypes: scan whole chunk, classify by shape ---
    for obj in find_all_json_objects(text):
        kind = classify_json(obj)
        if kind is None:
            continue
        key = json.dumps(obj, sort_keys=True)
        if key not in dedup[kind]:
            dedup[kind].add(key)
            results[kind].append(obj)

    # --- Positional sourcetypes: find ALL matching lines anywhere in chunk ---
    if "aws:cloudwatchlogs:vpcflow" in text or "vpcflow" in text:
        for vm in VPCFLOW_LINE_RE.finditer(text):
            rec = vm.groupdict()
            key = json.dumps(rec, sort_keys=True)
            if key not in dedup["vpcflow"]:
                dedup["vpcflow"].add(key)
                results["vpcflow"].append(rec)

    if "aws:s3:accesslogs" in text:
        for sm in S3_ACCESSLOG_LINE_RE.finditer(text):
            rec = sm.groupdict()
            key = json.dumps(rec, sort_keys=True)
            if key not in dedup["s3accesslogs"]:
                dedup["s3accesslogs"].add(key)
                results["s3accesslogs"].append(rec)


def find_buckets(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        if "journal.gz" in filenames and Path(dirpath).name == "rawdata":
            yield Path(dirpath) / "journal.gz"


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <extracted_botsv3_root> <output_dir>")
        sys.exit(1)

    root = Path(sys.argv[1]).expanduser().resolve()
    out_dir = Path(sys.argv[2]).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    journals = list(find_buckets(root))
    if not journals:
        print(f"No journal.gz files found under {root}")
        sys.exit(1)

    print(f"Found {len(journals)} bucket journal.gz files under {root}")

    results = {"cloudtrail": [], "guardduty": [], "vpcflow": [], "s3accesslogs": []}
    dedup = {"cloudtrail": set(), "guardduty": set(), "vpcflow": set(), "s3accesslogs": set()}

    for idx, jpath in enumerate(journals, 1):
        print(f"[{idx}/{len(journals)}] {jpath}")
        try:
            for text in iter_journal_text_chunks(jpath):
                extract_from_chunk(text, results, dedup)
        except Exception as e:
            print(f"  WARNING: {jpath}: {e}")

    out_files = {
        "cloudtrail": "cloudtrail_raw.jsonl",
        "guardduty": "guardduty_raw.jsonl",
        "vpcflow": "vpcflow_raw.jsonl",
        "s3accesslogs": "s3_accesslogs_raw.jsonl",
    }
    counts = {}
    for key, fname in out_files.items():
        path = out_dir / fname
        with open(path, "w") as f:
            for rec in results[key]:
                f.write(json.dumps(rec) + "\n")
        counts[key] = len(results[key])

    print("\n--- Done ---")
    print(json.dumps(counts, indent=2))
    print(f"\nOutput written to: {out_dir}")


if __name__ == "__main__":
    main()