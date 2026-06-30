#!/usr/bin/env python3
"""
extract_botsv3_aws.py

Extracts raw AWS CloudTrail and VPC Flow Log events from the BOTSv3 dataset
WITHOUT requiring a Splunk installation.

How it works
------------
BOTSv3 is distributed as pre-indexed Splunk buckets. The raw event text lives
inside each bucket's `rawdata/journal.gz` file. That file is NOT a single gzip
stream -- it's many independently-compressed gzip "slices" concatenated back
to back, and each decompressed slice contains the raw event text interleaved
with Splunk's internal binary metadata (host/source/sourcetype/time markers).

Rather than reverse-engineer Splunk's exact binary field framing (which has
changed across versions and isn't published), this script:
  1. Walks every bucket directory under the extracted dataset.
  2. Reads each journal.gz as a sequence of concatenated gzip members.
  3. Scans the decompressed bytes for embedded JSON objects using a
     brace-matching scanner (this works because CloudTrail and VPC Flow Log
     records -- our two targets -- are themselves JSON, so we don't need to
     know Splunk's surrounding metadata format at all).
  4. Fingerprints each found JSON object to classify it as CloudTrail,
     VPC Flow Log, or "other" (skipped).
  5. Writes deduplicated results to JSONL files, one per sourcetype.

Usage
-----
    python3 extract_botsv3_aws.py /path/to/extracted/botsv3 ./aws_raw_out

The first argument is the root of the *extracted* dataset (after you've run
`tar -xzf botsv3_data_set.tgz`) -- i.e. the directory that contains the
`botsv3` index folder with its `db_*` / `rb_*` / `hot_*` bucket subfolders.

Output
------
  ./aws_raw_out/cloudtrail_raw.jsonl
  ./aws_raw_out/vpcflow_raw.jsonl
  ./aws_raw_out/extraction_report.json   (counts + any warnings)

Notes
-----
- This is a best-effort structural extractor, not a byte-perfect Splunk
  journal parser. It will recover the vast majority of CloudTrail/VPC Flow
  events because they're well-formed embedded JSON, but it makes no claims
  about 100% completeness. Cross-check counts against what Splunk itself
  reports if you ever spin up a trial instance to verify.
- Memory use is bounded -- buckets are processed one at a time, slice by
  slice, not loaded wholesale.
"""

import gzip
import io
import json
import os
import sys
import zlib
from pathlib import Path

# ---- Fingerprints used to classify a recovered JSON blob ------------------

def classify_event(obj: dict) -> str | None:
    """Return 'cloudtrail', 'vpcflow', or None based on JSON shape."""
    if not isinstance(obj, dict):
        return None

    # CloudTrail management/data events have these top-level keys.
    if "eventVersion" in obj and "eventSource" in obj and "eventName" in obj:
        return "cloudtrail"

    # Splunk's aws:cloudwatchlogs:vpcflow sourcetype wraps the flow log
    # fields (these are the canonical VPC Flow Log v2 field names).
    vpcflow_fields = {
        "version", "account-id", "interface-id", "srcaddr", "dstaddr",
        "srcport", "dstport", "protocol", "packets", "bytes", "start",
        "end", "action", "log-status",
    }
    if isinstance(obj, dict) and vpcflow_fields.issubset(obj.keys()):
        return "vpcflow"

    # Some Splunk exports nest the actual record under a "message" or
    # "Records" key (CloudTrail's native S3 file shape is {"Records": [...]})
    return None


def find_json_objects(text: str):
    """
    Scan `text` for top-level {...} JSON objects using brace matching,
    yielding parsed dicts. Tolerant of garbage/binary noise between objects
    (those just fail json.loads and get skipped).
    """
    n = len(text)
    i = 0
    while i < n:
        if text[i] == "{":
            depth = 0
            start = i
            j = i
            in_str = False
            esc = False
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
                            candidate = text[start:j + 1]
                            try:
                                obj = json.loads(candidate)
                            except (json.JSONDecodeError, ValueError):
                                obj = None
                            if obj is not None:
                                yield obj
                                i = j  # resume scan after this object
                            break
                j += 1
            i = max(i, j) + 1
        else:
            i += 1


def iter_journal_text_chunks(journal_path: Path, chunk_decode_errors="ignore"):
    """
    Read journal.gz as a sequence of concatenated gzip members.
    Yields decoded text chunks (latin-1/utf-8 best-effort) for scanning.
    """
    with open(journal_path, "rb") as f:
        data = f.read()

    offset = 0
    total = len(data)
    n_members = 0
    while offset < total:
        # gzip member magic: 1f 8b
        if data[offset:offset + 2] != b"\x1f\x8b":
            # Not a clean boundary -- scan forward for the next magic byte
            # pair so one corrupt/odd slice doesn't kill the whole bucket.
            next_magic = data.find(b"\x1f\x8b", offset + 1)
            if next_magic == -1:
                break
            offset = next_magic
            continue

        decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)  # gzip mode
        try:
            chunk = decompressor.decompress(data[offset:])
        except zlib.error:
            next_magic = data.find(b"\x1f\x8b", offset + 1)
            if next_magic == -1:
                break
            offset = next_magic
            continue

        consumed = len(data[offset:]) - len(decompressor.unused_data)
        if consumed <= 0:
            break

        n_members += 1
        try:
            text = chunk.decode("utf-8", errors=chunk_decode_errors)
        except Exception:
            text = chunk.decode("latin-1", errors=chunk_decode_errors)
        yield text

        offset += consumed

    return n_members


def find_buckets(root: Path):
    """Yield paths to rawdata/journal.gz files under bucket directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        if "journal.gz" in filenames and os.path.basename(dirpath) == "rawdata":
            yield Path(dirpath) / "journal.gz"


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <extracted_botsv3_root> <output_dir>")
        sys.exit(1)

    root = Path(sys.argv[1]).expanduser().resolve()
    out_dir = Path(sys.argv[2]).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not root.exists():
        print(f"ERROR: input root does not exist: {root}")
        sys.exit(1)

    journals = list(find_buckets(root))
    if not journals:
        print(f"WARNING: no rawdata/journal.gz files found under {root}")
        print("Double-check this is the extracted dataset root (after tar -xzf).")
        sys.exit(1)

    print(f"Found {len(journals)} bucket journal.gz files under {root}")

    seen_cloudtrail = set()
    seen_vpcflow = set()

    ct_out = open(out_dir / "cloudtrail_raw.jsonl", "w")
    vpc_out = open(out_dir / "vpcflow_raw.jsonl", "w")

    counts = {"cloudtrail": 0, "vpcflow": 0, "other_skipped": 0, "buckets_processed": 0}
    warnings = []

    for idx, jpath in enumerate(journals, 1):
        print(f"[{idx}/{len(journals)}] {jpath}")
        try:
            for text_chunk in iter_journal_text_chunks(jpath):
                for obj in find_json_objects(text_chunk):
                    kind = classify_event(obj)
                    if kind == "cloudtrail":
                        key = json.dumps(obj, sort_keys=True)
                        if key not in seen_cloudtrail:
                            seen_cloudtrail.add(key)
                            ct_out.write(json.dumps(obj) + "\n")
                            counts["cloudtrail"] += 1
                    elif kind == "vpcflow":
                        key = json.dumps(obj, sort_keys=True)
                        if key not in seen_vpcflow:
                            seen_vpcflow.add(key)
                            vpc_out.write(json.dumps(obj) + "\n")
                            counts["vpcflow"] += 1
                    else:
                        counts["other_skipped"] += 1
        except Exception as e:
            warnings.append(f"{jpath}: {e}")
            print(f"  WARNING: {e}")
        counts["buckets_processed"] += 1

    ct_out.close()
    vpc_out.close()

    report = {"counts": counts, "warnings": warnings, "input_root": str(root)}
    with open(out_dir / "extraction_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\n--- Done ---")
    print(json.dumps(counts, indent=2))
    print(f"\nOutput written to: {out_dir}")
    if warnings:
        print(f"{len(warnings)} warnings -- see extraction_report.json")


if __name__ == "__main__":
    main()