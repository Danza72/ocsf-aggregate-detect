#!/usr/bin/env python3
"""
inventory_sourcetypes.py

Diagnostic tool: scans every bucket's journal.gz under the BOTSv3 dataset
and reports which Splunk sourcetypes actually appear in each one, with a
rough event count estimate per sourcetype.

This solves the "which bucket has what" problem without guessing -- it
looks for the literal `sourcetype::NAME` marker that Splunk embeds in the
raw journal stream (visible even amid the binary metadata noise) and tallies
occurrences.

Usage:
    python3 inventory_sourcetypes.py /path/to/botsv3

Output:
    Prints a per-bucket breakdown, then a grand total across all buckets,
    sorted by event count descending.
"""

import re
import sys
import zlib
from collections import Counter, defaultdict
from pathlib import Path

SOURCETYPE_RE = re.compile(r"sourcetype::([A-Za-z0-9:_\-./]+)")


def iter_journal_text(journal_path: Path):
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


def find_buckets(root: Path):
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        if "journal.gz" in filenames and Path(dirpath).name == "rawdata":
            yield Path(dirpath) / "journal.gz"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <extracted_botsv3_root>")
        sys.exit(1)

    root = Path(sys.argv[1]).expanduser().resolve()
    journals = list(find_buckets(root))
    if not journals:
        print(f"No journal.gz files found under {root}")
        sys.exit(1)

    print(f"Found {len(journals)} buckets\n")

    grand_total = Counter()
    per_bucket = {}

    for jpath in journals:
        bucket_name = jpath.parent.parent.name
        counts = Counter()
        for text in iter_journal_text(jpath):
            for m in SOURCETYPE_RE.finditer(text):
                counts[m.group(1)] += 1
        per_bucket[bucket_name] = counts
        grand_total.update(counts)
        top = ", ".join(f"{k}={v}" for k, v in counts.most_common(5))
        print(f"{bucket_name}: {top if top else '(no sourcetype markers found)'}")
        # Print the FULL PATH explicitly whenever a target sourcetype appears,
        # so it's unambiguous which bucket to peek into next.
        targets = ("vpcflow", "s3:accesslogs", "guardduty")
        for st in counts:
            if any(t in st for t in targets):
                print(f"    >>> FOUND {st} in: {jpath}")

    print("\n=== GRAND TOTAL (all buckets, marker-count proxy for event count) ===")
    for sourcetype, count in grand_total.most_common():
        print(f"{sourcetype:45s} {count}")


if __name__ == "__main__":
    main()