#!/usr/bin/env python3
"""
peek_sourcetype.py

Like peek.py, but instead of blindly printing the first few decompressed
chunks, it scans ALL chunks in a journal.gz and prints only the text
immediately surrounding a specific sourcetype marker you're looking for.

Usage:
    python3 peek_sourcetype.py <path_to_journal.gz> <sourcetype_substring> [max_hits]

Example:
    python3 peek_sourcetype.py .\botsv3\db\db_xxx\rawdata\journal.gz "aws:s3:accesslogs" 3
"""

import sys
import zlib


def iter_chunks(journal_path):
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


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <journal.gz> <sourcetype_substring> [max_hits]")
        sys.exit(1)

    journal_path = sys.argv[1]
    needle = sys.argv[2]
    max_hits = int(sys.argv[3]) if len(sys.argv) > 3 else 3

    hits = 0
    for chunk_idx, text in enumerate(iter_chunks(journal_path)):
        idx = text.find(needle)
        if idx == -1:
            continue
        while idx != -1 and hits < max_hits:
            start = max(0, idx - 50)
            end = min(len(text), idx + 2500)
            print(f"--- HIT {hits} (chunk {chunk_idx}, offset {idx}) ---")
            print(text[start:end])
            print()
            hits += 1
            idx = text.find(needle, idx + 1)
        if hits >= max_hits:
            break

    if hits == 0:
        print(f"No occurrences of '{needle}' found in any chunk.")
    else:
        print(f"Printed {hits} hit(s).")


if __name__ == "__main__":
    main()