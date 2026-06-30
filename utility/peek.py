import gzip, zlib, sys
from pathlib import Path

journal_path = sys.argv[1]  # path to one specific bucket's rawdata/journal.gz

with open(journal_path, "rb") as f:
    data = f.read()

offset = 0
total = len(data)
chunks_shown = 0
while offset < total and chunks_shown < 3:
    if data[offset:offset+2] != b"\x1f\x8b":
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
    text = chunk.decode("utf-8", errors="replace")
    print(f"--- CHUNK {chunks_shown} (first 2000 chars) ---")
    print(text[:2000])
    print()
    chunks_shown += 1
    offset += consumed