#!/usr/bin/env python3
"""M0: recover the embedded admin UI manifest directly from the Go binary.

Go's embed.FS stores file names as plain strings in .rodata, but they are
packed back-to-back with no separator ("dist/assets/a.jsdist/assets/b.js").
We scan for b"dist/" occurrences and cut each name where the next b"dist/"
begins or a non-path byte appears.

Usage:
    python3 tools/extract_ui_manifest.py --binary ~/lab/pb/pocketbase \
        --out spec/raw/ui-manifest.txt
"""

from __future__ import annotations

import argparse
import re

PATH_RE = re.compile(rb"^[A-Za-z0-9_.@/+-]+$")
EXTS = sorted(
    [b".webmanifest", b".woff2", b".woff", b".html", b".json", b".css", b".svg",
     b".png", b".ico", b".txt", b".map", b".js"],
    key=len,
    reverse=True,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--prefix", default="dist/")
    args = ap.parse_args()

    blob = open(args.binary, "rb").read()
    needle = args.prefix.encode()
    names: set[str] = set()

    start = 0
    while True:
        i = blob.find(needle, start)
        if i < 0:
            break
        start = i + 1
        # Take a bounded window and cut at the next "dist/" or non-path byte.
        window = blob[i : i + 400]
        end = window.find(needle, 1)
        if end > 0:
            window = window[:end]
        run = bytearray()
        for b in window:
            if 32 <= b < 127 and chr(b) not in '"\'`<>()[]{} ,;:\\*?=|!':
                run.append(b)
            else:
                break
        cand = bytes(run)
        if cand.endswith(needle) or not PATH_RE.match(cand) or len(cand) <= len(needle) + 3:
            continue
        # Names are packed next to unrelated rodata ("....jssql"); cut at the
        # last position where a known asset extension ends.
        cut = -1
        for ext in EXTS:
            pos = cand.rfind(ext)
            if pos >= 0:
                cut = max(cut, pos + len(ext))
        if cut < 0:
            continue
        cand = cand[:cut]
        if cand.endswith(b"/") or cand.endswith(needle):
            continue
        names.add(cand.decode())

    ordered = sorted(names)
    with open(args.out, "w") as f:
        for n in ordered:
            f.write(n + "\n")
    print(f"{len(ordered)} embedded UI paths -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
