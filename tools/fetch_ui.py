#!/usr/bin/env python3
"""M0: extract the embedded admin UI by crawling a running PocketBase oracle.

The admin UI is served under /_/ . We crawl index.html, follow every local
reference (src/href in HTML, static asset paths in JS/CSS), and mirror the tree.

Usage:
    python3 tools/fetch_ui.py --base http://127.0.0.1:18090 --out ui
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.parse
import urllib.request

QUOTES = "\"'`"
HTML_REF = re.compile(r'(?:src|href)="([^"]+)"')
JS_REF = re.compile(
    r'[' + QUOTES + r'(]\.?/?((?:assets|libs|images)/[A-Za-z0-9_.@/-]+'
    r'\.(?:js|css|woff2?|svg|png|ico|webmanifest|json|txt|html))[' + QUOTES + r')]'
)
JS_CHUNK = re.compile(
    r'[' + QUOTES + r']\./([A-Za-z0-9_@-]+-[A-Za-z0-9_-]{8}\.js)[' + QUOTES + r']'
)


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "pb-rs-spec-extractor"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:18090")
    ap.add_argument("--out", default="ui")
    ap.add_argument("--root", default="/_/")
    ap.add_argument("--manifest", default=None, help="file with dist/-relative paths")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    seen: set[str] = set()
    queue: list[str] = [args.root]

    if args.manifest:
        with open(args.manifest) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rel = line[len("dist/"):] if line.startswith("dist/") else line
                queue.append("/" + args.root.strip("/") + "/" + rel)

    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)

        url = base + path
        try:
            body = fetch(url)
        except Exception as e:  # noqa: BLE001
            print(f"skip {path}: {e}", file=sys.stderr)
            continue

        dest = os.path.join(args.out, path.lstrip("/"))
        if dest.endswith("/") or path == args.root:
            dest = os.path.join(dest, "index.html")
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as f:
            f.write(body)

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            continue

        refs: set[str] = set()
        for m in HTML_REF.finditer(text):
            refs.add(m.group(1))
        for m in JS_REF.finditer(text):
            refs.add("./" + m.group(1))
        for m in JS_CHUNK.finditer(text):
            refs.add("./assets/" + m.group(1))

        for ref in refs:
            if ref.startswith(("http://", "https://", "data:", "#", "mailto:")):
                continue
            candidates: list[str] = []
            if ref.startswith("/"):
                candidates.append(ref)
            else:
                candidates.append(urllib.parse.urljoin(path, ref))
                # Vite chunks reference "./assets/x.js" from inside /_/assets/*.js;
                # those are rooted at the UI base, not at the chunk directory.
                candidates.append("/" + args.root.strip("/") + "/" + ref.lstrip("./"))
            for cand in candidates:
                cand = cand.split("#")[0].split("?")[0]
                if cand not in seen and cand not in queue:
                    queue.append(cand)

    total = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, fs in os.walk(args.out)
        for f in fs
    )
    print(f"mirrored {len(seen)} paths, {total} bytes into {args.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
