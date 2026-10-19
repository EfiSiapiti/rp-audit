"""Run scripts.record_http for many RPs, one after another.

For each RP: opens Chrome at the RP's login/signup URL with the fabrication hook injected,
you log in and add a passkey by hand, press Enter in the terminal to finish that RP, and
the next one starts. Between RPs you can skip, quit, or continue.

By default it takes every `captured` RP in data/ledger.json that has no
data/http/<rp>.json yet.

Run from the rp-audit root:
    python -m scripts.record_http_batch --list                        # just show the queue
    python -m scripts.record_http_batch                               # everything captured, no descriptor yet
    python -m scripts.record_http_batch --rps bird.com,groups.io      # explicit list
    python -m scripts.record_http_batch --source manual               # only ledger source == manual
    python -m scripts.record_http_batch --redo --rps github.com       # re-record one that has a descriptor
    python -m scripts.record_http_batch --no-hook                     # real authenticator (Windows Hello)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HTTP_DIR = Path("data/http")


def _queue(args) -> list[tuple[str, str]]:
    led = json.load(open("data/ledger.json", encoding="utf-8"))["entries"]
    if args.rps:
        ids = [x.strip() for x in args.rps.split(",") if x.strip()]
    else:
        ids = [k for k, v in led.items() if v.get("state") == "captured"
               and (args.source is None or v.get("source") == args.source)]
    out = []
    for k in ids:
        if k not in led:
            print(f"  ! {k} not in ledger, skipping"); continue
        if (HTTP_DIR / f"{k}.json").exists() and not args.redo:
            continue
        e = led[k]
        out.append((k, e.get("signup_url") or e.get("canonical_origin") or f"https://{k}"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rps", help="comma-separated rp_ids (default: all captured without a descriptor)")
    ap.add_argument("--source", help="only ledger entries with this source (e.g. manual, manual-chrome)")
    ap.add_argument("--redo", action="store_true", help="include RPs that already have a descriptor")
    ap.add_argument("--no-hook", action="store_true", help="don't inject the fabrication hook")
    ap.add_argument("--list", action="store_true", help="print the queue and exit")
    ap.add_argument("--limit", type=int)
    a = ap.parse_args()

    q = _queue(a)
    if a.limit:
        q = q[:a.limit]
    print(f"{len(q)} RP(s) queued")
    for i, (k, u) in enumerate(q, 1):
        print(f"  {i:3d}. {k:28s} {u}")
    if a.list or not q:
        return 0

    done, skipped = [], []
    for i, (rp, url) in enumerate(q, 1):
        print(f"\n================ {i}/{len(q)}: {rp} ================")
        choice = input("  Enter = start, s = skip, q = quit > ").strip().lower()
        if choice == "q":
            break
        if choice == "s":
            skipped.append(rp); continue
        cmd = [sys.executable, "-m", "scripts.record_http", "--rp", rp, "--url", url]
        if not a.no_hook:
            cmd.append("--hook")
        rc = subprocess.call(cmd)    # inherits stdin/stdout so record_http's Enter prompt works
        (done if rc == 0 and (HTTP_DIR / f"{rp}.json").exists() else skipped).append(rp)
        if rc != 0:
            print(f"  ! record_http exited with code {rc}")

    print(f"\n=== recorded {len(done)}: {', '.join(done) or '-'}")
    if skipped:
        print(f"=== skipped/failed {len(skipped)}: {', '.join(skipped)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
