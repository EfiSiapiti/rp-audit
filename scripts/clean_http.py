"""Strip noise out of a captured raw HTTP log before classifying it by hand.

record_http.py captures every XHR/fetch/document response during a hand-driven
session, which includes a lot that is never part of the login/WebAuthn flow:
analytics/telemetry beacons, bundled JS/CSS/fonts/wasm, CAPTCHA/bot-detection
probes, keep-alive pings, emoji-picker data, and image loads. This removes all
of that (see http_flow.clean_raw_log for the exact rules) and writes the
trimmed log back, after backing up the original to data/http/_backup/.

Usage:
    python -m scripts.clean_http --rp canva.com
    python -m scripts.clean_http --rp canva.com --dry-run   # report only, write nothing
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from src.lib import http_flow

HTTP_DIR = Path("data/http")
BACKUP_DIR = HTTP_DIR / "_backup"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True, help="RP id, e.g. canva.com")
    ap.add_argument("--dry-run", action="store_true", help="report counts only, write nothing")
    args = ap.parse_args()

    raw_path = HTTP_DIR / f"{args.rp}.raw.json"
    if not raw_path.exists():
        raise SystemExit(f"no raw log at {raw_path} — run scripts.record_http first")

    records = json.loads(raw_path.read_text(encoding="utf-8"))
    kept, dropped = http_flow.clean_raw_log(records)

    total_dropped = sum(dropped.values())
    print(f"  {len(records)} requests -> keeping {len(kept)}, dropping {total_dropped}")
    for reason, count in sorted(dropped.items(), key=lambda kv: -kv[1]):
        print(f"    - {reason}: {count}")

    if args.dry_run:
        print("\n  --dry-run: nothing written")
        return

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_path = BACKUP_DIR / raw_path.name
    shutil.copy2(raw_path, backup_path)
    raw_path.write_text(json.dumps(kept, indent=2), encoding="utf-8")

    print(f"\n  original backed up -> {backup_path}")
    print(f"  cleaned log written -> {raw_path} ({len(kept)} requests)")


if __name__ == "__main__":
    main()
