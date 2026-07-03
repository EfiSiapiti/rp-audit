"""Bootstrap the ledger from CSV. Just populate it, no triage."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .lib import ledger, parse


def main():
    ap = argparse.ArgumentParser(description="Initialize ledger from CSV")
    ap.add_argument("csv", help="Path to the scan CSV")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise SystemExit(f"CSV not found: {csv_path}")

    rows = parse.parse_csv(csv_path)
    print(f"parsed {len(rows)} RPs from {csv_path}")

    # Load existing ledger or start fresh
    try:
        led = ledger.load()
    except (json.JSONDecodeError, FileNotFoundError):
        # Create fresh ledger if corrupted/missing
        led = {"version": 1, "entries": {}}
    
    now = datetime.now(timezone.utc).isoformat()
    added = 0
    
    # Add each row to ledger
    for row in rows:
        rp_id = row.rp_id
        if rp_id not in led["entries"]:
            led["entries"][rp_id] = {
                "rp_id": rp_id,
                "canonical_origin": row.canonical_origin,
                "entity": row.entity,
                "signup_url": row.enroll_url or row.canonical_origin,
                "state": "pending",
                "attempts": 0,
                "history": [{
                    "at": now,
                    "state": "pending",
                    "note": "initialized"
                }]
            }
            added += 1

    ledger.save(led)
    print(f"✓ Added {added} new RPs to ledger")
    print(f"  Total entries: {len(led['entries'])}")


if __name__ == "__main__":
    main()
