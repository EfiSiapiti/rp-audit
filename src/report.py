"""Read-only audit report over the ledger.

Usage:
    python -m src.report          # human-readable summary
    python -m src.report --json   # machine-readable

Never writes. Classifies each RP via lib.outcomes into
success / terminal / retry (second-pass candidate) / exhausted, and lists the
second-pass candidates so you can decide what to re-run by hand.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter

from .lib import ledger, outcomes


def _last_note(entry: dict) -> str:
    hist = entry.get("history") or []
    return hist[-1].get("note", "") if hist else ""


def build_report(led: dict) -> dict:
    entries = led.get("entries", {})
    buckets: dict[str, list[dict]] = {
        "success": [], "terminal": [], "retry": [], "exhausted": [],
    }
    state_counts: Counter = Counter()
    for e in entries.values():
        state = e.get("state", "")
        note = _last_note(e)
        attempts = e.get("attempts", 0)
        state_counts[state] += 1
        bucket = outcomes.classify(state, note, attempts)
        buckets[bucket].append({
            "rp_id": e.get("rp_id", ""),
            "state": state,
            "attempts": attempts,
            "note": note,
            "signup_url": e.get("signup_url") or e.get("canonical_origin", ""),
        })
    return {
        "total": len(entries),
        "state_counts": dict(state_counts),
        "buckets": buckets,
    }


def _print_human(rep: dict) -> None:
    print(f"\nLedger: {rep['total']} RPs\n")
    print("By state:")
    for state, count in sorted(rep["state_counts"].items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {state:28s} {count}")

    b = rep["buckets"]
    print("\nBy outcome bucket:")
    for name in ("success", "terminal", "retry", "exhausted"):
        print(f"  {name:28s} {len(b[name])}")

    cand = sorted(b["retry"], key=lambda r: (-r["attempts"], r["rp_id"]))
    print(f"\nSecond-pass candidates ({len(cand)}) — transient failures worth a retry:")
    if not cand:
        print("  (none)")
    for r in cand:
        print(f"  - {r['rp_id']:32s} attempts={r['attempts']}  {r['note'][:80]}")

    ex = sorted(b["exhausted"], key=lambda r: (-r["attempts"], r["rp_id"]))
    if ex:
        print(f"\nExhausted ({len(ex)}) — hit the attempt cap "
              f"({outcomes.DEFAULT_MAX_ATTEMPTS}); needs manual judgment "
              f"(likely IP-blocked — do not blindly retry):")
        for r in ex:
            print(f"  - {r['rp_id']:32s} attempts={r['attempts']}  {r['note'][:80]}")
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description="Read-only ledger report.")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    rep = build_report(ledger.load())
    if args.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        _print_human(rep)


if __name__ == "__main__":
    main()
