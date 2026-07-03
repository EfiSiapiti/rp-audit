"""Requeue RPs for a second pass — the one CLI that writes state back to 'redo'.

Dry-run is the DEFAULT; nothing is written without --apply.

Usage:
    python -m src.requeue --all-retryable                  # preview candidates
    python -m src.requeue --all-retryable --apply          # commit
    python -m src.requeue --rp afternic.com --rp ah.nl     # specific RPs (repeatable)
    python -m src.requeue --state failed --note-contains "turn budget"
    python -m src.requeue --all-retryable --reset-attempts --apply

Safety:
    - Only second-pass candidates (classify == "retry") are requeued by default.
    - Terminal / exhausted / captured RPs are refused unless --force, so you
      can't accidentally re-run a dead or rate-limited RP (e.g. afternic.com).
"""

from __future__ import annotations

import argparse

from .lib import ledger, outcomes


def _last_note(entry: dict) -> str:
    hist = entry.get("history") or []
    return hist[-1].get("note", "") if hist else ""


def _select(entries: dict, args) -> list[dict]:
    if args.all_retryable:
        return [
            e for e in entries.values()
            if outcomes.classify(e.get("state", ""), _last_note(e),
                                 e.get("attempts", 0)) == "retry"
        ]
    out: list[dict] = []
    for e in entries.values():
        if args.rp and e.get("rp_id") in args.rp:
            out.append(e)
        elif args.state and e.get("state") == args.state:
            if args.note_contains and args.note_contains.lower() not in _last_note(e).lower():
                continue
            out.append(e)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Requeue RPs to state 'redo'.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--all-retryable", action="store_true",
                   help="requeue every second-pass candidate (classify == retry)")
    g.add_argument("--rp", action="append", metavar="RP_ID",
                   help="requeue a specific rp_id (repeatable)")
    g.add_argument("--state", help="requeue all entries currently in this state")
    ap.add_argument("--note-contains",
                    help="with --state: only entries whose last note contains this substring")
    ap.add_argument("--reset-attempts", action="store_true",
                    help="also reset the attempts counter to 0")
    ap.add_argument("--force", action="store_true",
                    help="allow requeueing terminal / exhausted / captured RPs")
    ap.add_argument("--apply", action="store_true",
                    help="write the changes (otherwise this is a dry-run)")
    args = ap.parse_args()

    led = ledger.load()
    entries = led.get("entries", {})
    selected = _select(entries, args)
    if not selected:
        print("no matching RPs.")
        return

    to_change: list[dict] = []
    skipped: list[tuple[dict, str]] = []
    for e in selected:
        bucket = outcomes.classify(e.get("state", ""), _last_note(e), e.get("attempts", 0))
        if bucket == "retry" or args.force:
            to_change.append(e)
        else:
            skipped.append((e, bucket))

    verb = "Requeuing" if args.apply else "WOULD requeue"
    suffix = " (+reset attempts)" if args.reset_attempts else ""
    print(f"{verb} {len(to_change)} RP(s) -> 'redo'{suffix}:")
    for e in to_change:
        print(f"  - {e.get('rp_id'):32s} (was {e.get('state')}, attempts={e.get('attempts', 0)})")

    if skipped:
        print(f"\nSkipped {len(skipped)} protected RP(s) (use --force to override):")
        for e, bucket in skipped:
            print(f"  - {e.get('rp_id'):32s} {bucket} ({e.get('state')})")

    if not args.apply:
        print("\n(dry-run — re-run with --apply to write these changes)")
        return

    for e in to_change:
        if args.reset_attempts:
            e["attempts"] = 0
        ledger.update_state(led, e["rp_id"], "redo",
                            note=f"requeued via src.requeue (was {e.get('state')})")
    print(f"\napplied: {len(to_change)} RP(s) set to 'redo'.")


if __name__ == "__main__":
    main()
