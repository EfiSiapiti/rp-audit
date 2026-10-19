"""Register on RPs by hand and record the outcome in rp-audit's ledger.

Opens each RP in its own persistent Chrome profile (browser-profiles-manual/<rp>),
you drive the signup, then type the outcome. No session/cookie file is written.
An RP that is not in data/ledger.json yet is added as a new entry first (its signup
page is taken from data/ledger_fidentikit.json when the HTTP probe found one).

The persistent profile keeps you logged in, so a later `record_http` / passkey
capture for the same RP can reuse it.

Run from the rp-audit root:
    python -m scripts.manual_signup --rps hubdrive.space,blenderartists.org
    python -m scripts.manual_signup --rp bird.com
"""
from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from src.lib import browser as browsermod
from src.lib import ledger

SCREENING = Path("data/ledger_fidentikit.json")
OUTCOMES = ("captured", "captcha-blocked", "phone-gated", "geo-blocked", "duplicate-account",
            "requires-existing-account", "no-portal", "dns-dead", "failed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _screening_entry(rp_id: str) -> dict:
    try:
        return json.load(open(SCREENING, encoding="utf-8"))["entries"].get(rp_id, {})
    except (OSError, ValueError, KeyError):
        return {}


def _ensure_entry(led: dict, rp_id: str) -> str:
    """Make sure rp_id is in the ledger; return the URL to open."""
    scr = _screening_entry(rp_id)
    probe = scr.get("http_probe") or {}
    origin = scr.get("canonical_origin") or f"https://{rp_id}"
    url = probe.get("signup_url") or origin
    if rp_id not in led["entries"]:
        led["entries"][rp_id] = {
            "rp_id": rp_id, "canonical_origin": origin, "entity": "",
            "signup_url": url, "state": "pending", "attempts": 0, "source": "manual",
            "history": [{"at": _now(), "state": "pending", "note": "added for manual signup"}],
        }
        ledger.save(led)
        print(f"  (added {rp_id} to ledger)")
    else:
        e = led["entries"][rp_id]
        url = probe.get("signup_url") or e.get("signup_url") or e.get("canonical_origin") or url
    return url


def _prompt_outcome(rp_id: str) -> str | None:
    print(f"\n  Outcome for {rp_id}:")
    print(f"    valid: {', '.join(OUTCOMES)}")
    print("    (blank = skip this RP, leave it as is)")
    while True:
        choice = input("  outcome> ").strip()
        if not choice:
            return None
        if choice in OUTCOMES:
            return choice
        print(f"  ! '{choice}' is not valid; try again (or blank to skip)")


async def _process_one(rp_id: str) -> str | None:
    led = ledger.load()
    url = _ensure_entry(led, rp_id)
    page = await browsermod.ensure_browser_for(rp_id, persist=True)
    try:
        print(f"→ navigating to {url}")
        try:
            await page.goto(url, wait_until="domcontentloaded")
        except Exception as e:
            print(f"  ! navigation problem ({e}); drive the browser yourself")
        print("  Drive the site in the browser window. When you've reached an")
        print("  outcome (created the account, or hit a blocker), type it below.")
        outcome = _prompt_outcome(rp_id)
        if outcome is None:
            print(f"  – skipped {rp_id} (nothing recorded)")
            return None
        default = ("manually created via browser" if outcome == "captured"
                   else f"manually recorded: {outcome}")
        note = input(f"  note (Enter for '{default}')> ").strip() or default
        led = ledger.load()
        ledger.increment_attempts(led, rp_id)
        led = ledger.load()
        ledger.update_state(led, rp_id, outcome, note=note, extra={"source": "manual"})
        print(f"  ✓ ledger {rp_id} → {outcome}")
        return outcome
    finally:
        await browsermod.shutdown()


async def run(rp_ids: list[str]) -> int:
    tally: Counter = Counter()
    for i, rp_id in enumerate(rp_ids, 1):
        print(f"\n========== {i}/{len(rp_ids)}: {rp_id} ==========")
        try:
            out = await _process_one(rp_id)
        except KeyboardInterrupt:
            print("\n[interrupted]"); break
        if out:
            tally[out] += 1
    breakdown = ", ".join(f"{n} {k}" for k, n in tally.most_common()) or "nothing recorded"
    print(f"\n=== done: {sum(tally.values())}/{len(rp_ids)} recorded — {breakdown} ===")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--rp", help="one rp_id")
    g.add_argument("--rps", help="comma-separated rp_ids")
    a = ap.parse_args()
    ids = [a.rp] if a.rp else [x.strip() for x in a.rps.split(",") if x.strip()]
    return asyncio.run(run(ids))


if __name__ == "__main__":
    raise SystemExit(main())
