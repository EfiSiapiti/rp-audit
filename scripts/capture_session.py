"""Recover a captured session without re-running signup.

A signup run creates an account on an RP and writes sessions/<rp>.json
(cookies + localStorage), flipping the ledger entry to captured. When the
account already exists and its persistent profile under browser-profiles/<rp>
is already logged in, you don't want to re-walk the whole signup flow just to
grab a fresh session.

This script skips signup entirely: it reuses the same persistent-context
launch helper as the rest of the pipeline (src/lib/browser.py), opens the RP
on its already-logged-in profile, lets you eyeball that it's an authenticated
view, then captures storageState to sessions/<rp>.json. Optionally it flips
the ledger entry to captured.

Usage:
    python -m scripts.capture_session --rp bbn.music
    python -m scripts.capture_session --rp bbn.music --set-captured
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from src.lib import browser as browsermod
from src.lib import idb
from src.lib import ledger


def _origin_for(rp_id: str) -> str:
    """Where to navigate. Prefer the ledger's canonical_origin; fall back to
    https://<rp_id> so the script still works for an RP not in the ledger."""
    led = ledger.load()
    entry = led.get("entries", {}).get(rp_id, {})
    return entry.get("canonical_origin") or f"https://{rp_id}"


def _cookie_count(session_path: Path) -> int:
    try:
        data = json.loads(session_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    return len(data.get("cookies") or [])


async def capture_session_file(rp_id: str, page) -> int:
    """Write sessions/<rp_id>.json from the current browser context and return
    the captured cookie count.

    Uses Playwright's storageState (cookies + localStorage) and augments it with
    sessionStorage + IndexedDB via src/lib/idb.py, so RPs that keep their token
    there restore logged-in. The idb augmentation is best-effort and never fails
    the capture. Shared by capture_session.py (recovery) and manual_signup.py.
    """
    ctx = await browsermod.get_context()
    Path("sessions").mkdir(parents=True, exist_ok=True)
    session_path = Path(f"sessions/{rp_id}.json")
    await ctx.storage_state(path=str(session_path))
    try:
        summary = await idb.augment_session_file(page, session_path)
        if summary:
            print(f"  (captured {summary})")
    except Exception:
        pass
    return _cookie_count(session_path)


async def capture(rp_id: str, *, set_captured: bool) -> int:
    origin = _origin_for(rp_id)

    # Same launch path as the agent: per-RP persistent context, headed Chrome,
    # stealth patches — so args/channel/viewport match the rest of the pipeline.
    page = await browsermod.ensure_browser_for(rp_id)
    try:
        print(f"→ navigating to {origin}")
        await page.goto(origin, wait_until="domcontentloaded")

        print()
        print("  Confirm in the browser window that this is an AUTHENTICATED")
        print("  view (logged in — NOT a login/signup page) before capturing.")
        # input() blocks this thread; the headed browser stays interactive so
        # you can click around / navigate to an account page if needed first.
        input("  Press Enter to capture the session (Ctrl+C to abort)… ")

        session_path = Path(f"sessions/{rp_id}.json")
        n = await capture_session_file(rp_id, page)
        print(f"✓ wrote {session_path}")

        if n == 0:
            print(f"⚠ WARNING: {session_path} contains no cookies — the session "
                  f"is probably NOT usable. Check you were logged in, then rerun.")
        else:
            print(f"  ({n} cookie(s) captured)")

        if set_captured:
            led = ledger.load()
            if rp_id in led.get("entries", {}):
                ledger.update_state(led, rp_id, "captured",
                                    note="session recovered via scripts/capture_session.py",
                                    extra={"session_path": str(session_path)})
                print(f"✓ ledger entry {rp_id} → captured")
            else:
                print(f"⚠ {rp_id} not in ledger; skipped --set-captured")

        return 0 if n > 0 else 1
    finally:
        await browsermod.shutdown()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rp", required=True, help="RP id, e.g. bbn.music")
    ap.add_argument("--set-captured", action="store_true",
                    help="flip the ledger entry to 'captured' after a successful capture")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(capture(args.rp, set_captured=args.set_captured)))


if __name__ == "__main__":
    main()
