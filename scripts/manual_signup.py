"""Drive RPs by hand and record outcomes.

This is the signup path: it opens RPs one at a time in their per-RP browser
profile, you drive the page yourself, then type the outcome and any notes in
the console — and it records each across three tiers (the ledger, a per-run
artifact, and the batch log), flagged source=manual. Press Enter and it moves
to the next RP.

As a convenience it runs an "assist" bundle on the page — once on landing, and
again whenever you type `fill` at the prompt (do that after navigating to the
actual signup form). Assist, all best-effort and none of it clicking submit:

  1. dismisses a cookie/consent banner        (src/lib/consent.py)
  2. autofills the signup fields from identity.json  (src/lib/autofill.py)
  3. ticks required Terms/Privacy checkboxes, leaving marketing opt-ins alone
  4. scans for blockers (CAPTCHA, phone, geo, duplicate) and whether you're on
     an auth surface, and hints at the outcome   (src/lib/page_scan.py)

You still drive multi-step wizards, CAPTCHAs, and the final submit yourself.

Valid outcomes are defined in src/lib/outcomes.py (see _prompt_outcome). Every
outcome — `captured` included — is recorded the same way: ledger state, a
per-run artifact, and the batch log, plus a best-effort evidence screenshot.
The account itself stays logged in in its persistent browser profile under
browser-profiles/<rp_id>.

Usage:
    python -m scripts.manual_signup --batch 10        # next 10 pending RPs
    python -m scripts.manual_signup --rp notion.so     # one RP
    python -m scripts.manual_signup --rps a.com,b.com  # an explicit list
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.lib import autofill
from src.lib import browser as browsermod
from src.lib import consent
from src.lib import imap_poll
from src.lib import ledger
from src.lib import outcomes
from src.lib import page_scan
from src.lib import run_record
from src.lib.ledger import origin_for

PENDING_STATES = ("pending", "redo")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _default_note(outcome: str) -> str:
    if outcome == "captured":
        return "manually created via browser"
    return f"manually recorded: {outcome}"


def _collect_pending(n: int) -> list[str]:
    """The next N rp_ids in pending/redo state, in ledger order."""
    led = ledger.load()
    ids: list[str] = []
    for entry in led.get("entries", {}).values():
        if entry.get("state") in PENDING_STATES:
            ids.append(entry["rp_id"])
        if len(ids) >= n:
            break
    return ids


async def _assist(page, rp_id: str) -> None:
    """Everything we can do automatically on the current page, best-effort:
    dismiss a cookie banner, autofill the signup fields, tick required Terms/
    Privacy checkboxes, then scan for blockers and hint at the outcome. Every
    step is soft — a failure prints a warning and moves on; nothing here clicks
    submit, so you stay in control of the actual account creation.

    Each step is wrapped in a timeout: on a page that never settles (heavy
    consent iframes, redirect loops — e.g. onet.pl) a Playwright call into a
    still-navigating frame can block forever, which would freeze the whole run.
    A step that overruns is abandoned and we move on."""
    # 1. Cookie/consent banner.
    try:
        dismissed = await asyncio.wait_for(consent.dismiss_consent_banner(page), timeout=15)
        if dismissed:
            print(f"  ✓ consent banner dismissed ({dismissed})")
    except Exception as e:
        print(f"  ⚠ consent dismiss skipped ({type(e).__name__}); continuing")

    # 2. Autofill known signup fields.
    try:
        filled = await asyncio.wait_for(autofill.autofill(page, rp_id), timeout=20)
        if filled:
            parts = ", ".join(f"{k}={v}" for k, v in filled.items())
            print(f"  ✓ autofill: {parts}")
        else:
            print("  · autofill: nothing matched on this page")
    except Exception as e:
        print(f"  ⚠ autofill skipped ({type(e).__name__}); continuing")

    # 3. Tick required agreement checkboxes (leave marketing/newsletter alone).
    try:
        ticked = await asyncio.wait_for(autofill.tick_consent_checkboxes(page, rp_id), timeout=15)
        if ticked:
            print(f"  ✓ ticked agreement box(es): {'; '.join(ticked)}")
    except Exception as e:
        print(f"  ⚠ checkbox tick skipped ({type(e).__name__}); continuing")

    # 4. Read-only scan: blockers + whether we're on an auth surface.
    try:
        res = await asyncio.wait_for(page_scan.scan(page), timeout=20)
        for outcome, evidence in res.blockers:
            print(f"  ⚑ looks like '{outcome}' — {evidence}")
        if not res.blockers:
            if res.on_surface:
                print(f"  · on a login/signup surface ({res.surface_evidence})")
            else:
                print("  · no auth form detected yet — click through to the signup form, "
                      "then type 'fill'")
    except Exception as e:
        print(f"  ⚠ scan skipped ({type(e).__name__}); continuing")


async def _fetch_code(page, rp_id: str) -> None:
    """Poll IMAP for this RP's latest verification code/link and, if it's a code,
    try to type it into the page. Best-effort; prints what it found. Run this
    after you've submitted the form so the email has actually been sent."""
    print("  · polling IMAP for a verification code (up to 90s)…")
    try:
        # find_verification is blocking (it sleeps between polls) — run it off the
        # event loop so the browser stays responsive during the wait.
        found = await asyncio.to_thread(
            imap_poll.find_verification, rp_id,
            timeout_seconds=90, lookback_minutes=15,
        )
    except Exception as e:
        print(f"  ⚠ IMAP error: {e}")
        return
    if not found:
        print("  ✗ no code/link found — submit the form first, then retry 'code' "
              "once the email arrives")
        return
    if found.method == "code":
        print(f"  ✓ code: {found.value}   (from {found.sender}, "
              f"subj {found.subject[:50]!r})")
        try:
            filled = await autofill.fill_verification_code(page, found.value)
        except Exception as e:
            filled = False
            print(f"  ⚠ code autofill error: {e}")
        print("  ✓ typed the code into the page — check it, then submit" if filled
              else "  · no code field found — type it in by hand")
    else:
        print(f"  ✓ link: {found.value}")
        print("    open it in the browser window to continue verification.")


async def _prompt_outcome(rp_id: str, page) -> str | None:
    """Read a valid outcome from the console. Blank skips the RP (returns None).
    Typing `fill` re-runs the assist bundle (dismiss banner, autofill, tick
    consent, scan) against the current page — do that after you've navigated to
    the actual signup form. Typing `code` polls IMAP for the verification code
    and types it into the page — do that after you've submitted the form."""
    valid = sorted(outcomes.AGENT_OUTCOMES)
    print(f"\n  Outcome for {rp_id}:")
    print(f"    valid: {', '.join(valid)}")
    print("    ('fill' = re-run assist, 'code' = fetch email code via IMAP, "
          "blank = skip and leave pending)")
    while True:
        choice = input("  outcome> ").strip()
        if choice == "":
            return None
        if choice.lower() in ("fill", "f"):
            await _assist(page, rp_id)
            continue
        if choice.lower() in ("code", "otp"):
            await _fetch_code(page, rp_id)
            continue
        if choice in outcomes.AGENT_OUTCOMES:
            return choice
        print(f"  ! '{choice}' is not a valid outcome — try again "
              f"(or 'fill', 'code', or blank to skip)")


async def _record_outcome(rp_id: str, outcome: str, note: str, *,
                          page, origin: str, started: str) -> None:
    """Write the three recording tiers for one RP."""
    art_dir = Path("artifacts") / rp_id
    art_dir.mkdir(parents=True, exist_ok=True)

    # Best-effort evidence screenshot — the only artifact for a blocker, and
    # harmless for a capture. Never fails the record.
    artifacts: list[str] = []
    try:
        shot = art_dir / f"{_now()}-{outcome}.png"
        await page.screenshot(path=str(shot), full_page=True)
        artifacts.append(str(shot))
        print(f"  ✓ wrote {shot}")
    except Exception as e:
        print(f"  ⚠ screenshot failed (continuing): {e}")

    # Tier 1: ledger state + history.
    led = ledger.load()
    entry = led.get("entries", {}).get(rp_id, {})
    signup_url = entry.get("signup_url") or entry.get("canonical_origin") or origin
    attempts = entry.get("attempts", 0)
    if rp_id in led.get("entries", {}):
        attempts = ledger.increment_attempts(led, rp_id)
        extra = {"signup_url": signup_url, "source": "manual"}
        ledger.update_state(led, rp_id, outcome, note=note, extra=extra)
        print(f"  ✓ ledger {rp_id} → {outcome}")
    else:
        print(f"  ⚠ {rp_id} not in ledger; recorded artifact + batch log only")

    # Tier 2: per-run artifact, matching save_session_and_finish's shape.
    result = {
        "rp_id": rp_id,
        "started": started,
        "artifacts": artifacts,
        "finished": _now(),
        "outcome": outcome,
        "note": note,
        "signup_url": signup_url,
        "source": "manual",
    }
    result_path = art_dir / f"{_now()}-result.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"  ✓ wrote {result_path}")

    # Tier 3: batch-log line.
    run_record.append_batch_log(rp_id, outcome, attempts, note, source="manual")


async def _process_one(rp_id: str) -> str | None:
    """Open one RP, prompt for the outcome + note, and record it. Returns the
    recorded outcome, or None if the RP was skipped / not recorded."""
    origin = origin_for(rp_id)
    started = _now()
    page = await browsermod.ensure_browser_for(rp_id)
    print(f"→ navigating to {origin}")
    # Some RPs (heavy consent walls / redirect chains, e.g. onet.pl) never reach
    # 'domcontentloaded'. wait_until="commit" returns as soon as the server
    # responds, so the page keeps loading in the visible window while you drive,
    # and a bare goto can't hang the batch. Still bounded, and soft on failure.
    try:
        await page.goto(origin, wait_until="commit", timeout=30_000)
    except Exception as e:
        print(f"  ⚠ navigation didn't settle ({type(e).__name__}); continuing — "
              f"drive it manually, then type 'fill'")
    # Best-effort assist on the landing page. Most RPs need you to click through
    # to the signup form first — type 'fill' at the prompt to re-run assist
    # there. Nothing here clicks submit or fills a field you've already filled.
    await _assist(page, rp_id)
    print("  Drive the site in the browser window. Navigate to the signup form,")
    print("  type 'fill' to auto-handle it, 'code' to pull an email code via IMAP")
    print("  after submitting, finish the rest, then type the outcome below.")

    outcome = await _prompt_outcome(rp_id, page)
    if outcome is None:
        print(f"  – skipped {rp_id} (left pending)")
        return None
    raw = input(f"  note (Enter for '{_default_note(outcome)}')> ").strip()
    note = raw or _default_note(outcome)
    await _record_outcome(rp_id, outcome, note, page=page,
                          origin=origin, started=started)
    return outcome


def _print_summary(tally: Counter, processed: int, total: int) -> None:
    recorded = sum(tally.values())
    if tally:
        breakdown = ", ".join(f"{n} {oc}" for oc, n in tally.most_common())
    else:
        breakdown = "nothing recorded"
    skipped = processed - recorded
    tail = f" ({skipped} skipped)" if skipped else ""
    print(f"\n=== done: {processed}/{total} RP(s) processed — "
          f"{breakdown}{tail} ===")


async def run(rp_ids: list[str]) -> int:
    if not rp_ids:
        print("no RPs to process")
        return 0
    total = len(rp_ids)
    tally: Counter = Counter()
    processed = 0
    try:
        for i, rp_id in enumerate(rp_ids):
            print(f"\n========== {i + 1}/{total}: {rp_id} ==========")
            try:
                outcome = await _process_one(rp_id)
            except (KeyboardInterrupt, asyncio.CancelledError):
                print(f"\n(aborted at {rp_id})")
                _print_summary(tally, processed, total)
                return 1
            processed += 1
            if outcome:
                tally[outcome] += 1
            if i < total - 1:
                input("\n  Press Enter to open the next RP (Ctrl+C to stop)… ")
    finally:
        await browsermod.shutdown()
    _print_summary(tally, processed, total)
    return 0


def main() -> None:
    load_dotenv()  # IMAP_USER / IMAP_PASS for the 'code' command
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--rp", help="a single RP id, e.g. notion.so")
    g.add_argument("--rps", help="comma-separated RP ids, in order")
    g.add_argument("--batch", type=int, metavar="N",
                   help="the next N pending RPs from the ledger, in order")
    args = ap.parse_args()

    if args.rp:
        rp_ids = [args.rp]
    elif args.rps:
        rp_ids = [s.strip() for s in args.rps.split(",") if s.strip()]
    else:
        rp_ids = _collect_pending(args.batch)
        if not rp_ids:
            print("no pending RPs in the ledger")
            raise SystemExit(0)
        print(f"queued {len(rp_ids)} pending RP(s): {', '.join(rp_ids)}")

    raise SystemExit(asyncio.run(run(rp_ids)))


if __name__ == "__main__":
    main()
