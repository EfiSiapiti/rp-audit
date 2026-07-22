"""Attempt an RP in a plain, real Chrome — no Playwright-launched browser.

For heavily-defended RPs (Discord, X, TikTok, Canva, …) the Playwright launch is
fingerprinted and their bot-detection (hCaptcha etc.) loops forever — you get
stuck on a spinning "Are you human?" that never resolves. This opens the site in
a normal Chrome that *you* launched — no automation switches, sandbox on, its own
clean profile — so you have the best shot at getting through the CAPTCHA by hand.

Playwright is used only at the very end, and only to grab an evidence screenshot
over CDP (the browser is never Playwright-controlled during signup).

Flow, per RP:
1. Launches your system Chrome via subprocess with a dedicated per-RP profile
   under browser-profiles-manual/<rp_id> and --remote-debugging-port.
2. You drive the signup by hand and solve any CAPTCHA.
3. Press Enter, type the outcome. Every outcome is recorded across the ledger,
   an artifact, and the batch log (source=manual-chrome), with a best-effort
   evidence screenshot grabbed over CDP.

Usage:
    python -m scripts.manual_launch --rp discord.com
    python -m scripts.manual_launch --rps discord.com,x.com,tiktok.com
    python -m scripts.manual_launch --batch 10                 # next 10 pending RPs
    python -m scripts.manual_launch --state captcha-blocked   # retry every blocked RP
    python -m scripts.manual_launch --state captcha-blocked --state failed
    python -m scripts.manual_launch --rp discord.com --chrome "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright

from src.lib import ledger
from src.lib import outcomes
from src.lib import run_record
from src.lib.ledger import origin_for

# Kept separate from the Playwright profiles (browser-profiles/) on purpose: a
# fresh, automation-free profile is the whole point of this path.
MANUAL_PROFILES_ROOT = Path("browser-profiles-manual")
SOURCE = "manual-chrome"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _default_note(outcome: str) -> str:
    if outcome == "captured":
        return "manually created in real Chrome"
    return f"manually recorded (real Chrome): {outcome}"


# --- locating + launching real Chrome ------------------------------------

def _find_chrome(explicit: str | None) -> str:
    """Locate a real Chrome/Chromium executable, or exit with guidance."""
    if explicit:
        if not Path(explicit).exists():
            raise SystemExit(f"--chrome path does not exist: {explicit}")
        return explicit

    candidates: list[Path] = []
    for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if base:
            candidates.append(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe")
    # macOS
    candidates.append(Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
    # PATH (Linux / anything on PATH)
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))

    for c in candidates:
        if c and c.exists():
            return str(c)
    raise SystemExit(
        "could not find Chrome automatically — pass --chrome <path-to-chrome.exe>"
    )


def _free_port(preferred: int) -> int:
    """Return `preferred` if free, else the next free port in a small range."""
    for port in [preferred, *range(preferred + 1, preferred + 40)]:
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred


def _launch_chrome(chrome: str, port: int, profile_dir: Path, origin: str) -> subprocess.Popen:
    """Launch a real Chrome window on its own profile + debugging port.

    Deliberately NOT passing --no-sandbox or any automation switch: a clean,
    normal Chrome is what gets past the bot-detection.
    """
    profile_dir.mkdir(parents=True, exist_ok=True)
    args = [
        chrome,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir.absolute()}",
        "--no-first-run",
        "--no-default-browser-check",
        "--new-window",
        origin,
    ]
    return subprocess.Popen(args)


def _wait_for_cdp(port: int, timeout: float = 30.0) -> str:
    """Block until Chrome's DevTools endpoint answers, then return its base URL."""
    probe = f"http://127.0.0.1:{port}/json/version"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(probe, timeout=2) as r:
                json.loads(r.read())  # ensure it's really up
                return f"http://127.0.0.1:{port}"
        except Exception:
            time.sleep(0.5)
    raise SystemExit(f"Chrome DevTools endpoint on port {port} did not come up in {timeout:.0f}s")


# --- reading the session back over CDP (read-only; never drives the page) --

def _pick_page(ctx, origin: str):
    """Choose the tab to read from: prefer one on the RP's origin host, else the
    first http(s) tab, else open a blank one."""
    host = (urlparse(origin).hostname or "").lower()
    http_pages = [p for p in ctx.pages if (p.url or "").startswith(("http://", "https://"))]
    for p in http_pages:
        if host and host in (urlparse(p.url).hostname or "").lower():
            return p
    if http_pages:
        return http_pages[0]
    if ctx.pages:
        return ctx.pages[0]
    return None


async def _grab(rp_id: str, origin: str, cdp_url: str) -> str | None:
    """Connect over CDP to take an evidence screenshot. Returns the screenshot
    path, or None.

    Never closes the real Chrome — it just disconnects when the block exits.
    """
    art_dir = Path("artifacts") / rp_id
    art_dir.mkdir(parents=True, exist_ok=True)
    shot: str | None = None

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.connect_over_cdp(cdp_url)
        except Exception as e:
            print(f"  ⚠ could not connect over CDP for the evidence screenshot: {e}")
            return None
        ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
        page = _pick_page(ctx, origin)

        if page is not None:
            try:
                shot = str(art_dir / f"{_now()}-evidence.png")
                await page.screenshot(path=shot, full_page=True)
                print(f"  ✓ wrote {shot}")
            except Exception as e:
                print(f"  ⚠ screenshot failed (continuing): {e}")
                shot = None
    return shot


# --- recording (three tiers, mirrors manual_signup) -----------------------

def _record(rp_id: str, outcome: str, note: str, *, origin: str, started: str,
            artifacts: list[str]) -> None:
    led = ledger.load()
    entry = led.get("entries", {}).get(rp_id, {})
    signup_url = entry.get("signup_url") or entry.get("canonical_origin") or origin
    attempts = entry.get("attempts", 0)

    if rp_id in led.get("entries", {}):
        attempts = ledger.increment_attempts(led, rp_id)
        extra = {"signup_url": signup_url, "source": SOURCE}
        ledger.update_state(led, rp_id, outcome, note=note, extra=extra)
        print(f"  ✓ ledger {rp_id} → {outcome}")
    else:
        print(f"  ⚠ {rp_id} not in ledger; recorded artifact + batch log only")

    art_dir = Path("artifacts") / rp_id
    art_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "rp_id": rp_id,
        "started": started,
        "artifacts": artifacts,
        "finished": _now(),
        "outcome": outcome,
        "note": note,
        "signup_url": signup_url,
        "source": SOURCE,
    }
    result_path = art_dir / f"{_now()}-result.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"  ✓ wrote {result_path}")

    run_record.append_batch_log(rp_id, outcome, attempts, note, source=SOURCE)


def _prompt_outcome(rp_id: str) -> str | None:
    valid = sorted(outcomes.AGENT_OUTCOMES)
    print(f"\n  Outcome for {rp_id}:")
    print(f"    valid: {', '.join(valid)}")
    print("    (blank = skip and leave the ledger state unchanged)")
    while True:
        choice = input("  outcome> ").strip()
        if choice == "":
            return None
        if choice in outcomes.AGENT_OUTCOMES:
            return choice
        print(f"  ! '{choice}' is not a valid outcome — try again (or blank to skip)")


# --- per-RP + batch driver ------------------------------------------------

async def _process_one(chrome: str, rp_id: str, port_pref: int) -> str | None:
    origin = origin_for(rp_id)
    started = _now()
    port = _free_port(port_pref)
    profile_dir = MANUAL_PROFILES_ROOT / rp_id

    print(f"→ launching real Chrome (no Playwright automation) at {origin}")
    print(f"  profile: {profile_dir}   debug-port: {port}")
    proc = _launch_chrome(chrome, port, profile_dir, origin)
    try:
        _wait_for_cdp(port)
        print("  Chrome is up. Drive the signup by hand — solve the CAPTCHA, submit,")
        print("  and get to a logged-in view. Then come back here.")

        outcome = _prompt_outcome(rp_id)
        if outcome is None:
            print(f"  – skipped {rp_id} (ledger unchanged)")
            return None
        raw = input(f"  note (Enter for '{_default_note(outcome)}')> ").strip()
        note = raw or _default_note(outcome)

        cdp_url = f"http://127.0.0.1:{port}"
        shot = await _grab(rp_id, origin, cdp_url)

        artifacts = [shot] if shot else []
        _record(rp_id, outcome, note, origin=origin, started=started, artifacts=artifacts)
        return outcome
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


PENDING_STATES = ("pending", "redo")


def _collect_pending(n: int) -> list[str]:
    """The next N rp_ids in pending/redo state, in ledger order."""
    led = ledger.load()
    ids: list[str] = []
    for e in led.get("entries", {}).values():
        if e.get("state") in PENDING_STATES:
            ids.append(e["rp_id"])
        if len(ids) >= n:
            break
    return ids


def _collect(args) -> list[str]:
    if args.rp:
        return [args.rp]
    if args.rps:
        return [s.strip() for s in args.rps.split(",") if s.strip()]
    if args.batch:
        return _collect_pending(args.batch)
    # --state (repeatable): every RP currently in one of these states.
    wanted = set(args.state or [])
    led = ledger.load()
    return [e["rp_id"] for e in led.get("entries", {}).values()
            if e.get("state") in wanted]


async def _run(chrome: str, rp_ids: list[str], port_pref: int) -> int:
    total = len(rp_ids)
    tally: Counter = Counter()
    processed = 0
    for i, rp_id in enumerate(rp_ids):
        print(f"\n========== {i + 1}/{total}: {rp_id} ==========")
        try:
            outcome = await _process_one(chrome, rp_id, port_pref)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print(f"\n(aborted at {rp_id})")
            break
        processed += 1
        if outcome:
            tally[outcome] += 1
        if i < total - 1:
            input("\n  Press Enter to launch the next RP (Ctrl+C to stop)… ")

    breakdown = ", ".join(f"{n} {oc}" for oc, n in tally.most_common()) or "nothing recorded"
    print(f"\n=== done: {processed}/{total} processed — {breakdown} ===")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--rp", help="a single RP id, e.g. discord.com")
    g.add_argument("--rps", help="comma-separated RP ids, in order")
    g.add_argument("--state", action="append", metavar="STATE",
                   help="every RP currently in this ledger state (repeatable), "
                        "e.g. --state captcha-blocked")
    g.add_argument("--batch", type=int, metavar="N",
                   help="the next N pending/redo RPs from the ledger, in order")
    ap.add_argument("--chrome", help="path to chrome.exe (auto-detected if omitted)")
    ap.add_argument("--port", type=int, default=9222,
                    help="preferred remote-debugging port (default 9222; auto-bumps if busy)")
    args = ap.parse_args()

    chrome = _find_chrome(args.chrome)
    rp_ids = _collect(args)
    if not rp_ids:
        print("no matching RPs.")
        raise SystemExit(0)
    print(f"using Chrome: {chrome}")
    print(f"queued {len(rp_ids)} RP(s): {', '.join(rp_ids)}")

    raise SystemExit(asyncio.run(_run(chrome, rp_ids, args.port)))


if __name__ == "__main__":
    main()
