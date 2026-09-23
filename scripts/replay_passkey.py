"""Replay a recorded path on real Chrome, unattended.

Reads data/paths/<rp>.json (from record_path.py) and replays the login steps —
password from credentials.py, email OTP re-fetched live via imap_poll — on real
Chrome (channel="chrome", the browser that passes bot detection). Leaves the
window open at the end so you can inspect the logged-in state.

Login-only for now. The passkey ceremony belongs here too and will be added
later — both registration (navigator.credentials.create) and authentication
(navigator.credentials.get) — reusing the step-replay helpers below
(_replay_steps / _resolve_fill / _frame_for / load_steps).

Usage:
    python -m scripts.replay_passkey --rp github.com
"""
from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.lib import browser, credentials, imap_poll

PATHS_DIR = Path("data/paths")
CLICK_DELAY_MS = 2000  # pause after each click so the page (and any SPA nav) settles


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _frame_for(page, frame_url: str | None):
    if not frame_url or frame_url == page.url:
        return page
    for fr in page.frames:
        if fr.url == frame_url:
            return fr
    return page  # fall back to main frame


async def _resolve_fill(field: str, rp_id: str, literal, run_started) -> str | None:
    if field == "email":
        return credentials.resolve("email", rp_id=rp_id)
    if field == "password":
        return credentials.resolve("password", rp_id=rp_id)
    if field == "otp":
        secs = max(30, int((datetime.now(timezone.utc) - run_started).total_seconds()) + 15)
        found = await asyncio.to_thread(
            imap_poll.find_verification, rp_id, newer_than_seconds=secs)
        if found and found.method == "code" and found.value:
            return found.value
        if found and found.method == "link":
            print("    ⚠ IMAP found a magic LINK, not a code — this path needs a code field")
        else:
            print("    ⚠ no OTP found via IMAP — leaving field blank")
        return None
    return literal  # 'other'


async def _replay_steps(page, steps: list[dict], rp_id: str, run_started) -> None:
    for i, step in enumerate(steps, 1):
        kind = step.get("kind")
        try:
            if kind == "navigate":
                url = step.get("url") or ""
                if url and not (page.url or "").split("#")[0].startswith(url.split("#")[0]):
                    await page.goto(url, wait_until="domcontentloaded", timeout=60_000)
            elif kind == "click":
                tgt = _frame_for(page, step.get("frame_url"))
                await tgt.locator(step["selector"]).first.click(timeout=15_000)
                await page.wait_for_timeout(CLICK_DELAY_MS)
            elif kind == "fill":
                tgt = _frame_for(page, step.get("frame_url"))
                val = await _resolve_fill(step.get("field"), rp_id, step.get("value"), run_started)
                if val is not None:
                    await tgt.locator(step["selector"]).first.fill(val, timeout=15_000)
            print(f"    [{i}/{len(steps)}] {kind} ok")
        except Exception as e:
            print(f"    [{i}/{len(steps)}] {kind} FAILED: {str(e).splitlines()[0][:90]}")


def load_steps(rp_id: str, path: str | None) -> list[dict]:
    path_file = Path(path) if path else PATHS_DIR / f"{rp_id}.json"
    if not path_file.is_file():
        raise SystemExit(f"recorded path not found: {path_file} (run record_path.py first)")
    return json.loads(path_file.read_text(encoding="utf-8")).get("steps") or []


async def main() -> None:
    ap = argparse.ArgumentParser(description="Replay a recorded login on real Chrome")
    ap.add_argument("--rp", required=True)
    ap.add_argument("--path", default=None, help="recorded path json (default data/paths/<rp>.json)")
    args = ap.parse_args()

    load_dotenv()
    steps = load_steps(args.rp, args.path)
    run_started = datetime.now(timezone.utc)

    print(f"\n→ replay login for {args.rp} ({len(steps)} steps, real Chrome)")
    page = await browser.ensure_browser_for(args.rp)  # no extension → real Chrome
    await _replay_steps(page, steps, args.rp, run_started)

    print("\n✓ login replay done — window left open")
    try:
        await asyncio.to_thread(input, "  press Enter to close the browser… ")
    except (KeyboardInterrupt, EOFError):
        pass
    await browser.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
