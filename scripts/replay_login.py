"""Replay a recorded click path across multiple hook controls, unattended.

Reads data/paths/<rp>.json (from record_path.py) and, for each control (a
separate unpacked extension dir), relaunches Chromium with that control's hook,
replays the recorded login + add-passkey steps (password from credentials.py,
email OTP re-fetched live via imap_poll), lets hook.js fabricate, then records
the result with the same pipeline as src.hook.run.

Fresh ephemeral profile per control ⇒ a real re-login each run.

RUN THIS YOURSELF against YOUR OWN account.

Usage:
    python -m scripts.replay_controls --rp canva.com \
        --controls rsa-legit=../pwned-xploit/pwned-xploit/rsa-legit,\
rsa-e3=../pwned-xploit/pwned-xploit/rsa-e3,\
rsa-small-n=../pwned-xploit/pwned-xploit/rsa-small-n
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.lib import browser, credentials, imap_poll, ledger, webauthn_params
from src.hook import run as hookrun

PATHS_DIR = Path("data/paths")
CLICK_DELAY_MS = 2000  # pause after each click so the page (and any SPA nav) settles


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


async def _record(captured: dict, ctx, artifacts_dir: Path, rp_id: str,
                  label: str | None, run_started_iso: str) -> None:
    """Collect the hook log, dump artifacts, and persist params (same pipeline
    as src.hook.run). For login-only runs there is no create.called event, so
    this simply reports 'nothing to record'."""
    try:
        live = await hookrun._collect_observer_logs(ctx)
        persisted = await hookrun._load_persisted_logs(ctx)
        pending = list(captured.get("_console_tasks") or [])
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        ce = captured.get("console_events") or []
        frames = hookrun._dedupe_frame_blocks((live or []) + (persisted or []))
        if ce:
            frames = frames + [{"frame_url": "(console)", "entries": ce}]
        captured["observer_log"] = frames or None
    except Exception as e:
        print(f"  observer-log collection failed: {e}")

    try:
        hookrun._dump_capture(captured, artifacts_dir)
    except Exception as e:
        print(f"  capture dump failed: {e}")

    try:
        params = webauthn_params.extract_advertised(
            captured.get("observer_log"),
            {"requests": captured.get("requests"), "responses": captured.get("responses")},
            since_iso=run_started_iso,
            rp_id=rp_id,
        )
        if not params:
            print("  no create.called event captured — nothing to record")
            return
        ledger.record_advertised_params(rp_id, params, artifact=str(artifacts_dir))
        led = ledger.load()
        stored = led.get("entries", {}).get(rp_id, {}).get("advertised_params", params)
        webauthn_params.upsert_status_csv(rp_id, stored)
        exp_row = webauthn_params.flatten_experiment_columns(
            stored, rp_id=rp_id, label=label, artifact=str(artifacts_dir))
        webauthn_params.append_experiment(exp_row)
        print(f"  ✓ recorded → ledger[{rp_id}] + {webauthn_params.DEFAULT_STATUS_CSV} "
              f"+ {webauthn_params.DEFAULT_EXPERIMENTS_CSV} "
              f"(label={label or '-'}, result={exp_row['srv_result'] or exp_row['fab_outcome'] or '-'})")
    except Exception as e:
        print(f"  record failed: {e}")


def _parse_controls(spec: str) -> list[tuple[str, str]]:
    out = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            label, d = item.split("=", 1)
        else:
            d = item
            label = Path(d).name
        d = d.strip()
        # sentinel: no extension → real Chrome (e.g. login-only replay)
        ext = None if d.lower() in ("none", "-", "") else d
        out.append((label.strip(), ext))
    return out


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
        # Poll IMAP for a code that arrived during THIS replay.
        secs = max(30, int((datetime.now(timezone.utc) - run_started).total_seconds()) + 15)
        found = await asyncio.to_thread(
            imap_poll.find_verification, rp_id, newer_than_seconds=secs)
        # FoundVerification: .method ('code'|'link') + .value (the extracted code/url).
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


async def main() -> None:
    ap = argparse.ArgumentParser(description="Replay a click path across hook controls")
    ap.add_argument("--rp", required=True)
    ap.add_argument("--path", default=None, help="recorded path json (default data/paths/<rp>.json)")
    ap.add_argument("--controls", default="login=none",
                    help="comma list of label=extdir per control; use 'none' for no "
                         "extension / real Chrome (default: a single login-only run on real Chrome)")
    args = ap.parse_args()

    load_dotenv()
    import json
    path_file = Path(args.path) if args.path else PATHS_DIR / f"{args.rp}.json"
    if not path_file.is_file():
        raise SystemExit(f"recorded path not found: {path_file} (run record_path.py first)")
    recorded = json.loads(path_file.read_text(encoding="utf-8"))
    steps = recorded.get("steps") or []
    controls = _parse_controls(args.controls)
    for _, d in controls:
        if d and not Path(d).is_dir():
            raise SystemExit(f"control extension dir not found: {d}")

    print(f"\n→ replay {len(steps)} steps × {len(controls)} controls for {args.rp}")
    for idx, (label, ext_dir) in enumerate(controls, 1):
        print(f"\n══ control {idx}/{len(controls)}: {label}  ({ext_dir}) ══")
        run_started = datetime.now(timezone.utc)
        artifacts_dir = Path(f"artifacts/replay/{args.rp}/{label}/{_ts()}")
        page = await browser.ensure_browser_for(args.rp, extension_dir=ext_dir)
        ctx = await browser.get_context()
        captured = hookrun._new_capture()
        hookrun._attach_listeners(page, captured)

        await _replay_steps(page, steps, args.rp, run_started)
        await page.wait_for_timeout(1500)  # let fabrication.* + finish settle
        await _record(captured, ctx, artifacts_dir, args.rp, label, run_started.isoformat())
        if idx < len(controls):
            await browser.shutdown()  # wipe profile → next control re-logins

    # Leave the last window open so you can inspect the logged-in state; it
    # stays up (temp profile intact) until you press Enter here.
    print("\n✓ all controls done — window left open")
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
