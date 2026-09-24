"""Replay a recorded path on real Chrome, unattended.

Reads data/paths/<rp>.json (from record_path.py) and replays the login steps —
password from credentials.py, email OTP re-fetched live via imap_poll — on real
Chrome (channel="chrome", the browser that passes bot detection). Leaves the
window open at the end so you can inspect the logged-in state.

With --hook it also injects the pwned-xploit hook.js (no extension, real Chrome)
so a recorded Add-passkey step fabricates navigator.credentials.create() in-page,
and records the RP's response via src.hook.run's observation pipeline. Without
--hook it is a plain login replay.

Usage:
    python -m scripts.replay_passkey --rp github.com                       # login only
    python -m scripts.replay_passkey --rp github.com --hook --label ES256  # + passkey fabrication
"""
from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

from src.lib import browser, credentials, imap_poll, ledger, webauthn_params
from src.hook import run as hookrun
from scripts import hook_bridge

PATHS_DIR = Path("data/paths")
CLICK_DELAY_MS = 2000        # pause after a click so the page (and any SPA nav) settles
POST_CLICK_NAV_MS = 10000     # longer pause when the NEXT step navigates, so a login
                             # redirect finishes establishing the session first
DEFAULT_HOOK = "../pwned-xploit/pwned-xploit/hook.js"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _frame_for(page, frame_url: str | None):
    if not frame_url or frame_url == page.url:
        return page
    for fr in page.frames:
        if fr.url == frame_url:
            return fr
    return page  # fall back to main frame


async def _resolve_fill(field: str, rp_id: str, literal, run_started, used_otps=None) -> str | None:
    if field == "email":
        return credentials.resolve("email", rp_id=rp_id)
    if field == "password":
        return credentials.resolve("password", rp_id=rp_id)
    if field == "otp":
        secs = max(30, int((datetime.now(timezone.utc) - run_started).total_seconds()) + 15)
        found = await asyncio.to_thread(
            imap_poll.find_verification, rp_id, newer_than_seconds=secs,
            exclude_values=list(used_otps or []), prefer_code=True)
        if found:  # diagnostic: show exactly what IMAP matched, so we can pattern it
            print(f"    · IMAP match: method={found.method}  from={found.sender!r}")
            print(f"      subject: {found.subject!r}")
            print(f"      excerpt: {found.raw_excerpt[:200]!r}")
        else:
            print("    · IMAP: no email matched this RP (check sender/subject relation)")
        if found and found.method == "code" and found.value:
            if used_otps is not None:
                used_otps.append(found.value)   # never reuse this code later in the run
            return found.value
        if found and found.method == "link":
            print("    ⚠ IMAP resolved a magic LINK, not a code — see subject/excerpt above")
        else:
            print("    ⚠ no OTP code found — leaving field blank")
        return None
    return literal  # 'other'


async def _locate(active_pg, ctx, main_pg, selector, tries=27):
    """Find the locator for `selector` across every open window/frame, polling
    for a VISIBLE match (~8s) so a modal/popup that renders a moment after the
    prior click is found. Prefers a match inside an open dialog, then the LAST
    visible match in the DOM (a modal renders after the page's now-hidden
    duplicate), then any match; else the main page (Playwright auto-waits)."""
    def _order():
        order = [active_pg]
        if ctx is not None:
            order += [p for p in ctx.pages if p is not active_pg]
        if main_pg not in order:
            order.append(main_pg)
        return order

    def _scopes(pg):
        try:
            return [pg, *pg.frames]
        except Exception:
            return [pg]

    async def _in_dialog():
        for pg in _order():
            for c in _scopes(pg):
                try:
                    dlg = c.locator('[role="dialog"],[aria-modal="true"]').last
                    if await dlg.count():
                        el = dlg.locator(selector).first
                        if await el.count() and await el.is_visible():
                            return el
                except Exception:
                    continue
        return None

    async def _last_visible():
        for pg in _order():
            for c in _scopes(pg):
                try:
                    m = c.locator(selector)
                    for idx in range(await m.count() - 1, -1, -1):  # last→first
                        el = m.nth(idx)
                        if await el.is_visible():
                            return el
                except Exception:
                    continue
        return None

    for _ in range(tries):
        loc = await _in_dialog() or await _last_visible()
        if loc:
            return loc
        await main_pg.wait_for_timeout(300)
    # fallback: any match at all, else the main page
    for pg in _order():
        for c in _scopes(pg):
            try:
                loc = c.locator(selector).first
                if await loc.count():
                    return loc
            except Exception:
                continue
    return main_pg.locator(selector).first


async def _replay_steps(page, steps: list[dict], rp_id: str, run_started,
                        abort_check=None, ctx=None) -> None:
    # Track the active window: a popup that opens becomes active (so its steps
    # target it even when it shares the main page's URL); reverts to main on close.
    active = {"pg": page}
    used_otps: list[str] = []  # codes already consumed this run — never reuse one
    if ctx is not None:
        def _on_page(p):
            active["pg"] = p
            p.on("close", lambda: active.__setitem__("pg", page))
        ctx.on("page", _on_page)

    for i, step in enumerate(steps, 1):
        kind = step.get("kind")
        try:
            if kind == "navigate":
                url = step.get("url") or ""
                if url and not (page.url or "").split("#")[0].startswith(url.split("#")[0]):
                    await page.goto(url, wait_until="domcontentloaded", timeout=60_000)
                    # If a prior login is still settling, the RP bounces this nav
                    # to its login page — wait and retry a few times before moving on.
                    tgt_login = ("login" in url.lower() or "signin" in url.lower())
                    for _ in range(4):
                        cur = (page.url or "").lower()
                        if not tgt_login and ("login" in cur or "signin" in cur or "login.php" in cur):
                            print(f"       bounced to {page.url} — login still settling, retrying nav…")
                            await page.wait_for_timeout(4000)
                            try:
                                await page.goto(url, wait_until="domcontentloaded", timeout=60_000)
                            except Exception:
                                break
                        else:
                            break
            elif kind == "click":
                before = set(ctx.pages) if ctx else set()
                loc = await _locate(active["pg"], ctx, page, step["selector"])
                try:
                    await loc.click(timeout=8_000)
                except Exception:
                    # Actionability failed (e.g. Facebook's overlay-covered
                    # buttons) — force the click at the element's center.
                    await loc.click(timeout=6_000, force=True)
                # Wait for any navigation the click triggered (login redirect /
                # popup) to finish loading before the next step runs.
                try:
                    await page.wait_for_load_state("load", timeout=15_000)
                except Exception:
                    pass
                if ctx:
                    for np in [p for p in ctx.pages if p not in before]:
                        try:
                            await np.wait_for_load_state("load", timeout=15_000)
                        except Exception:
                            pass
                # If the next step is a goto, give the session extra time to
                # settle so we don't navigate while still mid-login.
                next_nav = i < len(steps) and steps[i].get("kind") == "navigate"
                await page.wait_for_timeout(POST_CLICK_NAV_MS if next_nav else CLICK_DELAY_MS)
            elif kind == "fill":
                loc = await _locate(active["pg"], ctx, page, step["selector"])
                val = await _resolve_fill(step.get("field"), rp_id, step.get("value"),
                                          run_started, used_otps=used_otps)
                if val is not None:
                    await loc.fill(val, timeout=15_000)
            print(f"    [{i}/{len(steps)}] {kind} ok")
        except Exception as e:
            print(f"    [{i}/{len(steps)}] {kind} FAILED: {str(e).splitlines()[0][:90]}")
            if kind == "click":
                print("    ⏹ click failed — stopping replay (won't proceed on a broken step)")
                return
        if abort_check:
            reason = abort_check()
            if reason:
                print(f"    ⏹ stopping replay: {reason} (skipping the rest)")
                return


def load_recorded(rp_id: str, path: str | None) -> dict:
    path_file = Path(path) if path else PATHS_DIR / f"{rp_id}.json"
    if not path_file.is_file():
        raise SystemExit(f"recorded path not found: {path_file} (run record_path.py first)")
    return json.loads(path_file.read_text(encoding="utf-8"))


def load_steps(rp_id: str, path: str | None) -> list[dict]:
    return load_recorded(rp_id, path).get("steps") or []


def _url_matches(cur: str, target: str) -> bool:
    """True if `cur` is the same page as `target` (scheme+host+path, ignoring
    query/hash) — used to check re-login landed on the recorded success URL."""
    if not cur or not target:
        return False
    a, b = urlparse(cur), urlparse(target)
    return (a.scheme, a.netloc, a.path.rstrip("/")) == (b.scheme, b.netloc, b.path.rstrip("/"))


def _event_types(captured: dict) -> set[str]:
    return {e.get("eventType") for e in (captured.get("console_events") or [])}


def _register_failed(captured: dict) -> str | None:
    """Abort signal: the create() ceremony failed client-side (so don't attempt
    the logout/re-login steps that follow)."""
    if "create.failed" in _event_types(captured):
        return "registration create() failed"
    return None


def _register_ok(captured: dict) -> bool:
    return bool(_event_types(captured) & {"fabrication.success", "create.success"})


async def _record(captured: dict, ctx, artifacts_dir: Path, rp_id: str,
                  label: str | None, run_started_iso: str, reauth_ok=None) -> None:
    """Collect the hook log, dump artifacts, persist params — reuses src.hook.run.
    Observation is via the injected hook's console events (the storage bridge is
    absent without the extension), folded into the observer log as a (console) frame."""
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
            since_iso=run_started_iso, rp_id=rp_id)
        if not params:
            print("  no create.called event captured — did the Add-passkey step run + hook fire?")
            return
        ledger.record_advertised_params(rp_id, params, artifact=str(artifacts_dir))
        led = ledger.load()
        stored = led.get("entries", {}).get(rp_id, {}).get("advertised_params", params)
        webauthn_params.upsert_status_csv(rp_id, stored)
        exp_row = webauthn_params.flatten_experiment_columns(
            stored, rp_id=rp_id, label=label, artifact=str(artifacts_dir))
        exp_row["reauth_ok"] = "" if reauth_ok is None else str(reauth_ok)
        webauthn_params.append_experiment(exp_row)
        print(f"  ✓ recorded → ledger[{rp_id}] + {webauthn_params.DEFAULT_STATUS_CSV} "
              f"+ {webauthn_params.DEFAULT_EXPERIMENTS_CSV} "
              f"(label={label or '-'}, result={exp_row['srv_result'] or exp_row['fab_outcome'] or '-'}, "
              f"reauth_ok={exp_row['reauth_ok'] or '-'})")
    except Exception as e:
        print(f"  record failed: {e}")


async def main() -> None:
    ap = argparse.ArgumentParser(description="Replay a recorded login/passkey path on real Chrome")
    ap.add_argument("--rp", required=True)
    ap.add_argument("--path", default=None, help="recorded path json (default data/paths/<rp>.json)")
    ap.add_argument("--hook", nargs="?", const=DEFAULT_HOOK, default=None,
                    help="inject pwned-xploit hook.js to fabricate create() on the recorded "
                         f"Add-passkey step and record the result; bare --hook uses {DEFAULT_HOOK}")
    ap.add_argument("--label", default=None, help="experiment label for data/experiments.csv")
    args = ap.parse_args()

    if args.hook and not Path(args.hook).is_file():
        raise SystemExit(f"hook.js not found: {args.hook}")
    load_dotenv()
    recorded = load_recorded(args.rp, args.path)
    steps = recorded.get("steps") or []
    success_url = recorded.get("success_url")
    run_started = datetime.now(timezone.utc)

    mode = "passkey" if args.hook else "login"
    print(f"\n→ replay {mode} for {args.rp} ({len(steps)} steps, real Chrome)")
    page = await browser.ensure_browser_for(args.rp)  # real Chrome, no extension
    ctx = await browser.get_context()

    captured = None
    abort_check = None
    if args.hook:
        # Inject the fabrication hook + persistence bridge into the MAIN world
        # before any RP navigation, then observe. The bridge (hook_bridge) carries
        # the fabricated private key to data/fab_keys.json so a key registered in
        # one run can authenticate in a later run.
        await hook_bridge.inject_hook(ctx, args.hook)
        print(f"  injected fabrication hook + persistence bridge: {args.hook}")
        captured = hookrun._new_capture()
        hookrun._attach_listeners(page, captured)
        ctx.on("page", lambda p: hookrun._attach_listeners(p, captured))
        # Stop before the logout/re-login steps if registration fails client-side.
        abort_check = lambda: _register_failed(captured)  # noqa: E731

    await _replay_steps(page, steps, args.rp, run_started, abort_check=abort_check, ctx=ctx)

    if args.hook:
        await page.wait_for_timeout(1500)  # let fabrication.* + finish settle
        # Re-login verdict: only when registration succeeded and we have a
        # recorded success URL to compare the final landing against.
        reauth_ok = None
        if not _register_ok(captured):
            print("  registration did not succeed — skipping re-login verdict")
        elif success_url:
            reauth_ok = _url_matches(page.url, success_url)
            print(f"  re-login verdict: reauth_ok={reauth_ok}  "
                  f"(landed {page.url!r} vs success {success_url!r})")
        else:
            print("  no success_url recorded — re-login verdict unavailable")
        artifacts_dir = Path(f"artifacts/passkey/{args.rp}/{args.label or 'run'}/{_ts()}")
        await _record(captured, ctx, artifacts_dir, args.rp, args.label,
                      run_started.isoformat(), reauth_ok=reauth_ok)

    print(f"\n✓ {mode} replay done — window left open")
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
