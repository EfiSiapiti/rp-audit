"""Hook runner — attach to a user-managed Chrome over CDP for hook.js observation runs.

Setup (one-time):
1. Launch Chrome with a dedicated profile + remote debugging port:
       & "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" `
           --remote-debugging-port=9222 `
           --user-data-dir="C:\\chrome-hook-profile"
2. In that Chrome, go to chrome://extensions, enable Developer mode,
   click "Load unpacked", and load your hook.js extension dir.

What this script does:
1. Connects to your already-running Chrome via CDP (no launch)
2. Optionally restores cookies + localStorage from sessions/<rp>.json
3. Optionally navigates the active page to --enroll-url
4. Captures network + console traffic on the active page
5. Waits — you drive the passkey registration manually
6. On Enter, dumps captured traffic to artifacts

Usage:
    python -m src.hook.run --rp notion.so --enroll-url https://www.notion.so/my-account
    python -m src.hook.run --rp notion.so --no-restore    # skip session injection
    python -m src.hook.run --rp notion.so --no-localstorage  # cookies only

Notes:
- Restored sessions are written into your live Chrome profile, so they
  persist after the script exits. You only need --restore once per RP;
  subsequent runs can use --no-restore.
- This means real Chrome fingerprint, no CAPTCHA hell, no Playwright contamination.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from playwright.async_api import async_playwright, Page, Request, Response, BrowserContext

from src.lib import idb, ledger, webauthn_params


load_dotenv()


DEFAULT_CDP_URL = "http://localhost:9222"

# URLs whose request/response we treat as part of the passkey exchange. Matched
# case-insensitively against the full URL. Kept broad on purpose — false
# positives are cheap (they just land in webauthn.json too); a miss loses the
# begin/finish pair we actually care about.
_WEBAUTHN_URL_RE = re.compile(
    r"webauthn|attestation|register|assert|fido|credential|passkey|/mfa|/2fa",
    re.IGNORECASE,
)

# Only fetch bodies for these resource types — capturing image/script/font/media
# bodies would bloat the dump and slow capture for no analytical value.
_BODY_RESOURCE_TYPES = {"xhr", "fetch", "document"}

# Cap a single captured body so one large response can't blow up the dump.
_MAX_BODY_BYTES = 512 * 1024  # 512 KB


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


async def _restore_cookies(ctx: BrowserContext, state: dict) -> int:
    """Inject cookies from a storageState dict. Returns count injected."""
    cookies = state.get("cookies", [])
    if not cookies:
        return 0
    await ctx.add_cookies(cookies)
    return len(cookies)


async def _hydrate_storage_for_origin(page: Page, state: dict, origin: str) -> int:
    """For the given origin, inject any saved localStorage entries.

    Returns number of entries injected. localStorage is per-origin, so
    we can only hydrate after page.goto has loaded a page on that origin.
    """
    matching = [o for o in state.get("origins", []) if o.get("origin") == origin]
    if not matching:
        return 0
    items = matching[0].get("localStorage", [])
    if not items:
        return 0
    await page.evaluate("""
        (items) => {
            for (const it of items) {
                try { localStorage.setItem(it.name, it.value); } catch (e) {}
            }
        }
    """, items)
    return len(items)


async def _hydrate_sessionstorage_for_origin(page: Page, state: dict, origin: str) -> int:
    """Restore sessionStorage captured for `origin` into the live page.

    Mirrors _hydrate_storage_for_origin. Some RPs (e.g. Bitwarden's web vault)
    keep their auth token + crypto keys in sessionStorage, which storage_state
    never captured; the session file carries them under a top-level
    `sessionStorage` map keyed by origin (see src/lib/idb.py). Returns the
    number of items written.
    """
    ss_map = state.get("sessionStorage")
    if not isinstance(ss_map, dict):
        return 0
    items = ss_map.get(origin)
    if not items:
        return 0
    return await idb.restore_sessionstorage(page, items)


async def _hydrate_indexeddb_for_origin(page: Page, state: dict, origin: str) -> int:
    """Restore IndexedDB databases captured for `origin` into the live page.

    Mirrors _hydrate_storage_for_origin: IndexedDB is per-origin, so this can
    only run after a page on that origin has loaded. The session file carries
    the data under a top-level `indexedDB` map keyed by origin (see
    src/lib/idb.py). Returns the number of records written.
    """
    idb_map = state.get("indexedDB")
    if not isinstance(idb_map, dict):
        return 0
    dbs = idb_map.get(origin)
    if not dbs:
        return 0
    return await idb.restore_indexeddb(page, dbs)


async def _collect_observer_logs(ctx: BrowserContext) -> list:
    """Pull window.__webauthnObserverGetLogs() from every frame of every open tab.

    This is the reliable source for the advertised options — the console text we
    capture separately mangles the structured payload objects. We sweep the whole
    context, not just the attached tab, because RPs often run the ceremony in a
    different origin/tab than the one you started on (e.g. facebook.com registers
    passkeys under accounts.meta.com in a separate tab), and sometimes inside a
    same-origin iframe. Returns a per-frame list of {frame_url, entries}, which
    webauthn_params.extract_advertised understands.
    """
    out: list = []
    for page in ctx.pages:
        for frame in page.frames:
            try:
                entries = await asyncio.wait_for(frame.evaluate(
                    "() => (window.__webauthnObserverGetLogs ? window.__webauthnObserverGetLogs() : null)"
                ), timeout=5)
            except Exception:
                entries = None
            if entries:
                out.append({"frame_url": frame.url, "entries": entries})
    return out


async def _load_persisted_logs(ctx: BrowserContext) -> list:
    """Read the cross-origin persisted event log from chrome.storage.

    hook.js mirrors its log to storage on every event, so this recovers the
    ceremony even when the tab/popup that ran it has since closed or navigated
    away (the in-memory log is gone by then). Any single hooked tab can read the
    whole store, so we stop at the first frame that answers. Returns the same
    per-frame shape as _collect_observer_logs.
    """
    for page in ctx.pages:
        for frame in page.frames:
            try:
                logs = await asyncio.wait_for(frame.evaluate(
                    "async () => (window.__webauthnObserverLoadPersistedLog "
                    "? await window.__webauthnObserverLoadPersistedLog() : null)"
                ), timeout=6)
            except Exception:
                logs = None
            if logs:
                out = []
                for slot in logs.values():
                    if isinstance(slot, dict) and slot.get("entries"):
                        out.append({
                            "frame_url": slot.get("url") or slot.get("origin") or "(persisted)",
                            "entries": slot["entries"],
                        })
                if out:
                    return out
    return []


def _dedupe_frame_blocks(blocks: list) -> list:
    """Drop frame blocks with identical entries (live sweep and the persisted
    log return the same events for a still-open tab)."""
    seen: set = set()
    out: list = []
    for b in blocks:
        key = json.dumps(b.get("entries"), sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        out.append(b)
    return out


def _new_capture() -> dict:
    """A fresh capture accumulator shared across every tab we listen on."""
    return {
        "requests": [],
        "responses": [],
        "batchexecute": [],
        "webauthn": [],
        "console": [],
        "page_errors": [],
        "observer_log": None,
    }


def _attach_listeners(page: Page, captured: dict) -> None:
    """Wire network + console listeners on `page`, accumulating into `captured`.

    Called for the attached tab and for every other/new tab in the context, so a
    manually-driven flow that navigates or pops up a different origin (e.g.
    accounts.meta.com) is still captured — no --enroll-url needed.
    """

    async def on_request(req: Request) -> None:
        # Outer guard: during teardown (browser/tab closing) any access can raise
        # TargetClosedError; swallow it so it never becomes an unretrieved-future
        # exception spamming the console after a successful run.
        try:
            rec = {
                "ts": _ts(),
                "method": req.method,
                "url": req.url,
                "resource_type": req.resource_type,
                "headers": dict(req.headers),
                "post_data": None,
            }
            try:
                if req.method == "POST":
                    rec["post_data"] = req.post_data
            except Exception:
                pass
            captured["requests"].append(rec)
            if "batchexecute" in req.url:
                captured["batchexecute"].append(rec)
                print(f"  · batchexecute POST → {urlparse(req.url).path}")
            if _WEBAUTHN_URL_RE.search(req.url):
                captured["webauthn"].append({"kind": "request", **rec})
                print(f"  · webauthn {req.method} → {urlparse(req.url).path}")
        except Exception:
            return

    async def on_response(resp: Response) -> None:
        try:
            rec = {
                "ts": _ts(),
                "url": resp.url,
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": None,
                "body_encoding": None,
            }
            # Capture the body for data responses only (xhr/fetch/document). The
            # WebAuthn begin response (challenge/options JSON) and the finish result
            # are the payloads we actually want to compare across RPs.
            try:
                if resp.request.resource_type in _BODY_RESOURCE_TYPES:
                    raw = await resp.body()
                    if raw is not None and len(raw) <= _MAX_BODY_BYTES:
                        try:
                            rec["body"] = raw.decode("utf-8")
                            rec["body_encoding"] = "utf-8"
                        except UnicodeDecodeError:
                            rec["body"] = base64.b64encode(raw).decode("ascii")
                            rec["body_encoding"] = "base64"
                    elif raw is not None:
                        rec["body_encoding"] = f"omitted ({len(raw)} bytes > cap)"
            except Exception:
                pass  # body may be unavailable (redirect, cached, already consumed)
            captured["responses"].append(rec)
            if _WEBAUTHN_URL_RE.search(resp.url):
                captured["webauthn"].append({"kind": "response", **rec})
        except Exception:
            return  # target closed during teardown — ignore

    def on_console(msg) -> None:
        captured["console"].append({
            "ts": _ts(),
            "type": msg.type,
            "text": msg.text,
        })
        if msg.text and ("[hook]" in msg.text.lower() or "webauthn" in msg.text.lower()):
            print(f"  hook: {msg.text}")

    def on_pageerror(err) -> None:
        captured["page_errors"].append({"ts": _ts(), "message": str(err)})
        print(f"  page error: {err}")

    page.on("request", on_request)
    page.on("response", on_response)
    page.on("console", on_console)
    page.on("pageerror", on_pageerror)
    # Swallow Playwright's internal pyee listener errors (e.g. the benign
    # "framedetached / list.remove(x): x not in list" that fires on churny tabs
    # like chrome://new-tab-page). These are harmless bookkeeping races; without
    # a handler pyee prints a scary traceback that looks like a crash.
    page.on("error", lambda *_: None)


def _dump_capture(captured: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "network.json", "w", encoding="utf-8") as f:
        json.dump({"requests": captured["requests"], "responses": captured["responses"]},
                  f, indent=2, default=str)
    if captured["batchexecute"]:
        with open(out_dir / "batchexecute.json", "w", encoding="utf-8") as f:
            json.dump(captured["batchexecute"], f, indent=2, default=str)
    if captured["webauthn"]:
        with open(out_dir / "webauthn.json", "w", encoding="utf-8") as f:
            json.dump(captured["webauthn"], f, indent=2, default=str)
    if captured.get("observer_log"):
        with open(out_dir / "observer_log.json", "w", encoding="utf-8") as f:
            json.dump(captured["observer_log"], f, indent=2, default=str)
    with open(out_dir / "console.json", "w", encoding="utf-8") as f:
        json.dump(captured["console"], f, indent=2, default=str)
    if captured["page_errors"]:
        with open(out_dir / "page_errors.json", "w", encoding="utf-8") as f:
            json.dump(captured["page_errors"], f, indent=2, default=str)

    observer_frames = captured.get("observer_log") or []
    summary = {
        "requests": len(captured["requests"]),
        "responses": len(captured["responses"]),
        "batchexecute": len(captured["batchexecute"]),
        "webauthn": len(captured["webauthn"]),
        "console": len(captured["console"]),
        "page_errors": len(captured["page_errors"]),
        "observer_log_frames": len(observer_frames),
    }
    print(f"\n  capture summary: {summary}")
    print(f"  → {out_dir}")


async def _pick_page(ctx, prefer_url_contains: str | None) -> Page:
    """Pick which open tab to attach to."""
    pages = ctx.pages
    if not pages:
        return await ctx.new_page()

    def is_real(p: Page) -> bool:
        u = p.url or ""
        return not (u.startswith("devtools://") or u.startswith("chrome://") or u == "about:blank")

    if prefer_url_contains:
        for p in pages:
            if prefer_url_contains in (p.url or ""):
                return p

    for p in pages:
        if is_real(p):
            return p

    return pages[0]


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True, help="rp_id label for artifact paths, e.g. notion.so")
    ap.add_argument("--enroll-url", help="navigate the chosen tab to this URL before capturing")
    ap.add_argument("--cdp-url", default=DEFAULT_CDP_URL,
                    help=f"Chrome DevTools Protocol URL (default: {DEFAULT_CDP_URL})")
    ap.add_argument("--new-tab", action="store_true",
                    help="open a fresh tab instead of reusing the active one")
    ap.add_argument("--session", help="override session file (default: sessions/<rp>.json)")
    ap.add_argument("--no-restore", action="store_true",
                    help="skip session restoration (use if Chrome profile is already logged in)")
    ap.add_argument("--no-localstorage", action="store_true",
                    help="restore cookies only, skip localStorage hydration")
    args = ap.parse_args()

    artifacts_dir = Path(f"artifacts/hook-runs/{args.rp}/{_ts()}")
    session_path = Path(args.session) if args.session else Path(f"sessions/{args.rp}.json")

    print(f"\n→ hook run for {args.rp}")
    print(f"  cdp:       {args.cdp_url}")
    print(f"  session:   {session_path} ({'will skip' if args.no_restore else 'will restore'})")
    print(f"  artifacts: {artifacts_dir}")

    # Load session up-front so we fail early if it's missing
    state = None
    if not args.no_restore:
        if not session_path.exists():
            raise SystemExit(
                f"\n  session not found: {session_path}\n"
                f"  either pass --no-restore (if Chrome profile is already logged in)\n"
                f"  or run the signup agent first to capture one"
            )
        with open(session_path, "r", encoding="utf-8") as f:
            state = json.load(f)

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.connect_over_cdp(args.cdp_url)
        except Exception as e:
            raise SystemExit(
                f"\n  could not connect to Chrome at {args.cdp_url}: {e}\n"
                f"  is Chrome running with --remote-debugging-port=9222?"
            )

        ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
        print(f"  connected — {len(ctx.pages)} open tab(s)")

        sws = ctx.service_workers
        bg_pages = ctx.background_pages
        print(f"  service workers: {[s.url for s in sws] or 'none'}")
        print(f"  background pages: {[p.url for p in bg_pages] or 'none'}")
        if not sws and not bg_pages:
            print(f"  ⚠ no extension service worker seen — but MV3 workers sleep when idle,")
            print(f"    so this is often a false alarm. The real test is seeing")
            print(f"    [webauthn-observer] lines in the tab console during registration.")
        else:
            print(f"  ✓ extension loaded")

        # Restore cookies into the live Chrome profile (persistent across runs)
        if state is not None:
            n = await _restore_cookies(ctx, state)
            print(f"  injected {n} cookies")

        # Pick the tab to attach to
        if args.new_tab:
            page = await ctx.new_page()
            print(f"  opened new tab")
        else:
            page = await _pick_page(ctx, args.rp)
            print(f"  attached to tab: {page.url or '(blank)'}")

        _url = page.url or ""
        if not _url or _url.startswith(("chrome://", "about:", "edge://", "devtools://")):
            print(f"  ⚠ this tab is a browser page — hook.js does NOT run on chrome:// pages.")
            print(f"    In THIS Chrome (the one on {args.cdp_url}), navigate to the RP's https")
            print(f"    site, log in, open passkey settings, and register there — then press Enter.")

        # Capture on every open tab, and on any tab/popup opened later — so a
        # manually-driven flow that navigates elsewhere (or triggers a popup like
        # accounts.meta.com) is captured without needing --enroll-url.
        captured = _new_capture()
        for p in ctx.pages:
            _attach_listeners(p, captured)

        def _on_new_page(p: Page) -> None:
            print(f"  + new tab: {p.url or '(blank)'}")
            _attach_listeners(p, captured)

        ctx.on("page", _on_new_page)

        # Navigate, then hydrate localStorage for that origin
        if args.enroll_url:
            print(f"  navigating to {args.enroll_url}")
            try:
                await page.goto(args.enroll_url, wait_until="domcontentloaded", timeout=30_000)
            except Exception as e:
                print(f"  navigation issue (continuing anyway): {e}")

            if state is not None and not args.no_localstorage:
                try:
                    current_origin = await page.evaluate("() => location.origin")
                    n = await _hydrate_storage_for_origin(page, state, current_origin)
                    if n:
                        print(f"  hydrated {n} localStorage entries for {current_origin}")
                    else:
                        print(f"  no localStorage entries for {current_origin} in session")
                    # sessionStorage (e.g. Bitwarden token/crypto keys) and
                    # IndexedDB (other RPs' tokens) — restored the same way, then
                    # one reload lets the app pick up all stores.
                    n_ss = await _hydrate_sessionstorage_for_origin(page, state, current_origin)
                    if n_ss:
                        print(f"  hydrated {n_ss} sessionStorage entries for {current_origin}")
                    n_idb = await _hydrate_indexeddb_for_origin(page, state, current_origin)
                    if n_idb:
                        print(f"  hydrated {n_idb} IndexedDB records for {current_origin}")
                    if n or n_ss or n_idb:
                        print(f"  reloading to let app pick up storage")
                        await page.reload()
                except Exception as e:
                    print(f"  storage hydration failed: {e}")
        elif state is not None and not args.no_localstorage:
            print(f"  ⚠ no --enroll-url given; skipping localStorage hydration")
            print(f"     (cookies alone are usually enough; navigate manually if needed)")

        print()
        print("  ┌" + "─" * 70 + "┐")
        print("  │  drive the passkey registration manually in Chrome.               │")
        print("  │  hook.js console output will appear here as it fires.             │")
        print("  │  open DevTools (F12) in the tab to watch Network/Console live.    │")
        print("  │                                                                   │")
        print("  │  press Enter when done (or Ctrl+C) — captures will be dumped.     │")
        print("  └" + "─" * 70 + "┘")
        print()

        try:
            await asyncio.to_thread(input, "  > ")
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n  interrupted — dumping captures anyway")
        except EOFError:
            print("\n  stdin closed — dumping captures")

        # Capture is done — stop attaching listeners to further tabs so the
        # throwaway storage-recovery tab (and any teardown churn) stays silent.
        try:
            ctx.remove_listener("page", _on_new_page)
        except Exception:
            pass

        # Pull the hook's structured event log. Sweep live frames first, then the
        # cross-origin persisted store (survives the ceremony tab closing). If a
        # ceremony popup already closed and only a blank tab remains, open a throwaway
        # https page to get a hook context that can read the persisted store.
        try:
            live = await _collect_observer_logs(ctx)
            persisted = await _load_persisted_logs(ctx)
            if not live and not persisted:
                try:
                    tmp = await ctx.new_page()
                    await tmp.goto("https://example.com", wait_until="domcontentloaded", timeout=15_000)
                    await tmp.wait_for_timeout(400)  # let the hook install + read storage
                    persisted = await _load_persisted_logs(ctx)
                    await tmp.close()
                    if persisted:
                        print("  recovered log from chrome.storage (ceremony tab had closed)")
                except Exception:
                    pass
            captured["observer_log"] = _dedupe_frame_blocks((live or []) + (persisted or [])) or None
        except Exception as e:
            print(f"  observer-log collection failed: {e}")

        try:
            _dump_capture(captured, artifacts_dir)
        except Exception as e:
            print(f"  capture dump failed: {e}")

        # Auto-record the advertised WebAuthn params into the ledger + status CSV.
        # Guarded so a parse failure never costs us the raw dumps above.
        try:
            params = webauthn_params.extract_advertised(
                captured.get("observer_log"), captured.get("webauthn")
            )
            if params:
                ledger.record_advertised_params(
                    args.rp, params, artifact=str(artifacts_dir)
                )
                # Re-read so the CSV carries the exact captured_at the ledger stored.
                led = ledger.load()
                stored = led.get("entries", {}).get(args.rp, {}).get(
                    "advertised_params", params
                )
                webauthn_params.upsert_status_csv(args.rp, stored)
                print(
                    f"  ✓ advertised params recorded → ledger[{args.rp}] "
                    f"+ {webauthn_params.DEFAULT_STATUS_CSV}"
                )
            elif captured.get("observer_log"):
                print("  observer log had no create.called event — nothing to record")
                print("  · the hook installed, but no navigator.credentials.create() fired")
                print("  · re-open the RP's 'add passkey' flow so create() is called, then Enter")
            else:
                print("  no observer log — hook.js didn't run on any open tab. Checklist:")
                print("  · registration must happen in THIS Chrome (port 9222), on an https page")
                print("  · extension loaded? chrome://extensions → 'Passkeys Pwned' enabled")
                print("  · during registration you should see [webauthn-observer] lines in")
                print("    that tab's DevTools console — if not, the hook isn't injected there")
        except Exception as e:
            print(f"  advertised-params persist failed: {e}")

        # Detach but do NOT close — leave the user's Chrome running.
        try:
            await browser.close()
        except Exception:
            pass


def _run_with_signal_handling():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    _run_with_signal_handling()