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
2. Optionally navigates the active page to --enroll-url
3. Captures network + console traffic on the active page
4. Waits — you drive the passkey registration manually (already logged in,
   since this is your own long-running Chrome profile)
5. On Enter, dumps captured traffic to artifacts

Usage:
    python -m src.hook.run --rp notion.so --enroll-url https://www.notion.so/my-account

Notes:
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

from src.lib import ledger, webauthn_params


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
        # Structured [webauthn-observer] events resolved live from console args —
        # a fallback source for create.called/fabrication.* when the in-page log is
        # lost to a fast post-registration redirect (e.g. Nintendo → /portal).
        "console_events": [],
        "_console_tasks": set(),
    }


async def _capture_console_event(msg, captured: dict) -> None:
    """Resolve a `[webauthn-observer] <eventType>` console message's payload arg into
    a structured observer-log-style entry. Done live (as the event fires) so it
    survives a navigation that would dispose the in-page log."""
    try:
        args = msg.args
        event_type = None
        if args:
            head = await args[0].json_value()
            prefix = "[webauthn-observer] "
            if isinstance(head, str) and head.startswith(prefix):
                event_type = head[len(prefix):].strip()
        if not event_type:
            return
        payload = await args[1].json_value() if len(args) > 1 else {}
        captured["console_events"].append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "eventType": event_type,
            "payload": payload,
        })
    except Exception:
        pass  # handle disposed (very fast navigation) or non-serializable arg


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
        try:
            text = msg.text
        except Exception:
            return
        captured["console"].append({"ts": _ts(), "type": msg.type, "text": text})
        if text and ("[hook]" in text.lower() or "webauthn" in text.lower()):
            print(f"  hook: {text}")
        # Resolve structured hook events from the console args NOW, before any
        # navigation disposes them. Keep a task reference so it isn't GC'd.
        if text and text.startswith("[webauthn-observer] "):
            t = asyncio.ensure_future(_capture_console_event(msg, captured))
            captured["_console_tasks"].add(t)
            t.add_done_callback(captured["_console_tasks"].discard)

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
    ap.add_argument("--label", default="",
                    help="control/config name for this run, logged in data/experiments.csv "
                         "(e.g. alg-downgrade-RS256, attestation-zero-aaguid)")
    ap.add_argument("--enroll-url", help="navigate the chosen tab to this URL before capturing")
    ap.add_argument("--cdp-url", default=DEFAULT_CDP_URL,
                    help=f"Chrome DevTools Protocol URL (default: {DEFAULT_CDP_URL})")
    ap.add_argument("--new-tab", action="store_true",
                    help="open a fresh tab instead of reusing the active one")
    args = ap.parse_args()

    # Anchor for scoping the (accumulated, cross-run) observer log to THIS run —
    # the registration happens after this point, stale ceremonies before it.
    run_started_iso = datetime.now(timezone.utc).isoformat()

    artifacts_dir = Path(f"artifacts/hook-runs/{args.rp}/{_ts()}")

    print(f"\n→ hook run for {args.rp}")
    print(f"  cdp:       {args.cdp_url}")
    print(f"  artifacts: {artifacts_dir}")

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

        # Navigate to the enroll URL, if given
        if args.enroll_url:
            print(f"  navigating to {args.enroll_url}")
            try:
                await page.goto(args.enroll_url, wait_until="domcontentloaded", timeout=30_000)
            except Exception as e:
                print(f"  navigation issue (continuing anyway): {e}")

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
            # Fold in structured console events (resolved live, immune to the
            # navigation loss above) as a fallback "(console)" frame — recovers
            # create.called/fabrication.* on RPs that hard-redirect after finish.
            try:
                pending = list(captured.get("_console_tasks") or [])
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
            except Exception:
                pass
            ce = captured.get("console_events") or []
            frames = _dedupe_frame_blocks((live or []) + (persisted or []))
            if ce:
                frames = frames + [{"frame_url": "(console)", "entries": ce}]
            captured["observer_log"] = frames or None
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
                captured.get("observer_log"),
                {"requests": captured.get("requests"), "responses": captured.get("responses")},
                since_iso=run_started_iso,
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
                # Append this run's fab/srv result to the experiment log — one
                # row per run, labelled by --label, never overwritten.
                exp_row = webauthn_params.flatten_experiment_columns(
                    stored, rp_id=args.rp, label=args.label, artifact=str(artifacts_dir)
                )
                webauthn_params.append_experiment(exp_row)
                print(
                    f"  ✓ experiment logged → {webauthn_params.DEFAULT_EXPERIMENTS_CSV} "
                    f"(label={args.label or '-'}, result={exp_row['srv_result'] or exp_row['fab_outcome'] or '-'})"
                )
                if exp_row["srv_result"] == "not-captured":
                    print("  ⚠ the finish request/response was NOT in the network capture —")
                    print("    the browser fabricated a credential but run.py didn't see it sent.")
                    print("    Re-run with run.py attached BEFORE you register, and keep the")
                    print("    ceremony tab open, to capture the server's real accept/reject.")
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