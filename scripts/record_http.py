"""Capture the HTTP requests of a hand-driven login + passkey run, for the
HTTP-based audit.

You launch real Chrome (same anti-detection attach model as record_path.py),
drive login and the passkey ceremony (enrol and/or authenticate) by hand ONCE,
and this records every XHR/fetch/document request+response into
data/http/<rp>.raw.json. That's all it does now — classification into a flow
descriptor (data/http/<rp>.json) is a separate, manual step: build one from
the raw log with http_flow.build_descriptor once you've reviewed/cleaned it.

Secrets never touch disk: the identity password/email and all Cookie/Authorization
/Set-Cookie header *values* are redacted at capture time (see http_flow.redact).

Drive the passkey with any authenticator that completes the ceremony (the
platform authenticator / Windows Hello works) — the register/authenticate
*finish* request fires and is captured either way.

Pass --persist to launch the kept per-RP profile under
browser-profiles-manual/<rp>/ instead of a fresh throwaway one — use this for
an RP you (or a prior session) already logged into by hand, so you land on
the real, already-authenticated site instead of its login page.

Usage:
    python -m scripts.record_http --rp github.com --url https://github.com/login
    python -m scripts.record_http --rp canva.com --persist --url https://www.canva.com/settings/login-and-security
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from src.lib import browser, credentials, http_flow

OUT_DIR = Path("data/http")

# Only these resource types carry the flow we care about; static assets are noise.
KEEP_TYPES = {"xhr", "fetch", "document", "other"}
MAX_BODY = 64 * 1024  # cap stored body text


async def _capture(page, records: list[dict], identity: dict, seen: set[int]):
    context = page.context

    async def on_response(response):
        try:
            request = response.request
            if request.resource_type not in KEEP_TYPES:
                return
            key = id(response)
            if key in seen:
                return
            seen.add(key)

            try:
                req_headers = await request.all_headers()
            except Exception:
                req_headers = dict(request.headers)
            try:
                resp_headers = await response.all_headers()
            except Exception:
                resp_headers = dict(response.headers)

            body = None
            try:
                ct = (resp_headers.get("content-type") or "").lower()
                if any(t in ct for t in ("json", "text", "javascript", "html", "xml")):
                    raw = await response.body()
                    body = raw[:MAX_BODY].decode("utf-8", "replace")
            except Exception:
                body = None

            rec = {
                "method": request.method,
                "url": request.url,
                "resource_type": request.resource_type,
                "status": response.status,
                "request_content_type": req_headers.get("content-type"),
                "response_content_type": resp_headers.get("content-type"),
                "request_headers": req_headers,
                "response_headers": resp_headers,
                "request_body": request.post_data,
                "response_body": body,
            }
            http_flow.redact(rec, identity)   # scrub secrets BEFORE buffering — never optional
            records.append(rec)
            print(f"    · {request.method} {request.url.split('?')[0]}")
        except Exception:
            pass

    context.on("response", lambda r: asyncio.create_task(on_response(r)))


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True, help="RP id, e.g. github.com")
    ap.add_argument("--url", help="URL to open first (e.g. the login page)")
    ap.add_argument("--persist", action="store_true",
                    help="use the kept profile under browser-profiles-manual/<rp>/ "
                         "(an RP you already logged into by hand) instead of a fresh one")
    args = ap.parse_args()

    try:
        identity = credentials.load_identity()
    except SystemExit:
        identity = {}   # capture still works; just no secret templating/redaction

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    seen: set[int] = set()

    page = await browser.ensure_browser_for(args.rp, persist=args.persist)
    await _capture(page, records, identity, seen)

    if args.url:
        await page.goto(args.url, wait_until="domcontentloaded")

    print(f"\n  Recording HTTP for {args.rp}. Drive login + the passkey ceremony by hand.")
    print("  Requests print as they happen. Press Enter here when done.\n")
    await asyncio.get_event_loop().run_in_executor(None, input)

    # let any in-flight response handlers finish
    await asyncio.sleep(1.0)

    raw_path = OUT_DIR / f"{args.rp}.raw.json"
    raw_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    print(f"\n  {len(records)} requests captured -> {raw_path}")
    print("  no flow descriptor written — classify/clean this raw log by hand, then build one")

    await browser.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
