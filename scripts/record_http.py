"""Capture the HTTP requests of a hand-driven login + passkey run, for the
HTTP-based audit.

You launch real Chrome (same anti-detection attach model as record_path.py),
drive login and the passkey ceremony (enrol and/or authenticate) by hand ONCE,
and this records every XHR/fetch/document request+response into
data/http/<rp>.raw.json, then classifies them into data/http/<rp>.json:

  login  |  webauthn_register_begin/finish  |  webauthn_auth_begin/finish

Secrets never touch disk: the identity password/email and all Cookie/Authorization
/Set-Cookie header *values* are redacted at capture time (see http_flow.redact);
login fields are templated to {{email}}/{{password}} in the descriptor.

Drive the passkey with any authenticator that completes the ceremony — the
platform authenticator (Windows Hello) works, or pass --extension <hook dir> to
fabricate navigator.credentials.create() with the pwned-xploit hook. Either way
the register/authenticate *finish* request fires and is captured.

Usage:
    python -m scripts.record_http --rp github.com --url https://github.com/login
    python -m scripts.record_http --rp github.com --url https://github.com/login \
        --extension ../pwned-xploit/pwned-xploit
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


async def _capture(page, records: list[dict], identity: dict, seen: set[int], counter: dict):
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
            # Trace the CSRF token to its cookie BEFORE redaction blanks cookie
            # values; stash the result so build_descriptor reuses it.
            csrf = http_flow.locate_csrf(rec)
            http_flow.redact(rec, identity)   # scrub secrets BEFORE buffering
            if csrf:
                rec["csrf_trace"] = csrf
            records.append(rec)

            tag = http_flow.classify_webauthn(rec)
            if tag:
                counter[tag] = counter.get(tag, 0) + 1
                print(f"    · {tag}: {request.method} {request.url.split('?')[0]}")
        except Exception:
            pass

    context.on("response", lambda r: asyncio.create_task(on_response(r)))


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True, help="RP id, e.g. github.com")
    ap.add_argument("--url", help="URL to open first (e.g. the login page)")
    ap.add_argument("--extension", help="hook extension dir to load (optional)")
    args = ap.parse_args()

    try:
        identity = credentials.load_identity()
    except SystemExit:
        identity = {}   # capture still works; just no secret templating/redaction

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    seen: set[int] = set()
    counter: dict[str, int] = {}

    page = await browser.ensure_browser_for(
        args.rp, extension_dir=args.extension, persist=bool(args.extension))
    await _capture(page, records, identity, seen, counter)

    if args.url:
        await page.goto(args.url, wait_until="domcontentloaded")

    print(f"\n  Recording HTTP for {args.rp}. Drive login + the passkey ceremony by hand.")
    print("  Tagged WebAuthn requests print as they happen. Press Enter here when done.\n")
    await asyncio.get_event_loop().run_in_executor(None, input)

    # let any in-flight response handlers finish
    await asyncio.sleep(1.0)

    raw_path = OUT_DIR / f"{args.rp}.raw.json"
    raw_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    descriptor = http_flow.build_descriptor(records, args.rp, identity)
    desc_path = OUT_DIR / f"{args.rp}.json"
    desc_path.write_text(json.dumps(descriptor, indent=2), encoding="utf-8")

    print(f"\n  {len(records)} requests captured -> {raw_path}")
    print(f"  flow descriptor -> {desc_path}")
    print(f"  summary: {descriptor['summary'] or '(no login/webauthn requests classified)'}")

    await browser.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
