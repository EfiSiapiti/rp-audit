"""Generic pure-HTTP passkey adapter for ajax-style RPs.

Some RPs (e.g. Canva) serve WebAuthn over XHR `_ajax` endpoints with the field
names minified to opaque keys and every call gated behind a JS-set session token
(x-*-authz). The generic replay_http can't drive those. This adapter does, with
NO per-RP code:

  1. Reads data/http/<rp>.json — only runs when style == "ajax".
  2. Infers the obfuscated field mapping from data/http/<rp>.raw.json
     (src.lib.ajax_infer) and caches it to data/http/<rp>.ajax.json.
  3. Borrows the live session ONCE from the logged-in browser profile
     (cookies + the live value of the x-*-authz session token).
  4. Replays register (+ --auth) over pure HTTP with ONE SoftAuthenticator, so
     the key + credId stay consistent across both legs.

Picked up automatically by `replay_http` when the descriptor says style=="ajax".

Usage:
    python -m scripts.ajax_adapter --rp canva.com
    python -m scripts.ajax_adapter --rp canva.com --auth
    python -m scripts.ajax_adapter --rp canva.com --auth --m-file data/http/canva.M.json
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
from pathlib import Path
from urllib.parse import urlparse

import httpx

from src.lib import browser, http_flow, ajax_infer
from src.lib.soft_authenticator import SoftAuthenticator, b64url_decode

HTTP_DIR = Path("data/http")


def _authz_name(ajax_headers: list[str]) -> str | None:
    for kw in ("authz", "csrf", "session", "token"):
        for h in ajax_headers:
            if kw in h:
                return h
    return None


async def borrow_session(rp_id: str, warm_url: str, authz_name: str | None) -> tuple[dict, str | None]:
    """Launch the logged-in profile, capture cookies + the live authz token value."""
    page = await browser.ensure_browser_for(rp_id, persist=True)
    ctx = page.context
    live_authz: dict = {}

    def on_request(req):
        if "/_ajax/" in req.url or authz_name:
            h = {k.lower(): v for k, v in req.headers.items()}
            if authz_name and h.get(authz_name) and "authz" not in live_authz:
                live_authz["authz"] = h[authz_name]

    ctx.on("request", on_request)
    await page.goto(warm_url, wait_until="domcontentloaded")
    for _ in range(30):
        if live_authz:
            break
        await asyncio.sleep(0.5)
    cookies = {c["name"]: c["value"] for c in await ctx.cookies()}
    await browser.shutdown()
    print(f"  borrowed session: {len(cookies)} cookies, "
          f"{authz_name}={'captured' if live_authz else 'MISSING'}")
    return cookies, live_authz.get("authz")


def _headers(leg: dict, origin: str, authz_name: str | None, live_authz: str | None,
             *, post: bool) -> dict:
    h = dict(leg.get("headers") or {})          # captured x-* (op name, account ids)
    if authz_name and live_authz:
        h[authz_name] = live_authz               # override only the live session token
    h["accept"] = "*/*"
    h["origin"] = origin
    h["referer"] = origin + "/"
    if post:
        h["content-type"] = "application/json;charset=UTF-8"
    return h


def _shape_credential(cred: dict, *, assertion: bool) -> dict:
    r = cred["response"]
    if assertion:
        return {"id": cred["id"], "rawId": cred["rawId"], "type": "public-key",
                "response": {"authenticatorData": r["authenticatorData"],
                             "clientDataJSON": r["clientDataJSON"],
                             "signature": r["signature"], "userHandle": ""},
                "clientExtensionResults": {}}
    return {"id": cred["id"], "rawId": cred["rawId"], "type": "public-key",
            "response": {"attestationObject": r["attestationObject"],
                         "clientDataJSON": r["clientDataJSON"]},
            "clientExtensionResults": {}}


def _do_leg(client: httpx.Client, leg: dict, origin: str, authz_name, live_authz,
            build_credential, m_blob) -> httpx.Response:
    b, f = leg["begin"], leg["finish"]
    # begin
    bh = _headers(b, origin, authz_name, live_authz, post=(b["method"] != "GET"))
    r = client.request(b["method"], b["url"], headers=bh,
                       content="{}" if b["method"] != "GET" else None)
    print(f"  {b['method']} begin -> {r.status_code}")
    resp = r.json()
    challenge = b64url_decode(ajax_infer.get_path(resp, b["challenge_path"]))
    rp_id = ajax_infer.get_path(resp, b["rpid_path"]) if "rpid_path" in b else urlparse(origin).netloc

    cred = build_credential(rp_id, challenge)
    if cred is None:
        raise RuntimeError("authenticator produced no credential (credId not offered?)")

    body = copy.deepcopy(f["template"])
    ajax_infer.set_path(body, f["credential_path"], json.dumps(cred, separators=(",", ":")))
    for fin_path, begin_path in f.get("copy", []):
        ajax_infer.set_path(body, fin_path, ajax_infer.get_path(resp, begin_path))
    if f.get("blob_path"):
        if m_blob is not None:
            ajax_infer.set_path(body, [f["blob_path"][0]], m_blob)
        else:
            print("    ! finish carries an anti-fraud blob and no --m-file given — "
                  "a rejection here is likely bot-detection, not WebAuthn verification")
    fh = _headers(f, origin, authz_name, live_authz, post=True)
    r = client.post(f["url"], content=json.dumps(body), headers=fh)
    print(f"  POST finish -> {r.status_code}  body={r.text[:160]!r}")
    return r


async def run(rp: str, *, do_auth: bool = False, m_file: str | None = None,
              warm_url: str | None = None) -> None:
    desc = json.loads((HTTP_DIR / f"{rp}.json").read_text(encoding="utf-8"))
    if desc.get("style") != "ajax":
        raise SystemExit(f"{rp} is style={desc.get('style')!r}; use replay_http instead")
    records = json.loads((HTTP_DIR / f"{rp}.raw.json").read_text(encoding="utf-8"))
    profile = ajax_infer.infer_profile(records)
    (HTTP_DIR / f"{rp}.ajax.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")

    reg = profile.get("register")
    if not reg or "error" in reg:
        raise SystemExit(f"register mapping not inferred: {reg.get('error') if reg else 'missing'}")
    origin = reg["origin"] or f"https://{rp}"
    authz_name = _authz_name(desc.get("ajax_headers") or [])
    m_blob = json.loads(Path(m_file).read_text(encoding="utf-8")) if m_file else None

    cookies, live_authz = await borrow_session(rp, warm_url or (origin + "/"), authz_name)
    auth = SoftAuthenticator()

    with httpx.Client(timeout=30, cookies=cookies, follow_redirects=True) as client:
        print("\n== REGISTER ==")
        r = _do_leg(client, reg, origin, authz_name, live_authz,
                    lambda rp, ch: _shape_credential(
                        auth.make_credential(rp_id=rp, challenge=ch, origin=origin), assertion=False),
                    m_blob=None)
        print(f"  -> {'REGISTERED fabricated passkey' if r.status_code == 200 else 'rejected'}")

        if do_auth and r.status_code == 200:
            au = profile.get("auth")
            if not au or "error" in au:
                print(f"\n  auth mapping not inferred ({au.get('error') if au else 'missing'}); "
                      "re-capture a passkey login to include it")
                return
            print("\n== AUTHENTICATE ==")
            r = _do_leg(client, au, origin, authz_name, live_authz,
                        lambda rp, ch: (lambda a: _shape_credential(a, assertion=True) if a else None)(
                            auth.get_assertion(rp_id=rp, challenge=ch, origin=origin)),
                        m_blob=m_blob)
            ok = r.status_code == 200 and '"A?":"A"' in r.text
            print(f"  -> {'LOGGED IN with fabricated passkey' if ok else 'auth rejected'}")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True)
    ap.add_argument("--auth", action="store_true")
    ap.add_argument("--m-file", help="JSON file with a live-captured anti-fraud blob for the finish")
    ap.add_argument("--warm-url", help="page to load to borrow the session (default: RP origin)")
    args = ap.parse_args()
    await run(args.rp, do_auth=args.auth, m_file=args.m_file, warm_url=args.warm_url)


if __name__ == "__main__":
    asyncio.run(main())
