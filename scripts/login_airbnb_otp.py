"""Replay airbnb.com's email+OTP login from the raw capture (data/http/aibnb.com.raw.json).

airbnb.com has no password login at all — classify_login never tags it
(descriptor's flow is just ['webauthn_auth_begin']) because its auth API is a
multi-step, continuation-token state machine instead:

    POST /api/v2/auth/options          (no email yet)
    POST /api/v2/auth/identify/email   (submits email, triggers the OTP email)
    ... wait for the OTP email ...
    POST /api/v2/auth/authenticate/email_otp   (submits email + otp)

Each response hands back a fresh `x-airbnb-set-auth-session` header that MUST
be echoed as the `x-airbnb-auth-session` request header on the next call —
a server-side continuation token, not a cookie or CSRF value. Replaying any
one of these calls with a stale captured session header just fails; replaying
them in order while carrying that token forward is what actually works.

This is airbnb-specific (the step/continuation-token shape isn't something
other captured RPs share), so it lives as its own script rather than inside
replay_http.py's generalized login() — same convention as manual_signup.py /
open_managed_profile.py for other one-off flows.

Usage:
    python -m scripts.login_airbnb_otp
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from dotenv import load_dotenv

from src.lib import credentials, imap_poll

load_dotenv()   # IMAP_USER/IMAP_PASS live in .env; imap_poll reads them from os.environ

RAW_PATH = Path("data/http/aibnb.com.raw.json")   # project's data uses this spelling
RP_ID_FOR_MAIL = "airbnb.com"                      # the real domain, for IMAP sender matching

_DROP_REQUEST_HEADERS = {"cookie", "content-length", "host"}


def _raw_records() -> list[dict]:
    return json.loads(RAW_PATH.read_text(encoding="utf-8"))


def _find(records: list[dict], url_suffix: str) -> dict | None:
    for rec in records:
        if (rec.get("method") or "").upper() == "POST" and rec.get("url", "").split("?")[0].endswith(url_suffix):
            return rec
    return None


def _carry_headers(rec: dict, overrides: dict | None = None) -> dict:
    out = {k: v for k, v in (rec.get("request_headers") or {}).items()
           if not k.lower().startswith(":") and k.lower() not in _DROP_REQUEST_HEADERS}
    if overrides:
        out.update(overrides)
    return out


def _post(client: httpx.Client, rec: dict, body_text: str, auth_session: str | None) -> httpx.Response:
    overrides = {"x-airbnb-auth-session": auth_session} if auth_session is not None else None
    headers = _carry_headers(rec, overrides)
    return client.request(rec["method"], rec["url"], headers=headers, content=body_text.encode())


def _next_auth_session(resp: httpx.Response) -> str | None:
    for k, v in resp.headers.items():
        if k.lower() == "x-airbnb-set-auth-session":
            return v
    return None


def main() -> None:
    records = _raw_records()
    options_rec = _find(records, "/auth/options")
    identify_rec = _find(records, "/auth/identify/email")
    authenticate_rec = _find(records, "/auth/authenticate/email_otp")
    if not (options_rec and identify_rec and authenticate_rec):
        raise SystemExit("could not find all three captured auth requests in the raw log")

    email = credentials.resolve("email", rp_id=RP_ID_FOR_MAIL)
    rp_id = "aibnb.com"   # for credentials.resolve's own lookups, matching identity.json's convention here

    with httpx.Client(timeout=30, follow_redirects=True) as client:
        print(f"  POST {options_rec['url'].split('?')[0]} (no email yet, establishes the session chain)")
        r = _post(client, options_rec, options_rec.get("request_body") or "", auth_session=None)
        print(f"    -> {r.status_code}")
        session_token = _next_auth_session(r)
        if not session_token:
            raise SystemExit("auth/options did not hand back an x-airbnb-set-auth-session header — can't continue")

        identify_body = (identify_rec.get("request_body") or "").replace("{{email}}", email)
        print(f"  POST {identify_rec['url'].split('?')[0]} (submits email, should trigger the OTP email)")
        r = _post(client, identify_rec, identify_body, auth_session=session_token)
        print(f"    -> {r.status_code}  {(r.text or '')[:200]!r}")
        session_token = _next_auth_session(r) or session_token

        old_body = json.loads(authenticate_rec.get("request_body") or "{}")
        old_otp = (((old_body.get("steps") or [{}, {}])[1] or {}).get("emailOtpChallenge") or {}).get("otp")

        # airbnb sends more than one OTP email per identify/email call, and
        # find_verification's own "newest wins" ordering did NOT reliably
        # match which one airbnb actually considers current (confirmed: the
        # code it called newest got rejected as already-expired, the other
        # one didn't). So: enumerate every candidate in the window first —
        # never submit one blind — and use whichever was found LAST in that
        # enumeration, submitting only once.
        print(f"  collecting OTP codes mailed to {email} ...")
        codes: list[str] = []
        first_timeout = 120   # wait properly for the first one to land at all
        while True:
            found = imap_poll.find_verification(RP_ID_FOR_MAIL, timeout_seconds=first_timeout,
                                                prefer_code=True, newer_than_seconds=90,
                                                exclude_values=codes)
            if not found or found.method != "code":
                break
            print(f"    code {len(codes) + 1}: {found.value!r} (subject: {found.subject!r})")
            codes.append(found.value)
            first_timeout = 15   # short: just long enough to catch a near-simultaneous second mail
        if not codes:
            raise SystemExit("no OTP code found in mail within the timeout")
        otp = codes[-1]
        print(f"  using code {otp!r} ({len(codes)} found total, picked the last one)")

        authenticate_body = (authenticate_rec.get("request_body") or "").replace("{{email}}", email)
        if old_otp:
            authenticate_body = authenticate_body.replace(old_otp, otp)
        else:
            print("  WARNING: could not find the captured OTP value to replace — body still carries the stale one")

        print(f"  POST {authenticate_rec['url'].split('?')[0]} (submits email + fresh otp)")
        r = _post(client, authenticate_rec, authenticate_body, auth_session=session_token)
        print(f"    -> {r.status_code}  {(r.text or '')[:300]!r}")

        try:
            parsed = r.json()
        except ValueError:
            parsed = None
        ok = isinstance(parsed, dict) and isinstance(parsed.get("authentication"), dict) \
            and bool(parsed["authentication"].get("userId"))
        print(f"\n  {'LOGGED IN' if ok else 'NOT logged in'} "
             f"{'(userId ' + str(parsed['authentication'].get('userId')) + ')' if ok else ''}")


if __name__ == "__main__":
    main()
