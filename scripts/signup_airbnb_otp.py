"""Establish an airbnb.com auth session over HTTP via email + OTP, and surface
what airbnb asks for if the account doesn't exist yet.

This rides the exact flow captured in data/http/aibnb.com.raw.json — there is
NO separate signup endpoint in that capture; the only auth legs airbnb uses are:

    POST /api/v2/auth/options          (no email yet, opens the session chain)
    POST /api/v2/auth/identify/email   (submits email; mails the OTP)
    ... wait for the OTP email ...
    POST /api/v2/auth/authenticate/email_otp   (submits email + otp)

airbnb routes both login AND new-account creation through this same chain. The
`identify/email` response tells you which case you're in:
  * existing account -> it offers fallbacks like {"password":{}} and
    authenticate/email_otp logs you straight in (that's scripts.login_airbnb_otp).
  * new address      -> authenticate/email_otp returns a `nextStepConfig`
    naming the extra fields airbnb wants (name, birthdate, terms). Those field
    names come FROM THAT RESPONSE, captured live — this script does not guess
    them. It prints the nextStepConfig so the real signup leg can be built from
    airbnb's own answer (then recorded with scripts.record_http if wanted).

So with the identity.json email (which already has an account) this behaves as
a login. To exercise account creation, point identity.json at an unused address;
the script will then print exactly what airbnb demands next.

Everything shared with login (session-chain carry, fresh per-request IDs,
dropped stale fingerprint headers, Chrome TLS impersonation via curl_cffi, the
cookie warm-up and OTP collection) is imported from that module, not copied.

Usage:
    python -m scripts.signup_airbnb_otp
"""
from __future__ import annotations

import json

from curl_cffi import requests as cffi_requests

from src.lib import credentials
from scripts.login_airbnb_otp import (
    IMPERSONATE,
    RP_ID_FOR_MAIL,
    _check_challenge,
    _collect_otp,
    _find,
    _new_ids,
    _next_auth_session,
    _post,
    _raw_records,
    _warm_cookies,
)


def main() -> None:
    records = _raw_records()
    options_rec = _find(records, "/auth/options")
    identify_rec = _find(records, "/auth/identify/email")
    authenticate_rec = _find(records, "/auth/authenticate/email_otp")
    if not (options_rec and identify_rec and authenticate_rec):
        raise SystemExit("could not find the captured options/identify/authenticate requests in the raw log")

    email = credentials.resolve("email", rp_id=RP_ID_FOR_MAIL)

    with cffi_requests.Session(impersonate=IMPERSONATE, timeout=30) as client:
        _warm_cookies(client, options_rec)

        session_ids = _new_ids()
        attempt_ids = _new_ids(with_attempt=True)

        print(f"  POST {options_rec['url'].split('?')[0]} (no email yet, opens the session chain)")
        r = _post(client, options_rec, options_rec.get("request_body") or "", auth_session=None, ids=session_ids)
        print(f"    -> {r.status_code}")
        _check_challenge(r)
        session_token = _next_auth_session(r)
        if not session_token:
            raise SystemExit("auth/options did not hand back an x-airbnb-set-auth-session header — can't continue")

        identify_body = (identify_rec.get("request_body") or "").replace("{{email}}", email)
        print(f"  POST {identify_rec['url'].split('?')[0]} (submits email, mails the OTP)")
        r = _post(client, identify_rec, identify_body, auth_session=session_token, ids=attempt_ids)
        print(f"    -> {r.status_code}  {(r.text or '')[:300]!r}")
        _check_challenge(r)
        session_token = _next_auth_session(r) or session_token

        # Read identify's verdict: a password fallback means the account already
        # exists (this will just log in); its absence means a new address, where
        # authenticate/email_otp should come back asking for profile fields.
        try:
            identify_json = r.json()
        except ValueError:
            identify_json = {}
        fallbacks = (((identify_json.get("nextStepConfig") or {}).get("emailOtp") or {})
                     .get("fallbackChallenges") or [])
        exists = any("password" in (fb or {}) for fb in fallbacks)
        print(f"  identify verdict: account {'EXISTS (this will behave as a login)' if exists else 'appears NEW (expect a profile next-step)'}")

        otp = _collect_otp(email)

        # The real captured endpoint and body: identify + otp, exactly as login.
        # No invented path, no guessed profile fields.
        old_body = json.loads(authenticate_rec.get("request_body") or "{}")
        old_otp = (((old_body.get("steps") or [{}, {}])[1] or {}).get("emailOtpChallenge") or {}).get("otp")
        authenticate_body = (authenticate_rec.get("request_body") or "").replace("{{email}}", email)
        if old_otp:
            authenticate_body = authenticate_body.replace(old_otp, otp)
        else:
            print("  WARNING: could not find the captured OTP value to replace — body still carries the stale one")

        print(f"  POST {authenticate_rec['url'].split('?')[0]} (submits email + fresh otp)")
        r = _post(client, authenticate_rec, authenticate_body, auth_session=session_token, ids=attempt_ids)
        print(f"    -> {r.status_code}  {(r.text or '')[:400]!r}")
        _check_challenge(r)

        try:
            parsed = r.json()
        except ValueError:
            parsed = None

        authed = isinstance(parsed, dict) and isinstance(parsed.get("authentication"), dict) \
            and bool(parsed["authentication"].get("userId"))
        if authed:
            print(f"\n  AUTH ESTABLISHED (userId {parsed['authentication'].get('userId')}) — "
                  f"{'logged in to the existing account' if exists else 'account created'}")
            return

        # Not authenticated: for a new address airbnb hands back the next step it
        # wants. Surface it verbatim — that IS the signup leg's spec, straight
        # from airbnb, to build/record next.
        next_step = isinstance(parsed, dict) and parsed.get("nextStepConfig")
        if next_step:
            print("\n  NOT yet authenticated — airbnb wants another step. Its spec (build the signup leg from this):")
            print(json.dumps(next_step, indent=2)[:1200])
        else:
            print("\n  NOT authenticated and no next-step config returned — check the response body above.")


if __name__ == "__main__":
    main()
