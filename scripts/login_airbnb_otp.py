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
import random
import string
import uuid
from pathlib import Path

from curl_cffi import requests as cffi_requests
from dotenv import load_dotenv

from src.lib import credentials, imap_poll

load_dotenv()   # IMAP_USER/IMAP_PASS live in .env; imap_poll reads them from os.environ

RAW_PATH = Path("data/http/aibnb.com.raw.json")   # project's data uses this spelling
RP_ID_FOR_MAIL = "airbnb.com"                      # the real domain, for IMAP sender matching

_DROP_REQUEST_HEADERS = {"cookie", "content-length", "host"}

# Per-request / per-attempt values the browser mints fresh each time. Replaying
# the captured ones re-sends identical IDs on every run. The two fingerprint
# headers come from a client-side script (timestamped token + visitor id) that
# plain HTTP can't run, so they are omitted rather than replayed stale or forged.
_RANDOM_ID_HEADERS = ("x-airbnb-client-trace-id", "x-client-request-id", "x-airbnb-network-log-link")
_OMIT_HEADERS = {"x-fingerprint-request-token", "x-fingerprint-visitor-id"}
_ALPHABET = string.digits + string.ascii_lowercase

# Tier 1 of the tiered approach (plain HTTP -> TLS impersonation -> real
# browser): curl_cffi reproduces Chrome's JA3/JA4 + HTTP/2 handshake, so the
# client matches the Chrome that recorded the captured headers. Plain httpx is
# Tier 0 and presents an OpenSSL fingerprint that contradicts those headers.
IMPERSONATE = "chrome"
_CHALLENGE_MARKERS = ("airlock", "captcha", "enable javascript")


def _raw_records() -> list[dict]:
    return json.loads(RAW_PATH.read_text(encoding="utf-8"))


def _find(records: list[dict], url_suffix: str) -> dict | None:
    for rec in records:
        if (rec.get("method") or "").upper() == "POST" and rec.get("url", "").split("?")[0].endswith(url_suffix):
            return rec
    return None


def _rand_id(n: int = 28) -> str:
    return "".join(random.choices(_ALPHABET, k=n))


def _carry_headers(rec: dict, overrides: dict | None = None) -> dict:
    out = {k: v for k, v in (rec.get("request_headers") or {}).items()
           if not k.lower().startswith(":") and k.lower() not in _DROP_REQUEST_HEADERS
           and k.lower() not in _OMIT_HEADERS}
    for h in _RANDOM_ID_HEADERS:
        if h in out:
            out[h] = _rand_id()
    if overrides:
        out.update(overrides)
    return out


def _post(client: cffi_requests.Session, rec: dict, body_text: str, auth_session: str | None,
          ids: dict[str, str]) -> cffi_requests.Response:
    overrides = dict(ids)
    if auth_session is not None:
        overrides["x-airbnb-auth-session"] = auth_session
    headers = _carry_headers(rec, overrides)
    return client.request(rec["method"], rec["url"], headers=headers, data=body_text.encode())


def _check_challenge(r: cffi_requests.Response) -> None:
    """Stop (don't escalate evasion) when airbnb answers with an Airlock/challenge."""
    body = (r.text or "")[:2000].lower()
    # A wrong/expired OTP is a 403 too, but it's not a bot block — call it what it
    # is so it isn't mistaken for an airlock (usually means the OTP picker chose a
    # stale code; re-run and it should pick the newest).
    if "incorrect_verification_code" in body or "incorrectverificationcode" in body:
        raise SystemExit(f"OTP rejected as incorrect (HTTP {r.status_code}) — likely a stale code was submitted; re-run")
    if r.status_code in (403, 429) or any(m in body for m in _CHALLENGE_MARKERS):
        raise SystemExit(f"challenge/airlock detected (HTTP {r.status_code}): {body[:200]!r}\n"
                         "  Tier 1 insufficient or account is airlocked — resolve it in a real browser "
                         "(scripts/open_profile.py) and retry after a cool-down.")


def _next_auth_session(resp: cffi_requests.Response) -> str | None:
    for k, v in resp.headers.items():
        if k.lower() == "x-airbnb-set-auth-session":
            return v
    return None


def _warm_cookies(client: cffi_requests.Session, options_rec: dict) -> None:
    """Fresh page load first, like the browser: sets the first-party cookies
    the captured requests carried (the script otherwise sends no cookie)."""
    home = client.get("https://www.airbnb.com/",
                      headers={"user-agent": options_rec["request_headers"].get("user-agent", ""),
                               "accept-language": "en-US,en;q=0.9"})
    print(f"  GET / -> {home.status_code}, {len(client.cookies)} cookies")
    _check_challenge(home)


def _new_ids(with_attempt: bool = False) -> dict[str, str]:
    """One auth-session-id per login; one auth-attempt per step group (identify
    + otp share it in the capture, options has none)."""
    ids = {"x-airbnb-auth-session-id": str(uuid.uuid4())}
    if with_attempt:
        ids["x-airbnb-auth-attempt"] = str(uuid.uuid4())
    return ids


def _collect_otp(email: str, exclude: list[str] | None = None) -> str:
    """Mail-poll for the login/airlock OTP and return the code to submit.

    airbnb invalidates older codes when it issues a new one, so the valid code is
    the one from the NEWEST email. find_verification's call order is not reliably
    newest-first (it once returned a stale code first), so we can't pick by
    position — instead we enumerate every candidate in the window and pick the one
    with the latest received_at timestamp. That also excludes codes left over from
    earlier runs, which is what made a stale code get submitted and rejected.

    `exclude`: code values already consumed earlier in the same run (e.g. the
    login OTP when a passkey-registration airlock then mails its own code)."""
    print(f"  collecting OTP codes mailed to {email} ...")
    seen: list[str] = list(exclude or [])
    found_codes: list[tuple[str, str]] = []   # (received_at, value)
    first_timeout = 120   # wait properly for the first one to land at all
    while True:
        found = imap_poll.find_verification(RP_ID_FOR_MAIL, timeout_seconds=first_timeout,
                                            prefer_code=True, newer_than_seconds=120,
                                            lookback_minutes=2,
                                            exclude_values=seen)
        if not found or found.method != "code":
            break
        print(f"    code {len(found_codes) + 1}: {found.value!r} at {found.received_at} (subject: {found.subject!r})")
        found_codes.append((found.received_at, found.value))
        seen.append(found.value)
        first_timeout = 15   # short: just long enough to catch a near-simultaneous second mail
    if not found_codes:
        raise SystemExit("no OTP code found in mail within the timeout")
    received_at, otp = max(found_codes, key=lambda c: c[0])   # newest email wins
    print(f"  using code {otp!r} ({len(found_codes)} found, picked the newest by received_at {received_at})")
    return otp


def login(client: cffi_requests.Session, records: list[dict]) -> str | None:
    """Run the options -> identify -> authenticate OTP login on `client` and
    return the authenticated userId (or None). Shared by the login script and
    by passkey registration, which needs an authenticated session first."""
    options_rec = _find(records, "/auth/options")
    identify_rec = _find(records, "/auth/identify/email")
    authenticate_rec = _find(records, "/auth/authenticate/email_otp")
    if not (options_rec and identify_rec and authenticate_rec):
        raise SystemExit("could not find all three captured auth requests in the raw log")

    email = credentials.resolve("email", rp_id=RP_ID_FOR_MAIL)
    _warm_cookies(client, options_rec)
    session_ids = _new_ids()
    attempt_ids = _new_ids(with_attempt=True)

    print(f"  POST {options_rec['url'].split('?')[0]} (opens the session chain)")
    r = _post(client, options_rec, options_rec.get("request_body") or "", auth_session=None, ids=session_ids)
    print(f"    -> {r.status_code}")
    _check_challenge(r)
    session_token = _next_auth_session(r)
    if not session_token:
        raise SystemExit("auth/options did not hand back an x-airbnb-set-auth-session header — can't continue")

    identify_body = (identify_rec.get("request_body") or "").replace("{{email}}", email)
    print(f"  POST {identify_rec['url'].split('?')[0]} (submits email, triggers the OTP email)")
    r = _post(client, identify_rec, identify_body, auth_session=session_token, ids=attempt_ids)
    print(f"    -> {r.status_code}  {(r.text or '')[:200]!r}")
    _check_challenge(r)
    session_token = _next_auth_session(r) or session_token

    old_body = json.loads(authenticate_rec.get("request_body") or "{}")
    old_otp = (((old_body.get("steps") or [{}, {}])[1] or {}).get("emailOtpChallenge") or {}).get("otp")
    otp = _collect_otp(email)
    authenticate_body = (authenticate_rec.get("request_body") or "").replace("{{email}}", email)
    if old_otp:
        authenticate_body = authenticate_body.replace(old_otp, otp)
    else:
        print("  WARNING: could not find the captured OTP value to replace — body still carries the stale one")

    print(f"  POST {authenticate_rec['url'].split('?')[0]} (submits email + fresh otp)")
    r = _post(client, authenticate_rec, authenticate_body, auth_session=session_token, ids=attempt_ids)
    print(f"    -> {r.status_code}  {(r.text or '')[:300]!r}")
    _check_challenge(r)
    try:
        parsed = r.json()
    except ValueError:
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("authentication"), dict):
        return parsed["authentication"].get("userId")
    return None


def main() -> None:
    records = _raw_records()
    with cffi_requests.Session(impersonate=IMPERSONATE, timeout=30) as client:
        user_id = login(client, records)
    print(f"\n  {'LOGGED IN (userId ' + str(user_id) + ')' if user_id else 'NOT logged in'}")


if __name__ == "__main__":
    main()
