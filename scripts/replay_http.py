"""Replay the LOGIN leg of an RP over pure HTTP (no browser).

Reads the flow descriptor (data/http/<rp>.json) to know which request is the
login POST and which body fields carry the credentials, then:

  1. GET the login page and scrape its <form> (grabs every hidden field live —
     CSRF token, anti-bot timestamps, honeypots — so we submit exactly what the
     page would).
  2. Fill the descriptor's templated fields ({{email}}/{{password}}) from the
     credential vault; leave every other hidden field as the page rendered it.
  3. POST to the form action with a realistic browser header set and a cookie jar.
  4. Report whether a session was established.

The WebAuthn ceremony legs are NOT replayed here — those need the software
authenticator (deferred). This is the login foundation the ceremony builds on.

Usage:
    python -m scripts.replay_http --rp github.com --login-url https://github.com/login
"""
from __future__ import annotations

import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from src.lib import credentials
from src.lib.soft_authenticator import SoftAuthenticator, b64url_decode

HTTP_DIR = Path("data/http")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
BASE_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}


class _Form:
    def __init__(self, action: str, method: str):
        self.action = action
        self.method = (method or "get").lower()
        self.fields: dict[str, str] = {}
        self.has_password = False


class _FormParser(HTMLParser):
    """Collect every <form> and its input/select/textarea name=value pairs."""

    def __init__(self):
        super().__init__()
        self.forms: list[_Form] = []
        self._cur: _Form | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = _Form(a.get("action", ""), a.get("method", "get"))
            self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            name = a.get("name")
            if not name:
                return
            self._cur.fields[name] = a.get("value", "")
            if a.get("type", "").lower() == "password":
                self._cur.has_password = True

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def _login_entry(descriptor: dict) -> dict | None:
    for e in descriptor.get("flow", []):
        if e.get("tag") == "login" and "{{password}}" in (e.get("login_fields") or {}).values():
            return e
    return None


def _pick_form(forms: list[_Form], field_names: set[str]) -> _Form | None:
    # prefer a form that has a password input AND carries the descriptor's fields
    scored = []
    for f in forms:
        score = (1 if f.has_password else 0) + len(field_names & set(f.fields))
        scored.append((score, f))
    scored.sort(key=lambda t: t[0], reverse=True)
    return scored[0][1] if scored and scored[0][0] > 0 else None


# cookie names that reliably indicate an authenticated session across RPs
_AUTH_COOKIE_HINTS = ("user_session", "logged_in", "dotcom_user", "sessionid",
                      "sid", "auth", "sso", "session_token")


def _looks_logged_in(client: httpx.Client, rp_id: str, final_url: str) -> tuple[bool, str]:
    # 1. authenticated-session cookie present? (most reliable, RP-agnostic)
    names = {c.name.lower(): (c.value or "") for c in client.cookies.jar}
    for hint in _AUTH_COOKIE_HINTS:
        for name, val in names.items():
            if hint in name and val and val.lower() not in ("", "no", "false", "0"):
                masked = (val[:4] + "…") if len(val) > 4 else "set"   # never print the full session token
                return True, f"auth cookie {name} present ({masked})"
    # 2. probe an auth-required page WITHOUT following redirects — a bounce to a
    #    login/sign-in URL means we are not authenticated.
    if "/login" in final_url or "/session" in final_url:
        return False, f"landed back on an auth page: {final_url}"
    try:
        r = client.get(f"https://{rp_id}/", headers=BASE_HEADERS, follow_redirects=False)
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and any(
                k in loc.lower() for k in ("login", "signin", "sign_in", "session")):
            return False, f"root redirects to auth: {loc}"
        return True, f"root returned {r.status_code}, no auth redirect"
    except Exception as e:
        return False, f"could not verify root: {e}"


def _origin(url: str) -> str:
    u = urlparse(url)
    return f"{u.scheme}://{u.netloc}"


def _enclosing_object(s: str, anchor: str) -> str | None:
    """Return the smallest well-formed JSON object substring containing `anchor`."""
    i = s.find(anchor)
    if i < 0:
        return None
    depth, start = 0, None
    for j in range(i, -1, -1):
        c = s[j]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                start = j
                break
            depth -= 1
    if start is None:
        return None
    depth = 0
    for k in range(start, len(s)):
        if s[k] == "{":
            depth += 1
        elif s[k] == "}":
            depth -= 1
            if depth == 0:
                return s[start:k + 1]
    return None


def login(client: httpx.Client, rp_id: str, login_url: str, descriptor: dict) -> tuple[bool, str]:
    entry = _login_entry(descriptor)
    if not entry:
        raise SystemExit("descriptor has no login step with a {{password}} field")
    fields = entry["login_fields"]
    placeholders = {v: k for k, v in fields.items()}
    print(f"  login endpoint (descriptor): {entry['method']} {entry['url']}  fields={fields}")

    r = client.get(login_url, headers=BASE_HEADERS)
    print(f"  GET {login_url} -> {r.status_code}")
    parser = _FormParser()
    parser.feed(r.text)
    form = _pick_form(parser.forms, set(fields.keys()))
    if not form:
        return False, "could not find the login form on the page"
    action = urljoin(str(r.url), form.action) or entry["url"]

    payload = dict(form.fields)   # keep every hidden field (CSRF, timestamps, honeypot)
    if "{{email}}" in placeholders:
        payload[placeholders["{{email}}"]] = credentials.resolve("email", rp_id=rp_id)
    if "{{password}}" in placeholders:
        payload[placeholders["{{password}}"]] = credentials.resolve("password", rp_id=rp_id)

    post_headers = {**BASE_HEADERS, "Origin": _origin(login_url), "Referer": login_url,
                    "Content-Type": "application/x-www-form-urlencoded"}
    resp = client.post(action, data=payload, headers=post_headers)
    chain = " -> ".join(str(h.status_code) for h in resp.history) or "(none)"
    print(f"  POST {action} -> {resp.status_code}  redirects: {chain}  final: {resp.url}")
    return _looks_logged_in(client, rp_id, str(resp.url))


def register_passkey(client: httpx.Client, rp_id: str, begin_url: str,
                     finish_url: str, origin: str) -> tuple[bool, str]:
    """Run the WebAuthn registration ceremony over HTTP with the software
    authenticator: GET options -> fabricate attestation -> POST finish.
    """
    import html as _html
    auth = SoftAuthenticator()

    r = client.get(begin_url, headers=BASE_HEADERS)
    print(f"  GET {begin_url} -> {r.status_code}")
    page = _html.unescape(r.text)
    opts_raw = _enclosing_object(page, "pubKeyCredParams")
    if not opts_raw:
        return False, "could not find creation options (pubKeyCredParams) on the begin page"
    opts = json.loads(opts_raw)
    rp = (opts.get("rp") or {}).get("id") or rp_id
    challenge = b64url_decode(opts["challenge"])
    offered = [p.get("alg") for p in opts.get("pubKeyCredParams", [])]
    print(f"  options: rp={rp}  algs_offered={offered}  attestation={opts.get('attestation')}")

    # CSRF token for the finish form (the form posting to the finish endpoint)
    fparser = _FormParser()
    fparser.feed(r.text)
    token = None
    for f in fparser.forms:
        if "trusted_devices" in f.action or finish_url.endswith(f.action):
            token = f.fields.get("authenticity_token")
    if token is None:  # fall back to any authenticity_token on the page
        for f in fparser.forms:
            if "authenticity_token" in f.fields:
                token = f.fields["authenticity_token"]; break
    if not token:
        return False, "no authenticity_token found for the finish form"

    cred = auth.make_credential(rp_id=rp, challenge=challenge, origin=origin)
    print(f"  fabricated ES256 fmt:none credential id={cred['id'][:12]}…")

    # GitHub's finish payload: the RegistrationResponseJSON with only the fields
    # its client sends (clientDataJSON, attestationObject, transports).
    response_json = json.dumps({
        "type": "public-key",
        "id": cred["id"],
        "rawId": cred["rawId"],
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": cred["response"]["clientDataJSON"],
            "attestationObject": cred["response"]["attestationObject"],
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
    }, separators=(",", ":"))

    # multipart/form-data (GitHub requires it): plain fields via files= with no filename
    files = {"authenticity_token": (None, token), "response": (None, response_json)}
    fin_headers = {**BASE_HEADERS, "Origin": origin, "Referer": begin_url,
                   "Accept": "application/json"}
    resp = client.post(finish_url, files=files, headers=fin_headers)
    body = (resp.text or "")[:300]
    print(f"  POST {finish_url} -> {resp.status_code}")
    print(f"  server said: {body!r}")
    ok = resp.status_code in (200, 201)
    return ok, f"finish returned {resp.status_code}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True)
    ap.add_argument("--login-url", help="login page to scrape the form from (not needed for ajax RPs)")
    ap.add_argument("--register", action="store_true", help="also run the passkey registration ceremony")
    ap.add_argument("--begin-url", help="passkey registration begin page (default: github's)")
    ap.add_argument("--finish-url", help="passkey registration finish endpoint")
    args = ap.parse_args()

    desc_path = HTTP_DIR / f"{args.rp}.json"
    if not desc_path.exists():
        raise SystemExit(f"no descriptor at {desc_path} — run scripts.record_http first")
    descriptor = json.loads(desc_path.read_text(encoding="utf-8"))

    # Route ajax-style (obfuscated, session-token-gated) RPs to the ajax adapter.
    if descriptor.get("style") == "ajax":
        import asyncio
        from scripts import ajax_adapter
        print(f"  {args.rp} is an ajax-style RP — routing to ajax_adapter")
        asyncio.run(ajax_adapter.run(args.rp, do_auth=args.register))
        return

    if not args.login_url:
        raise SystemExit("--login-url is required for standard (non-ajax) RPs")
    origin = _origin(args.login_url)

    with httpx.Client(timeout=30, follow_redirects=True) as client:
        ok, why = login(client, args.rp, args.login_url, descriptor)
        print(f"\n  {'LOGGED IN' if ok else 'NOT logged in'} — {why}\n")
        if not ok or not args.register:
            return

        begin = args.begin_url or f"https://{args.rp}/sessions/trusted-device"
        finish = args.finish_url or f"https://{args.rp}/u2f/trusted_devices"
        ok, why = register_passkey(client, args.rp, begin, finish, origin)
        print(f"\n  {'PASSKEY REGISTERED' if ok else 'registration FAILED'} — {why}")


if __name__ == "__main__":
    main()
