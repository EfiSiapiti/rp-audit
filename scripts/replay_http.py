"""Replay the LOGIN + passkey legs of an RP over pure HTTP (no browser).

Reads the flow descriptor (data/http/<rp>.json) to know which request is the
login POST and which body fields carry the credentials, then:

  1. GET the login page and scrape its <form> (grabs every hidden field live —
     CSRF token, anti-bot timestamps, honeypots — so we submit exactly what the
     page would).
  2. Fill the descriptor's templated fields ({{email}}/{{password}}) from the
     credential vault; leave every other hidden field as the page rendered it.
  3. POST to the form action with a realistic browser header set and a cookie jar.
  4. Report whether a session was established.

With --register it also runs the registration ceremony with the software
authenticator; with --authenticate it then logs in with that fabricated passkey
over HTTP from a fresh (password-less) session — one SoftAuthenticator spans both
legs so the key stays consistent.

The passkey legs are replayed PER REQUEST rather than against one assumed wire
shape: each begin/finish is cloned from exactly what the raw capture recorded
(method, custom headers like a Next.js `next-action` id, body shape — JSON
dict, JSON list, or a credential stringified under an opaque key) and only the
WebAuthn-specific fields are substituted, using http_flow's generic locator
helpers. That is what lets the same code handle a clean JSON API (archidekt),
an RP that renames every field and gates calls behind a live session header
(canva's `_ajax` endpoints — see borrow_session), and a Next.js Server Action
where begin AND finish POST to the IDENTICAL url with the response wrapped in
a react-server-component text stream (bird.com) — without a per-RP branch.

Usage:
    python -m scripts.replay_http --rp github.com --login-url https://github.com/login
    python -m scripts.replay_http --rp github.com --login-url https://github.com/login --register --authenticate
    python -m scripts.replay_http --rp canva.com --register   # ajax RP: session is borrowed from a real browser
"""
from __future__ import annotations

import argparse
import asyncio
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from src.lib import credentials, http_flow
from src.lib.soft_authenticator import SoftAuthenticator, b64url_decode

HTTP_DIR = Path("data/http")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
_SENTINEL_ORIG = object()   # "replay the body as originally captured" (vs. an explicit override, incl. None)

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


def derive_login_url(rp_id: str, entry: dict) -> tuple[str, str]:
    """Find the page the login form actually lived on, from the raw capture.

    The Referer header on the login POST is the page the browser was on when it
    submitted — i.e. the real login page, scraped straight from what was
    recorded, with no guessed path. Returns (url, how) where `how` says whether
    it came from the capture or had to fall back to a guess.
    """
    raw_path = HTTP_DIR / f"{rp_id}.raw.json"
    if raw_path.exists():
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        for rec in raw:
            if rec.get("method") != entry.get("method") or rec.get("url") != entry.get("url"):
                continue
            headers = {k.lower(): v for k, v in (rec.get("request_headers") or {}).items()}
            ref = headers.get("referer")
            if ref:
                return ref, "referer on the captured login POST"
            break   # matched the request but it carried no Referer; stop looking
    return _origin(entry["url"]) + "/", "no Referer captured — falling back to the site's origin"


def derive_register_urls(descriptor: dict) -> tuple[str | None, str | None]:
    """Pull the RP's own webauthn_register_begin/finish URLs straight out of the
    descriptor, instead of defaulting to github's endpoints. None, None if this
    RP's capture never recorded a passkey registration."""
    begin = finish = None
    for e in descriptor.get("flow", []):
        if e.get("tag") == "webauthn_register_begin" and begin is None:
            begin = e.get("url")
        elif e.get("tag") == "webauthn_register_finish" and finish is None:
            finish = e.get("url")
    return begin, finish

def derive_auth_urls(descriptor: dict) -> tuple[str | None, str | None]:
    """Pull the RP's own webauthn_auth_begin/finish URLs out of the descriptor
    (the passwordless-login equivalent of derive_register_urls)."""
    begin = finish = None
    for e in descriptor.get("flow", []):
        if e.get("tag") == "webauthn_auth_begin" and begin is None:
            begin = e.get("url")
        elif e.get("tag") == "webauthn_auth_finish" and finish is None:
            finish = e.get("url")
    return begin, finish

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


def login(client: httpx.Client, rp_id: str, login_url: str, descriptor: dict) -> tuple[bool, str]:
    entry = _login_entry(descriptor)
    if not entry:
        raise SystemExit("descriptor has no login step with a {{password}} field")
    fields = entry["login_fields"]
    placeholders = {v: k for k, v in fields.items()}
    print(f"  login endpoint (descriptor): {entry['method']} {entry['url']}  fields={fields}")

    r = client.get(login_url, headers=BASE_HEADERS)
    print(f"  GET {login_url} -> {r.status_code}")

    if "json" in (entry.get("request_content_type") or "").lower():
        # The real login is a JSON API call (e.g. a React/SPA front end posting
        # straight to a REST endpoint) — the page's own <form>, if any, may use
        # different field names entirely (archidekt's visible form uses
        # "username"; the actual API call sends "email"). Clone the ORIGINAL
        # captured body instead of trusting the scraped form.
        orig = next((rec for rec in _raw_records(rp_id)
                    if rec.get("method") == entry["method"] and rec.get("url") == entry["url"]), None)
        orig_body = (http_flow.parse_body((orig or {}).get("request_body"), entry.get("request_content_type"))
                    if orig else None)
        payload = dict(orig_body) if isinstance(orig_body, dict) else {}
        if "{{email}}" in placeholders:
            payload[placeholders["{{email}}"]] = credentials.resolve("email", rp_id=rp_id)
        if "{{password}}" in placeholders:
            payload[placeholders["{{password}}"]] = credentials.resolve("password", rp_id=rp_id)
        post_headers = {**BASE_HEADERS, "Origin": _origin(login_url), "Referer": login_url,
                        "Content-Type": "application/json", "Accept": "application/json"}
        resp = client.post(entry["url"], json=payload, headers=post_headers)
        chain = " -> ".join(str(h.status_code) for h in resp.history) or "(none)"
        print(f"  POST {entry['url']} -> {resp.status_code}  redirects: {chain}  final: {resp.url}")
        # resp.url IS the API endpoint (e.g. .../api/rest-auth/login/, which
        # itself contains "login") — pass "" so that doesn't false-trip the
        # "bounced back to a login page" shortcut below.
        return _looks_logged_in(client, rp_id, "")

    parser = _FormParser()
    parser.feed(r.text)
    form = _pick_form(parser.forms, set(fields.keys()))
    if not form:
        # JS-rendered form (React/Next.js controlled inputs render no
        # server-side name=value pairs to scrape, even though the browser
        # did send a real multipart submission — e.g. bird.com). Fall back
        # to cloning the ORIGINAL captured request's raw body+headers
        # verbatim and substituting the placeholders in the raw text,
        # rather than trying to reconstruct it from a <form> that isn't
        # there.
        orig = next((rec for rec in _raw_records(rp_id)
                    if (rec.get("method") or "").upper() == "POST"
                    and "{{password}}" in (rec.get("request_body") or "")), None)
        if not orig:
            return False, "could not find the login form on the page, and no raw request to clone"
        raw_body = orig["request_body"].replace("{{password}}", credentials.resolve("password", rp_id=rp_id))
        if "{{email}}" in raw_body:
            raw_body = raw_body.replace("{{email}}", credentials.resolve("email", rp_id=rp_id))
        resp = _replay_captured(client, orig, body=raw_body,
                               header_overrides={"Origin": _origin(login_url), "Referer": login_url})
        chain = " -> ".join(str(h.status_code) for h in resp.history) or "(none)"
        print(f"  {orig['method']} {orig['url']} -> {resp.status_code}  redirects: {chain}  final: {resp.url}")
        return _looks_logged_in(client, rp_id, str(resp.url))
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


def _raw_records(rp_id: str) -> list[dict]:
    p = HTTP_DIR / f"{rp_id}.raw.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _raw_record_for_tag(rp_id: str, tag: str, index: int = 0) -> dict | None:
    """The index-th raw request classified with this WebAuthn tag — matched by
    TAG, not by url+method: some RPs (bird.com's Next.js Server Actions) POST
    both the begin and the finish to the identical url, distinguished only by
    a per-request header (`next-action`) and body shape."""
    matches = [rec for rec in _raw_records(rp_id) if http_flow.classify_webauthn(rec) == tag]
    return matches[index] if index < len(matches) else None


# headers that must never be replayed verbatim: pseudo-headers, the stale
# captured cookie (the live client's own jar supplies the current one), and
# content-length (recomputed from whatever body we actually send).
_DROP_REQUEST_HEADERS = {"cookie", "content-length", "host"}

# a live value borrowed from a real browser session (see borrow_session) —
# overrides the stale captured value of that header on every replay, e.g.
# canva's x-*-authz session token, which is minted fresh client-side and
# can't be replayed from a static capture.
_LIVE_HEADER_OVERRIDES: dict[str, str] = {}


def _carry_headers(rec: dict, overrides: dict | None = None) -> dict:
    """Headers to replay a captured request with: everything it originally
    carried — accept/content-type, and any RP-specific header a generic
    client would never think to set (next-action, x-deployment-id, a
    minified ajax API's custom headers) — minus the ones above, with any
    borrowed live value substituted in."""
    out = {k: v for k, v in (rec.get("request_headers") or {}).items()
           if not k.lower().startswith(":") and k.lower() not in _DROP_REQUEST_HEADERS}
    for k in out:
        if k.lower() in _LIVE_HEADER_OVERRIDES:
            out[k] = _LIVE_HEADER_OVERRIDES[k.lower()]
    if overrides:
        out.update(overrides)
    return out


def _replay_captured(client: httpx.Client, rec: dict, *, body=_SENTINEL_ORIG,
                     header_overrides: dict | None = None) -> httpx.Response:
    """Replay a captured request near-verbatim against the live client: same
    method/url/headers, same body unless `body` overrides it (a dict/list is
    JSON-encoded to match how these bodies are always sent on the wire; a str
    is sent as-is; None sends no body)."""
    headers = _carry_headers(rec, header_overrides)
    if body is _SENTINEL_ORIG:
        orig = rec.get("request_body")
        content = orig.encode() if isinstance(orig, str) else None
    elif body is None:
        content = None
    elif isinstance(body, str):
        content = body.encode()
    else:
        content = json.dumps(body, separators=(",", ":")).encode()
    return client.request(rec["method"], rec["url"], headers=headers, content=content)


def _safe_get_path(obj, path):
    """http_flow.get_path, but None instead of a crash when the live object
    doesn't actually have that shape — e.g. a 403/challenge page returned
    instead of the real begin options (not actually logged in)."""
    try:
        return http_flow.get_path(obj, path)
    except (KeyError, IndexError, TypeError):
        return None


def _shape_credential(cred: dict, *, assertion: bool) -> dict:
    r = cred["response"]
    if assertion:
        return {"id": cred["id"], "rawId": cred["rawId"], "type": "public-key",
                "response": {"authenticatorData": r["authenticatorData"],
                             "clientDataJSON": r["clientDataJSON"],
                             "signature": r["signature"], "userHandle": r.get("userHandle") or ""},
                "clientExtensionResults": {}}
    return {"id": cred["id"], "rawId": cred["rawId"], "type": "public-key",
            "response": {"attestationObject": r["attestationObject"],
                         "clientDataJSON": r["clientDataJSON"]},
            "clientExtensionResults": {}}


def _register_legacy_multipart(client: httpx.Client, begin_resp: httpx.Response, finish_url: str,
                               origin: str, cred: dict) -> tuple[bool, str]:
    """Fallback for RPs with no JSON/structured finish body at all (GitHub: a
    <form> on the begin page carries an authenticity_token; the finish POST
    is multipart with that token plus the response JSON) — the one shape the
    generic clone-the-captured-body engine below can't handle, because there
    is no captured body to clone from."""
    fparser = _FormParser()
    fparser.feed(begin_resp.text)
    token = None
    for f in fparser.forms:
        if "trusted_devices" in f.action or finish_url.endswith(f.action):
            token = f.fields.get("authenticity_token")
    if token is None:
        for f in fparser.forms:
            if "authenticity_token" in f.fields:
                token = f.fields["authenticity_token"]; break
    if not token:
        return False, "no authenticity_token found for the finish form"

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
    files = {"authenticity_token": (None, token), "response": (None, response_json)}
    fin_headers = {**BASE_HEADERS, "Origin": origin, "Referer": str(begin_resp.url), "Accept": "application/json"}
    resp = client.post(finish_url, files=files, headers=fin_headers)
    body = (resp.text or "")[:300]
    print(f"  POST {finish_url} -> {resp.status_code}")
    print(f"  server said: {body!r}")
    ok = resp.status_code in (200, 201)
    return ok, f"finish returned {resp.status_code}"


def register_passkey(client: httpx.Client, rp_id: str, begin_url: str,
                     finish_url: str, origin: str, auth: SoftAuthenticator) -> tuple[bool, str]:
    """Run the WebAuthn registration ceremony over HTTP with the software
    authenticator: replay the captured begin request -> fabricate the
    attestation from whatever options it returns -> replay the captured
    finish request with the credential (and any id the finish echoes back
    from the begin) spliced in.

    Each leg is cloned from the RAW capture of that exact request — method,
    custom headers (a Next.js `next-action` id, an ajax API's session header,
    …), body shape (JSON dict, JSON list, or a credential stringified under
    an opaque key) — rather than assumed to be a GET+HTML-scrape or a plain
    JSON POST. That's what makes this one path work for a clean JSON API, a
    Next.js Server Action (begin AND finish POST to the IDENTICAL url — see
    bird.com), and an RP that renames every field (falls back to locating the
    challenge/rp-id by value+position instead of by name — see canva.com).

    Uses the caller's `auth` so the fabricated key persists for a later
    authenticate_passkey() in the same run.
    """
    begin_rec = _raw_record_for_tag(rp_id, "webauthn_register_begin")
    finish_rec = _raw_record_for_tag(rp_id, "webauthn_register_finish")
    if not begin_rec or not finish_rec:
        return False, "no captured register begin/finish request to replay (re-run scripts.record_http)"

    finish_body = http_flow.parse_body(finish_rec.get("request_body"), finish_rec.get("request_content_type"))
    found = http_flow.find_credential_path(finish_body, ("attestationObject",)) if finish_body is not None else None

    r = _replay_captured(client, begin_rec)
    print(f"  {begin_rec['method']} {begin_rec['url']} -> {r.status_code}")

    new_opts = http_flow.locate_begin_options(r.text, "register")
    old_opts = http_flow.locate_begin_options(begin_rec.get("response_body") or "", "register")

    if new_opts is not None and old_opts is not None:
        challenge_b64 = http_flow.find_value(new_opts, "challenge")
        rp = (http_flow.find_value(new_opts, "rp") or {}).get("id") or rp_id
        user_id_b64 = (http_flow.find_value(new_opts, "user") or {}).get("id")
        user_id = b64url_decode(user_id_b64) if user_id_b64 else None
        offered = [p.get("alg") for p in (http_flow.find_value(new_opts, "pubKeyCredParams") or [])]
    else:
        # Renamed/minified fields (ajax RPs like canva): cross-reference the
        # challenge and rp id by VALUE + POSITION against the old capture
        # instead of by name.
        if not found:
            return False, "could not find creation options (pubKeyCredParams) in the begin response"
        _, old_inner, _ = found
        old_challenge, old_origin = http_flow.clientdata_challenge_origin(old_inner)
        old_opts = http_flow.parse_body(begin_rec.get("response_body"), begin_rec.get("response_content_type"))
        new_opts = http_flow.parse_body(r.text, r.headers.get("content-type"))
        if old_opts is None or new_opts is None or old_challenge is None:
            return False, "could not find creation options (pubKeyCredParams) in the begin response"
        mapping = http_flow.infer_obfuscated_begin_paths(old_opts, old_challenge, old_origin)
        if "challenge_path" not in mapping:
            return False, "ajax RP: could not locate the challenge in the begin response (renamed fields)"
        challenge_b64 = _safe_get_path(new_opts, mapping["challenge_path"])
        if challenge_b64 is None:
            return False, (f"live begin response doesn't match the captured shape at "
                           f"{mapping['challenge_path']} — likely not actually logged in "
                           f"(blocked/redirected instead of the real options)")
        rp = (_safe_get_path(new_opts, mapping["rpid_path"]) if mapping.get("rpid_path") else None) or rp_id
        user_id = None
        offered = None

    if not challenge_b64:
        return False, "begin response carried no challenge"
    challenge = b64url_decode(challenge_b64)
    print(f"  options: rp={rp}  algs_offered={offered or '(unknown — renamed fields)'}"
          f"  user.id={'captured' if user_id else 'absent'}")

    cred = auth.make_credential(rp_id=rp, challenge=challenge, origin=origin, user_id=user_id)
    print(f"  fabricated ES256 fmt:none credential id={cred['id'][:12]}…")

    if found is None:
        return _register_legacy_multipart(client, r, finish_url, origin, cred)

    cred_path, _, stringified = found
    shaped = _shape_credential(cred, assertion=False)
    new_val = json.dumps(shaped, separators=(",", ":")) if stringified else shaped
    if cred_path:   # non-empty: the credential sits inside a wrapper (bird.com's list envelope, etc.)
        http_flow.set_path(finish_body, cred_path, new_val)
    else:           # cred_path == []: the WHOLE finish body IS the credential (groups.io) — set_path
        finish_body = new_val   # has no container to mutate into for an empty path, so reassign instead

    for fin_path, begin_path in http_flow.find_copy_fields(old_opts, finish_body, cred_path):
        try:
            new_val = http_flow.get_path(new_opts, begin_path)
        except (KeyError, IndexError, TypeError):
            continue
        http_flow.set_path(finish_body, fin_path, new_val)

    resp = _replay_captured(client, finish_rec, body=finish_body)
    body_preview = (resp.text or "")[:300]
    print(f"  {finish_rec['method']} {finish_rec['url']} -> {resp.status_code}")
    print(f"  server said: {body_preview!r}")
    ok = resp.status_code in (200, 201)
    return ok, f"finish returned {resp.status_code}"


def persist_fab_key(rp_id: str, auth: SoftAuthenticator) -> bool:
    """Write the HTTP-minted credential into data/fab_keys.json (hook.js's record
    shape) so the injected browser hook can load it and authenticate in-page —
    i.e. register over HTTP here, then sign in with that same key in a real
    browser you drive (scripts.drive_hooked)."""
    from scripts import hook_bridge
    record = auth.export_record(rp_id)
    if record is None:
        print("  persist: no credential to export")
        return False
    keys = hook_bridge._load_keys()
    keys[rp_id] = record
    hook_bridge._save_keys(keys)
    print(f"  persisted fabricated key -> {hook_bridge.FAB_KEYS_FILE} "
          f"(credId={record['credIdBase64'][:12]}…) — load it in a hooked browser to authenticate")
    return True


def _sign_request(page: str) -> dict | None:
    """Pull the conditional-webauthn options the login page embeds in the
    `data-webauthn-sign-request` attribute (an html-escaped JSON blob)."""
    import html as _html
    import re
    m = re.search(r'data-webauthn-sign-request="([^"]*)"', page)
    if not m:
        return None
    try:
        return json.loads(_html.unescape(m.group(1)))
    except json.JSONDecodeError:
        return None


def _webauthn_form(parser: _FormParser) -> _Form | None:
    """The hidden form that POSTs the assertion (carries a webauthn_response field)."""
    for f in parser.forms:
        if "webauthn_response" in f.fields:
            return f
    return None


def authenticate_passkey(client: httpx.Client, rp_id: str, login_url: str,
                         origin: str, auth: SoftAuthenticator,
                         begin_url: str | None = None, finish_url: str | None = None) -> tuple[bool, str]:
    """Log in with the fabricated passkey over HTTP (no password).

    Two shapes, mirrored from whatever the capture actually recorded:
    - A pure JSON WebAuthn API (begin_url/finish_url derived from the
      descriptor's own webauthn_auth_begin/finish steps): POST begin for the
      challenge, sign with the credential registered this run, POST finish —
      no HTML page or CSRF token involved.
    - GitHub's model (no such JSON endpoints captured): scrape the login
      page's data-webauthn-sign-request + authenticity_token instead.
    """
    if begin_url and finish_url:
        begin_rec = _raw_record_for_tag(rp_id, "webauthn_auth_begin")
        finish_rec = _raw_record_for_tag(rp_id, "webauthn_auth_finish")
        if not begin_rec or not finish_rec:
            return False, "no captured auth begin/finish request to replay (re-run scripts.record_http)"

        finish_body = http_flow.parse_body(finish_rec.get("request_body"), finish_rec.get("request_content_type"))
        required = ("authenticatorData", "signature")
        found = http_flow.find_credential_path(finish_body, required) if finish_body is not None else None

        r = _replay_captured(client, begin_rec)
        print(f"  {begin_rec['method']} {begin_rec['url']} -> {r.status_code}")

        new_opts = http_flow.locate_begin_options(r.text, "auth")
        old_opts = http_flow.locate_begin_options(begin_rec.get("response_body") or "", "auth")

        if new_opts is not None and old_opts is not None:
            challenge_b64 = http_flow.find_value(new_opts, "challenge")
            rp = (http_flow.find_value(new_opts, "rp") or {}).get("id") or http_flow.find_value(new_opts, "rpId") or rp_id
            allow = [b64url_decode(c["id"]) for c in (http_flow.find_value(new_opts, "allowCredentials") or [])] or None
        else:
            if not found:
                return False, "could not find assertion options (allowCredentials/rpId) in the begin response"
            _, old_inner, _ = found
            old_challenge, old_origin = http_flow.clientdata_challenge_origin(old_inner)
            old_opts = http_flow.parse_body(begin_rec.get("response_body"), begin_rec.get("response_content_type"))
            new_opts = http_flow.parse_body(r.text, r.headers.get("content-type"))
            if old_opts is None or new_opts is None or old_challenge is None:
                return False, "could not find assertion options (allowCredentials/rpId) in the begin response"
            mapping = http_flow.infer_obfuscated_begin_paths(old_opts, old_challenge, old_origin)
            if "challenge_path" not in mapping:
                return False, "ajax RP: could not locate the challenge in the begin response (renamed fields)"
            challenge_b64 = _safe_get_path(new_opts, mapping["challenge_path"])
            if challenge_b64 is None:
                return False, (f"live begin response doesn't match the captured shape at "
                               f"{mapping['challenge_path']} — likely not actually logged in")
            rp = (_safe_get_path(new_opts, mapping["rpid_path"]) if mapping.get("rpid_path") else None) or rp_id
            allow = None

        if not challenge_b64:
            return False, "begin response carried no challenge"
        assertion = auth.get_assertion(rp_id=rp, challenge=b64url_decode(challenge_b64), origin=origin, allow_credentials=allow)
        if assertion is None:
            return False, "authenticator holds no credential for this RP (register first, same run)"
        print(f"  signed assertion with credential id={assertion['id'][:12]}…  "
              f"userHandle={'set' if assertion['response']['userHandle'] else 'null'}")

        if found is None:
            return False, "finish request body has no recognizable credential shape to clone"

        cred_path, _, stringified = found
        shaped = _shape_credential(assertion, assertion=True)
        new_val = json.dumps(shaped, separators=(",", ":")) if stringified else shaped
        if cred_path:
            http_flow.set_path(finish_body, cred_path, new_val)
        else:
            finish_body = new_val

        for fin_path, begin_path in http_flow.find_copy_fields(old_opts, finish_body, cred_path):
            try:
                new_val = http_flow.get_path(new_opts, begin_path)
            except (KeyError, IndexError, TypeError):
                continue
            http_flow.set_path(finish_body, fin_path, new_val)

        resp = _replay_captured(client, finish_rec, body=finish_body)
        body_preview = (resp.text or "")[:300]
        print(f"  {finish_rec['method']} {finish_rec['url']} -> {resp.status_code}")
        print(f"  server said: {body_preview!r}")
        if resp.status_code not in (200, 201):
            return False, f"finish returned {resp.status_code}"
        try:
            parsed = resp.json()
        except Exception:
            parsed = None
        if isinstance(parsed, dict) and parsed.get("success") is True:
            return True, "finish response body says success:true"
        # No explicit success flag — fall back to the cookie/root-redirect check.
        # Pass "" rather than resp.url: resp.url IS the finish endpoint, whose own
        # path often contains "/login" (e.g. .../webauthn/login/.../finish), which
        # would false-trip _looks_logged_in's "bounced back to login" shortcut.
        return _looks_logged_in(client, rp_id, "")

    # --- GitHub-style HTML path: no JSON auth endpoints were captured ---
    r = client.get(login_url, headers=BASE_HEADERS)
    print(f"  GET {login_url} -> {r.status_code}")
    sr = _sign_request(r.text)
    parser = _FormParser(); parser.feed(r.text)
    form = _webauthn_form(parser)
    if not sr or not form:
        frag = f"https://{rp_id}/u2f/login_fragment?disable_signup=false&is_emu_login=false&mobile_ios=false"
        r = client.get(frag, headers={**BASE_HEADERS, "Accept": "text/html, */*; q=0.01",
                                      "X-Requested-With": "XMLHttpRequest", "Referer": login_url})
        print(f"  GET {frag} -> {r.status_code}")
        sr = sr or _sign_request(r.text)
        parser = _FormParser(); parser.feed(r.text)
        form = form or _webauthn_form(parser)
    if not sr:
        return False, "no data-webauthn-sign-request challenge on the login page"
    if not form or "authenticity_token" not in form.fields:
        return False, "no webauthn_response form / authenticity_token on the login page"

    pk = sr.get("publicKey") or {}
    rp = pk.get("rpId") or rp_id
    challenge = b64url_decode(pk["challenge"])
    allow = [b64url_decode(c["id"]) for c in pk.get("allowCredentials") or []] or None
    print(f"  challenge options: rpId={rp}  allowCredentials={len(allow or [])}  mediation={sr.get('mediation')}")

    assertion = auth.get_assertion(rp_id=rp, challenge=challenge, origin=origin, allow_credentials=allow)
    if assertion is None:
        return False, "authenticator holds no credential for this RP (register first, same run)"
    print(f"  signed assertion with credential id={assertion['id'][:12]}…  "
          f"userHandle={'set' if assertion['response']['userHandle'] else 'null'}")

    action = urljoin(str(r.url), form.action)
    payload = dict(form.fields)
    payload["authenticity_token"] = form.fields["authenticity_token"]
    payload["webauthn_response"] = json.dumps(assertion, separators=(",", ":"))
    post_headers = {**BASE_HEADERS, "Origin": origin, "Referer": login_url,
                    "Content-Type": "application/x-www-form-urlencoded"}
    resp = client.post(action, data=payload, headers=post_headers)
    chain = " -> ".join(str(h.status_code) for h in resp.history) or "(none)"
    print(f"  POST {action} -> {resp.status_code}  redirects: {chain}  final: {resp.url}")
    return _looks_logged_in(client, rp_id, str(resp.url))

def _authz_name(ajax_headers: list[str]) -> str | None:
    """The one captured custom header most likely to be a live session token
    client JS sets after load (ajax RPs like canva — their API calls 401
    without it, and nothing in a static capture can replay a value that's
    minted fresh in-browser each session)."""
    for kw in ("authz", "csrf", "session", "token"):
        for h in ajax_headers:
            if kw in h:
                return h
    return None


async def borrow_session(rp_id: str, warm_url: str, authz_name: str) -> dict:
    """Launch the already-logged-in persistent browser profile for this RP,
    load `warm_url`, and capture its cookies plus the live value of
    `authz_name` off an outgoing request — merged into _LIVE_HEADER_OVERRIDES
    so every subsequent _carry_headers() call picks it up automatically."""
    from src.lib import browser
    page = await browser.ensure_browser_for(rp_id, persist=True)
    ctx = page.context
    live: dict = {}

    def on_request(req):
        h = {k.lower(): v for k, v in req.headers.items()}
        if h.get(authz_name) and authz_name not in live:
            live[authz_name] = h[authz_name]

    ctx.on("request", on_request)
    await page.goto(warm_url, wait_until="domcontentloaded")
    for _ in range(30):
        if live:
            break
        await asyncio.sleep(0.5)
    cookies = {c["name"]: c["value"] for c in await ctx.cookies()}
    await browser.shutdown()
    print(f"  borrowed session: {len(cookies)} cookies, "
          f"{authz_name}={'captured' if live else 'MISSING'}")
    _LIVE_HEADER_OVERRIDES.update(live)
    return cookies


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True)
    ap.add_argument("--login-url", help="login page to scrape the form from (not needed for ajax RPs; "
                                        "omit it and it's derived from the Referer on the captured login POST)")
    ap.add_argument("--register", action="store_true", help="also run the passkey registration ceremony")
    ap.add_argument("--authenticate", action="store_true",
                    help="after registering, log in with that passkey over HTTP (fresh session, no password)")
    ap.add_argument("--persist-key", action="store_true",
                    help="write the registered key to data/fab_keys.json so a hooked browser "
                         "(scripts.drive_hooked) can authenticate with it by hand")
    ap.add_argument("--begin-url", help="passkey registration begin page (default: github's)")
    ap.add_argument("--finish-url", help="passkey registration finish endpoint")
    ap.add_argument("--warm-url", help="page to load when borrowing a live session for an RP whose API "
                                        "is gated behind a session header set by in-page JS (e.g. canva); "
                                        "default: the site origin")
    args = ap.parse_args()

    desc_path = HTTP_DIR / f"{args.rp}.json"
    if not desc_path.exists():
        raise SystemExit(f"no descriptor at {desc_path} — run scripts.record_http first")
    descriptor = json.loads(desc_path.read_text(encoding="utf-8"))

    entry = _login_entry(descriptor)
    login_url = args.login_url
    if not login_url and entry:
        login_url, how = derive_login_url(args.rp, entry)
        print(f"  login page (derived: {how}): {login_url}")

    authz_name = _authz_name(descriptor.get("ajax_headers") or [])
    if not login_url and not authz_name:
        raise SystemExit("descriptor has no login step with a {{password}} field — "
                         "nothing to derive a login URL from; pass --login-url")
    origin = _origin(login_url) if login_url else f"https://{args.rp}"

    borrowed_cookies = None
    if authz_name:
        warm = args.warm_url or (origin + "/")
        print(f"  {args.rp} gates its API behind a live session header ({authz_name}) — "
              f"borrowing it from an already-authenticated browser profile")
        borrowed_cookies = asyncio.run(borrow_session(args.rp, warm, authz_name))

    auth = SoftAuthenticator()   # one authenticator: the key must survive register -> authenticate

    with httpx.Client(timeout=30, follow_redirects=True, cookies=borrowed_cookies or None) as client:
        if borrowed_cookies is not None:
            ok, why = True, f"borrowed an already-authenticated browser session ({len(borrowed_cookies)} cookies)"
        else:
            ok, why = login(client, args.rp, login_url, descriptor)
        print(f"\n  {'LOGGED IN' if ok else 'NOT logged in'} — {why}\n")
        if not ok or not (args.register or args.authenticate):
            return

        d_begin, d_finish = derive_register_urls(descriptor)
        begin = args.begin_url or d_begin or f"https://{args.rp}/sessions/trusted-device"
        finish = args.finish_url or d_finish or f"https://{args.rp}/u2f/trusted_devices"
        if not args.begin_url or not args.finish_url:
            src = "descriptor's captured register step" if (d_begin or d_finish) else "github's defaults (none captured here — likely wrong)"
            print(f"  register begin/finish (derived: {src}): {begin}  |  {finish}")
        print("== REGISTER ==")
        ok, why = register_passkey(client, args.rp, begin, finish, origin, auth)
        print(f"\n  {'PASSKEY REGISTERED' if ok else 'registration FAILED'} — {why}")
        if ok and args.persist_key:
            persist_fab_key(args.rp, auth)
        if not ok or not args.authenticate:
            return

        if borrowed_cookies is not None:
            # The live session header stays tied to this one borrowed
            # session — a fresh client would lose it too, so there's no
            # "passkey alone" variant to demonstrate for these RPs.
            print("\n== AUTHENTICATE (same borrowed session) ==")
            a_begin, a_finish = derive_auth_urls(descriptor)
            ok, why = authenticate_passkey(client, args.rp, login_url or origin, origin, auth,
                                           begin_url=a_begin, finish_url=a_finish)
            print(f"\n  {'LOGGED IN WITH FABRICATED PASSKEY' if ok else 'passkey login FAILED'} — {why}")
            return

    # Fresh client = empty cookie jar, so a success proves the passkey ALONE
    # (no password, no carried-over session) logged us in.
    print("\n== AUTHENTICATE (passkey only, fresh session) ==")
    a_begin, a_finish = derive_auth_urls(descriptor)
    if a_begin or a_finish:
        print(f"  auth begin/finish (derived: descriptor's captured auth step): {a_begin}  |  {a_finish}")
    with httpx.Client(timeout=30, follow_redirects=True) as fresh:
        ok, why = authenticate_passkey(fresh, args.rp, login_url, origin, auth,
                                       begin_url=a_begin, finish_url=a_finish)
        print(f"\n  {'LOGGED IN WITH FABRICATED PASSKEY' if ok else 'passkey login FAILED'} — {why}")

if __name__ == "__main__":
    main()
