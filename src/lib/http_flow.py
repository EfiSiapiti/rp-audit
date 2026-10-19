"""Classify a captured HTTP flow into the requests that make up login and the
WebAuthn (passkey) register/authenticate ceremonies.

This is the "detect the HTTP requests" half of the HTTP-based audit: given a raw
capture of a hand-driven login + passkey run (see scripts/record_http.py), tag
each request by the *shape of its body*, not its URL — RP endpoint paths are all
custom, but the WebAuthn wire format is standard:

  register_begin   response JSON has  challenge + pubKeyCredParams
  register_finish  request  JSON has  attestationObject
  auth_begin       response JSON has  challenge (+ allowCredentials/rpId), no pubKeyCredParams
  auth_finish      request  JSON has  signature + authenticatorData
  login            POST carrying the identity email/password, or whose response
                   sets a session cookie; CSRF token located + traced to source

Secrets never reach disk: redact() strips the identity password/email/OTP and all
Cookie/Authorization/Set-Cookie *values* (names are kept) before a record is
buffered. The emitted descriptor (data/http/<rp>.json) is a replay-ready template
with {{password}}/{{email}}/{{otp}} placeholders where secrets were.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable
from urllib.parse import parse_qsl

# ---------------------------------------------------------------------------
# body parsing helpers
# ---------------------------------------------------------------------------

def parse_body(body: str | None, content_type: str | None) -> Any:
    """Best-effort structured view of a request/response body.

    Returns a dict/list for JSON, a dict for form-encoded, else None. We try
    JSON first regardless of content-type (many RPs mislabel), then fall back to
    x-www-form-urlencoded.
    """
    if not body:
        return None
    txt = body.strip()
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        pass
    ct = (content_type or "").lower()
    if "form-urlencoded" in ct or ("=" in txt and "{" not in txt[:1]):
        try:
            pairs = parse_qsl(txt, keep_blank_values=True)
            if pairs:
                return dict(pairs)
        except Exception:
            pass
    return None


def _walk(obj: Any) -> Iterable[tuple[str, Any]]:
    """Yield every (key, value) pair anywhere in a nested dict/list."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk(item)


def has_key(obj: Any, key: str) -> bool:
    """True if `key` appears anywhere in the nested structure (case-sensitive)."""
    return any(k == key for k, _ in _walk(obj))


def find_value(obj: Any, key: str) -> Any:
    """First value for `key` anywhere in the nested structure, else None."""
    for k, v in _walk(obj):
        if k == key:
            return v
    return None


# ---------------------------------------------------------------------------
# WebAuthn ceremony classification (RP-agnostic, by body shape)
# ---------------------------------------------------------------------------

# Third-party CAPTCHA / bot-detection vendors whose payloads reuse WebAuthn-ish
# words ("challenge", "public_key") and must never be classified as the RP's
# WebAuthn endpoint.
_CAPTCHA_HOSTS = (
    "arkoselabs.com", "funcaptcha.com", "hcaptcha.com", "recaptcha.net",
    "google.com/recaptcha", "gstatic.com/recaptcha", "challenges.cloudflare.com",
    "datadome.co", "perimeterx.net", "px-cloud.net", "captcha-delivery.com",
)

def classify_webauthn(rec: dict) -> str | None:
    """Return a webauthn tag for a captured request record, or None.

    Uses structured JSON detection when the body parses, and falls back to a
    raw-substring signal otherwise. The fallback matters because real RPs don't
    always send clean JSON: GitHub POSTs the register *finish* as multipart/form
    -data and embeds the begin *options* inside an HTML fragment — neither parses,
    but the WebAuthn field names are still present verbatim. For *detecting* which
    request is which, presence of the field name is enough.

    rec keys used: request_body, request_content_type, response_body,
    response_content_type.
    """
    # Third-party CAPTCHA / bot-detection vendors use "challenge" and "public_key"
    # in their own payloads (Arkose FunCaptcha themes, etc.) and would otherwise
    # trip the begin heuristics. They are never the RP's WebAuthn endpoint.
    url = (rec.get("url") or "").lower()
    if any(h in url for h in _CAPTCHA_HOSTS):
        return None

    req_raw = rec.get("request_body") or ""
    resp_raw = rec.get("response_body") or ""
    req = parse_body(req_raw, rec.get("request_content_type"))
    resp = parse_body(resp_raw, rec.get("response_content_type"))

    def present(structured, raw, key) -> bool:
        return (structured is not None and has_key(structured, key)) or (key in raw)

    # --- finish legs: identified by the request body the client POSTs ---
    if present(req, req_raw, "attestationObject"):
        return "webauthn_register_finish"
    if present(req, req_raw, "signature") and present(req, req_raw, "authenticatorData"):
        return "webauthn_auth_finish"

    # --- begin legs: identified by the options the server returns ---
    if present(resp, resp_raw, "challenge"):
        if present(resp, resp_raw, "pubKeyCredParams"):
            return "webauthn_register_begin"
        # auth options: challenge + a WebAuthn-specific marker, and no creation
        # -only fields. Requiring a marker (not a bare "challenge") keeps CAPTCHA
        # / bot-detection payloads that reuse the word "challenge" from matching.
        if not present(resp, resp_raw, "pubKeyCredParams") and not present(resp, resp_raw, "\"user\""):
            if (present(resp, resp_raw, "allowCredentials")
                    or present(resp, resp_raw, "rpId")
                    or present(resp, resp_raw, "userVerification")):
                return "webauthn_auth_begin"

    # URL fallback: some RPs obfuscate/minify the option field names (Canva renames
    # challenge/rp/user to single letters), so shape-detection misses the begin.
    # But the endpoint path still names the ceremony. Only trust this for clearly
    # WebAuthn URLs, and only for a begin (the finish is already caught above by its
    # attestationObject/signature body).
    if any(k in url for k in ("webauthn", "passkey", "/fido")):
        seg = url
        if any(k in seg for k in ("start", "begin", "option", "challenge", "/new")):
            if any(k in seg for k in ("regist", "attest", "create", "enroll")):
                return "webauthn_register_begin"
            if any(k in seg for k in ("auth", "assert", "login", "signin", "sign-in")):
                return "webauthn_auth_begin"
    return None


# ---------------------------------------------------------------------------
# per-request replay helpers (generic WebAuthn begin/finish template handling)
# ---------------------------------------------------------------------------
#
# Different RPs wire the SAME ceremony onto wildly different HTTP shapes: a
# clean JSON API (archidekt), single-letter-renamed JSON gated behind a live
# session header (canva's `_ajax` endpoints), or a Next.js Server Action where
# begin AND finish POST to the IDENTICAL url and the response is wrapped in a
# React-server-component text stream (bird.com). None of that is worth a
# per-RP branch: the WebAuthn field names (or, when renamed, the VALUES — a
# challenge/credential is unmistakable regardless of what key it sits under)
# are enough to locate everything generically, request by request.

def walk_paths(obj: Any, prefix: tuple = ()) -> Iterable[tuple[tuple, Any]]:
    """Yield every (path, value) pair in a nested dict/list, path included."""
    yield prefix, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_paths(v, prefix + (i,))


def get_path(obj: Any, path) -> Any:
    for k in path:
        obj = obj[k]
    return obj


def set_path(obj: Any, path, value) -> None:
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value


def _enclosing_starts(text: str, anchor: str, count: int) -> list[int]:
    """Opening-brace indices of up to `count` successively wider `{...}`
    objects around `anchor`, innermost first (index 0 = tightest enclosing)."""
    i = text.find(anchor)
    if i < 0:
        return []
    starts: list[int] = []
    search_from = i
    for _ in range(count):
        depth, start = 0, None
        for j in range(search_from, -1, -1):
            c = text[j]
            if c == "}":
                depth += 1
            elif c == "{":
                if depth == 0:
                    start = j
                    break
                depth -= 1
        if start is None:
            break
        starts.append(start)
        search_from = start - 1
    return starts


def _parse_from(text: str, start: int) -> Any | None:
    """Parse the well-formed `{...}` object that begins at `start`.

    `{`/`}` themselves are never HTML-escaped, so the brace-matching above is
    safe to do on the raw text, but a quote inside an HTML page (github embeds
    the creation options as a JS string literal) often is (`&quot;`) — unescape
    before handing the span to json.loads.
    """
    import html as _html
    depth = 0
    for k in range(start, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(_html.unescape(text[start:k + 1]))
                except Exception:
                    return None
    return None


def enclosing_json(text: str, anchor: str) -> dict | None:
    """Smallest well-formed `{...}` JSON object in `text` that contains `anchor`.

    Works whether `text` is a plain JSON body, an HTML page with the options
    embedded inline, or a React-server-component stream (`N:{...}` lines) —
    the object boundaries are found by brace-matching around the anchor
    substring, not by assuming the whole payload parses as one JSON value.
    """
    starts = _enclosing_starts(text, anchor, 1)
    return _parse_from(text, starts[0]) if starts else None


def locate_begin_options(raw_text: str, kind: str) -> dict | None:
    """Find the WebAuthn creation/assertion options for a begin response,
    by literal field name, widened one level up so echo fields the finish
    leg may reference (e.g. a sibling `challengeId`) come along for
    find_copy_fields. `kind` is "register" or "auth". `challenge`/`rp`/`user`/
    `pubKeyCredParams` may end up nested inside the returned object — look
    them up with has_key/find_value, not a top-level `in`/`[]`.

    Returns None when the RP renames the fields (ajax/obfuscated style) —
    callers fall back to value-based matching in that case.
    """
    anchors = ("pubKeyCredParams",) if kind == "register" else (
        "allowCredentials", "userVerification", "rpId")
    for a in anchors:
        starts = _enclosing_starts(raw_text, a, 2)
        for start in reversed(starts):   # widest first, so sibling echo fields are included
            obj = _parse_from(raw_text, start)
            if obj is not None and has_key(obj, "challenge"):
                return obj
    return None


def find_credential_path(obj: Any, required_keys: tuple[str, ...]) -> tuple[list, dict, bool] | None:
    """Find where a finish request body carries the WebAuthn credential.

    Handles both shapes seen in the wild: a plain nested credential object
    (`{"id":..., "response": {"attestationObject": ...}}`, possibly itself
    inside a list — bird.com), and a credential JSON-stringified under an
    opaque key (canva's ajax API). `required_keys` are the response-level
    keys that must all be present — ("attestationObject",) for register,
    ("authenticatorData", "signature") for auth.

    Returns (path, parsed_credential, is_stringified) or None.
    """
    for path, val in walk_paths(obj):
        if isinstance(val, dict):
            resp = val.get("response")
            if isinstance(resp, dict) and all(k in resp for k in required_keys):
                return list(path), val, False
        elif isinstance(val, str) and all(k in val for k in required_keys):
            try:
                parsed = json.loads(val)
            except Exception:
                continue
            resp = parsed.get("response") if isinstance(parsed, dict) else None
            if isinstance(resp, dict) and all(k in resp for k in required_keys):
                return list(path), parsed, True
    return None


def value_path(obj: Any, predicate) -> list | None:
    """Path to the first value in `obj` satisfying `predicate(value)`."""
    for path, val in walk_paths(obj):
        if path and predicate(val):
            return list(path)
    return None


def clientdata_challenge_origin(cred: dict) -> tuple[str | None, str | None]:
    """Decode a WebAuthn credential's clientDataJSON -> (challenge, origin)."""
    from src.lib.soft_authenticator import b64url_decode
    cdj = (cred.get("response") or {}).get("clientDataJSON")
    if not cdj:
        return None, None
    try:
        data = json.loads(b64url_decode(cdj))
        return data.get("challenge"), data.get("origin")
    except Exception:
        return None, None


def infer_obfuscated_begin_paths(begin_parsed: Any, challenge: str, origin: str | None) -> dict:
    """Value-based fallback for RPs that rename every WebAuthn field (ajax
    style, e.g. canva's single-letter keys): locate the challenge and the rp
    id INSIDE the begin response by the value the old capture is known to
    carry, as a path — not a key name, which these RPs often reuse at
    several nesting levels for unrelated fields. Returns
    {"challenge_path": [...], "rpid_path": [...] | None}.
    """
    out: dict = {}
    cp = value_path(begin_parsed, lambda v: v == challenge)
    if cp:
        out["challenge_path"] = cp
    host = (origin or "").split("://")[-1]
    if host:
        rp = value_path(begin_parsed, lambda v: isinstance(v, str) and (v == host or host.endswith(v)))
        if rp:
            out["rpid_path"] = rp
    return out


def find_copy_fields(begin_opts: dict, finish_obj: Any, cred_path: list) -> list[tuple[list, list]]:
    """Fields in `finish_obj` (outside the credential subtree) whose captured
    value also appears somewhere in the begin response — a session/challenge/
    request id the finish echoes back. Returns [(finish_path, begin_path)];
    at replay, re-resolve each via get_path(new_begin_opts, begin_path) so the
    echoed id is fresh even though the finish body is otherwise a frozen
    template.

    Positional (not key-name) on the begin side: some RPs reuse the same
    short/renamed key at several nesting levels for unrelated fields (ajax
    RPs that minify to single letters), so looking a value back up by key
    name alone can land on the wrong occurrence. A path, paired with the
    assumption that the begin response's shape is stable across runs (same
    API, same schema — only the values differ), is unambiguous.
    """
    begin_index: dict[str, list] = {}
    for path, val in walk_paths(begin_opts):
        if path and isinstance(val, str) and len(val) >= 8 and val not in begin_index:
            begin_index[val] = list(path)
    cp = tuple(cred_path)
    copies: list[tuple[list, list]] = []
    for path, val in walk_paths(finish_obj):
        if not path or list(path[:len(cp)]) == list(cp):
            continue
        if isinstance(val, str) and len(val) >= 8 and val in begin_index:
            copies.append((list(path), begin_index[val]))
    return copies


# ---------------------------------------------------------------------------
# CSRF token location
# ---------------------------------------------------------------------------

_CSRF_HEADER_NAMES = (
    "x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token",
    "x-requestverificationtoken", "__requestverificationtoken", "x-csrf",
)
_CSRF_BODY_NAMES = (
    "authenticity_token", "_csrf", "csrf_token", "csrfmiddlewaretoken",
    "__requestverificationtoken", "csrfToken", "_token",
)


def locate_csrf(rec: dict) -> dict | None:
    """Find a CSRF token this request carries, and where it likely came from.

    Returns {location, name, source} or None. `source` is traced to a request
    cookie of equal value when possible (the classic double-submit pattern);
    otherwise left as "unknown" for the capture-time tracer to resolve against
    prior HTML responses.
    """
    headers = {k.lower(): v for k, v in (rec.get("request_headers") or {}).items()}
    for name in _CSRF_HEADER_NAMES:
        if name in headers and headers[name]:
            return {"location": "header", "name": name,
                    "source": _trace_to_cookie(headers.get("cookie", ""), headers[name])}
    req = parse_body(rec.get("request_body"), rec.get("request_content_type"))
    if isinstance(req, dict):
        for name in _CSRF_BODY_NAMES:
            for k in req:
                if k.lower() == name.lower() and req[k]:
                    return {"location": "body", "name": k,
                            "source": _trace_to_cookie(headers.get("cookie", ""), str(req[k]))}
    return None


def _trace_to_cookie(cookie_header: str, token_value: str) -> str:
    """If the token equals a cookie value, name that cookie; else 'unknown'."""
    if not cookie_header or not token_value:
        return "unknown"
    for pair in cookie_header.split(";"):
        if "=" not in pair:
            continue
        name, _, val = pair.strip().partition("=")
        # cookie values are often the token URL-encoded; compare a prefix too
        if val and (val == token_value or token_value.startswith(val[:16])):
            return f"cookie:{name}"
    return "unknown"


# ---------------------------------------------------------------------------
# login classification
# ---------------------------------------------------------------------------

_PW_NAME = re.compile(r"(?<!new)pass(word|wd|phrase)?$|^pwd$", re.I)
# ^ excludes "newPassword" / "new_password" (etc.) fields: those set a NEW
#   password (account-settings / passkey-setup flows), not a login credential —
#   without the exclusion they still end in "...password" and get misread as
#   the login submission, inventing a login step where none was captured.
_EMAIL_NAME = re.compile(r"^(login|email|e-mail|username|user|account|identifier)$", re.I)


def classify_login(rec: dict, identity: dict) -> dict | None:
    """Tag a request as a login step and template its secret-bearing fields.

    A request is a login only if it carries a credential — the identity
    email/password (raw), the {{email}}/{{password}} placeholders redact() has
    already substituted, or a field whose *name* means email/password. This
    deliberately does NOT tag a POST just because it sets a cookie, so
    availability/nickname checks that happen to refresh a session cookie are not
    mistaken for login. Returns {fields, sets_session_cookie} or None; `fields`
    maps the body key -> placeholder.
    """
    if (rec.get("method") or "").upper() not in ("POST", "PUT"):
        return None
    raw = rec.get("request_body") or ""
    req = parse_body(raw, rec.get("request_content_type"))
    email = str(identity.get("email", "")) or None
    password = str(identity.get("password", "")) or None
    fields: dict[str, str] = {}

    if isinstance(req, dict):
        for k, v in req.items():
            sv = v if isinstance(v, str) else json.dumps(v)
            if "{{password}}" in sv or (password and password in sv) or _PW_NAME.search(k):
                fields[k] = "{{password}}"
            elif "{{email}}" in sv or (email and email in sv) or _EMAIL_NAME.match(k):
                fields[k] = "{{email}}"
    else:
        # unparseable body (e.g. multipart): fall back to placeholder presence
        if "{{password}}" in raw or (password and password in raw):
            fields["<password field>"] = "{{password}}"
        if "{{email}}" in raw or (email and email in raw):
            fields["<email field>"] = "{{email}}"

    has_password = "{{password}}" in fields.values()
    if not has_password:
        return None   # no credential -> not a login submit
    return {"fields": fields, "sets_session_cookie": _sets_session_cookie(rec)}


def _sets_session_cookie(rec: dict) -> bool:
    resp_headers = rec.get("response_headers") or {}
    setc = ""
    for k, v in resp_headers.items():
        if k.lower() == "set-cookie":
            setc = v if isinstance(v, str) else " ".join(v)
    return bool(re.search(r"(session|sess|sid|auth|token|_gh_sess|csrf)", setc, re.I))


# ---------------------------------------------------------------------------
# redaction (applied at capture time, before anything is written)
# ---------------------------------------------------------------------------

def redact(rec: dict, identity: dict) -> dict:
    """Strip secrets from a record IN PLACE and return it.

    - identity password/email/OTP-looking values in bodies -> placeholders
    - Cookie / Authorization request-header values -> '<redacted>'
    - Set-Cookie response-header values -> name plus '<redacted>'
    Names/structure are preserved so the flow stays classifiable and templatable.
    """
    from urllib.parse import quote, quote_plus

    def _variants(val: str) -> list[str]:
        # a secret may appear raw or percent-encoded (form bodies, query strings)
        out = [val, quote(val, safe=""), quote_plus(val)]
        seen, uniq = set(), []
        for v in out:
            if v and v not in seen:
                seen.add(v); uniq.append(v)
        return uniq

    password = str(identity.get("password", "")) or None
    email = str(identity.get("email", "")) or None

    def scrub_body(s: str | None) -> str | None:
        if not s:
            return s
        if password:
            for v in _variants(password):
                s = s.replace(v, "{{password}}")
        if email:
            for v in _variants(email):
                s = s.replace(v, "{{email}}")
        return s

    rec["request_body"] = scrub_body(rec.get("request_body"))
    # response bodies rarely echo secrets, but scrub email/password just in case
    rec["response_body"] = scrub_body(rec.get("response_body"))

    def scrub_headers(headers: dict | None, kind: str) -> dict | None:
        if not headers:
            return headers
        out = {}
        for k, v in headers.items():
            lk = k.lower()
            if kind == "req" and lk in ("cookie", "authorization"):
                out[k] = "<redacted>"
            elif kind == "resp" and lk == "set-cookie":
                names = ";".join(
                    (c.strip().split("=", 1)[0] for c in (v if isinstance(v, str) else "").split(";") if "=" in c)
                )
                out[k] = f"{names.split(';')[0]}=<redacted>" if names else "<redacted>"
            else:
                out[k] = v
        return out

    rec["request_headers"] = scrub_headers(rec.get("request_headers"), "req")
    rec["response_headers"] = scrub_headers(rec.get("response_headers"), "resp")
    return rec


# ---------------------------------------------------------------------------
# descriptor assembly
# ---------------------------------------------------------------------------

def detect_style(records: list[dict]) -> dict:
    """Decide whether an RP's WebAuthn flow is 'standard' (field names like
    challenge/pubKeyCredParams/attestationObject) or 'ajax' (fields
    renamed/minified and often gated behind a JS-set session header — e.g.
    Canva's single-letter A/B/C maps). Informational only now: replay_http's
    begin/finish locators try the literal-name path first and fall back to
    value+position matching automatically, so both styles replay through the
    same engine — this just explains in the descriptor which path a given RP
    needed.

    Decisive signal is the BEGIN: a begin whose response parses as JSON but
    contains no `challenge` anywhere (key or substring) means the fields were
    renamed — it was only classifiable via the URL fallback. A finish that
    parses as JSON without a real attestationObject/signature key (the credential
    is stringified under a renamed key) is a secondary signal. Also collects the
    custom x-* request headers the flow carries, so the adapter knows what to
    borrow from the live browser session.
    """
    ajax = False
    headers: set[str] = set()
    for rec in records:
        tag = classify_webauthn(rec)
        if not tag:
            continue
        for k in (rec.get("request_headers") or {}):
            lk = k.lower()
            if lk.startswith("x-") and lk != "x-requested-with":
                headers.add(lk)
        if tag.endswith("begin"):
            resp = parse_body(rec.get("response_body"), rec.get("response_content_type"))
            resp_raw = rec.get("response_body") or ""
            if resp is not None and not has_key(resp, "challenge") and "challenge" not in resp_raw:
                ajax = True
        elif tag.endswith("finish"):
            req = parse_body(rec.get("request_body"), rec.get("request_content_type"))
            if req is not None and not (has_key(req, "attestationObject") or has_key(req, "signature")):
                ajax = True
    return {"style": "ajax" if ajax else "standard", "ajax_headers": sorted(headers)}


def build_descriptor(records: list[dict], rp_id: str, identity: dict) -> dict:
    """Classify every record and emit the per-RP flow descriptor.

    Only requests that got a tag are kept in `flow`; the raw log keeps the rest.
    """
    flow: list[dict] = []
    for rec in records:
        wa = classify_webauthn(rec)
        login = None if wa else classify_login(rec, identity)
        if not wa and not login:
            continue
        entry = {
            "tag": wa or "login",
            "method": rec.get("method"),
            "url": rec.get("url"),
            "status": rec.get("status"),
            "request_content_type": rec.get("request_content_type"),
        }
        csrf = rec.get("csrf_trace") or locate_csrf(rec)
        if csrf:
            entry["csrf"] = csrf
        if login:
            entry["login_fields"] = login["fields"]
            entry["sets_session_cookie"] = login["sets_session_cookie"]
        flow.append(entry)

    style = detect_style(records)
    return {
        "rp_id": rp_id,
        "captured_requests": len(records),
        "style": style["style"],          # informational — replay_http handles both the same way
        "ajax_headers": style["ajax_headers"],
        "flow": flow,
        "summary": _summarize(flow),
    }


def _summarize(flow: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for e in flow:
        counts[e["tag"]] = counts.get(e["tag"], 0) + 1
    return counts
