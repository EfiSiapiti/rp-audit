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
    return None


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

_PW_NAME = re.compile(r"pass(word|wd|phrase)?$|^pwd$", re.I)
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

    return {
        "rp_id": rp_id,
        "captured_requests": len(records),
        "flow": flow,
        "summary": _summarize(flow),
    }


def _summarize(flow: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for e in flow:
        counts[e["tag"]] = counts.get(e["tag"], 0) + 1
    return counts
