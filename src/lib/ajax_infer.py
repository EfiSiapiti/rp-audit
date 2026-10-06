"""Infer an ajax RP's obfuscated WebAuthn field mapping from its capture.

Ajax-style RPs (e.g. Canva) rename the WebAuthn fields to opaque keys (A/B/C/…),
so we can't hardcode where the challenge / credential / session-id live. But a
capture contains the ground truth: the finish request carries the credential, and
its clientDataJSON embeds the exact challenge the begin issued. By cross-
referencing those known values back to the obfuscated keys, we learn the mapping
for any ajax RP straight from its capture — no per-RP code.

Strategy: keep the captured finish body as a TEMPLATE and learn which paths are
dynamic — the credential, and every field that echoes a begin value (session id /
request id / user id). At replay the adapter deep-copies the template and
overwrites: credential_path ← freshly fabricated credential; each copy rule ←
the matching value from the LIVE begin; blob_path ← a live-captured anti-fraud
blob (--m-file). Everything else (small static flags) is replayed verbatim.

Paths are key lists (dict keys / list indices), e.g. ["A","credential"].
"""

from __future__ import annotations

import json
from typing import Any

from src.lib import http_flow
from src.lib.soft_authenticator import b64url_decode


def _walk_paths(obj: Any, prefix: tuple = ()):
    yield prefix, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_paths(v, prefix + (i,))


def get_path(obj: Any, path):
    for k in path:
        obj = obj[k]
    return obj


def set_path(obj: Any, path, value) -> None:
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value


def _x_headers(rec: dict) -> dict:
    """The request's x-* headers (op name, account ids, etc.) — the session token
    among them is overridden with a live value at replay."""
    return {k.lower(): v for k, v in (rec.get("request_headers") or {}).items()
            if k.lower().startswith("x-") and k.lower() != "x-requested-with"}


def _parse(rec: dict, which: str) -> Any:
    if which == "request":
        return http_flow.parse_body(rec.get("request_body"), rec.get("request_content_type"))
    return http_flow.parse_body(rec.get("response_body"), rec.get("response_content_type"))


def _find_stringified(obj: Any, needle: str):
    """Path + parsed inner of the first string value that is JSON containing needle."""
    for path, val in _walk_paths(obj):
        if isinstance(val, str) and needle in val:
            try:
                return list(path), json.loads(val)
            except Exception:
                continue
    return None, None


def _challenge_origin(inner: dict) -> tuple[str | None, str | None]:
    cdj = (inner.get("response") or {}).get("clientDataJSON")
    if not cdj:
        return None, None
    try:
        data = json.loads(b64url_decode(cdj))
        return data.get("challenge"), data.get("origin")
    except Exception:
        return None, None


def _path_to_value(obj: Any, target, skip_prefix=None) -> list | None:
    for path, val in _walk_paths(obj):
        if not path:
            continue
        if skip_prefix and list(path[:len(skip_prefix)]) == list(skip_prefix):
            continue
        if val == target:
            return list(path)
    return None


def _infer_leg(begin_rec: dict, finish_rec: dict, cred_needle: str) -> dict:
    begin = _parse(begin_rec, "response")
    finish = _parse(finish_rec, "request")
    if begin is None or finish is None:
        raise ValueError("begin/finish body did not parse as JSON")

    cred_path, inner = _find_stringified(finish, cred_needle)
    if cred_path is None:
        raise ValueError(f"no stringified credential ({cred_needle}) found in finish body")
    challenge, origin = _challenge_origin(inner)
    host = (origin or "").split("://")[-1]

    begin_info = {"url": begin_rec["url"], "method": begin_rec["method"],
                  "headers": _x_headers(begin_rec)}
    if challenge:
        p = _path_to_value(begin, challenge)
        if p:
            begin_info["challenge_path"] = p
    for path, val in _walk_paths(begin):
        if isinstance(val, str) and host and "." in val and (val == host or host.endswith(val)):
            begin_info["rpid_path"] = list(path)
            break

    # learn copy rules: any finish value (outside the credential) that echoes a
    # begin value is a dynamic handshake field (session id / request id / user id)
    copy, static, blob_path = [], {}, None
    begin_index = {v: list(p) for p, v in _walk_paths(begin) if isinstance(v, str) and len(v) >= 8}
    cp = tuple(cred_path)
    for path, val in _walk_paths(finish):
        if not path or list(path[:len(cp)]) == list(cp):
            continue
        if isinstance(val, (dict, list)):
            if len(json.dumps(val)) > 2000:
                blob_path = list(path)          # big structured anti-fraud blob
            continue
        if isinstance(val, str):
            if len(val) > 2000:
                blob_path = list(path)
            elif val in begin_index and val != challenge:
                copy.append([list(path), begin_index[val]])
            elif len(val) < 64:
                static[list(path)[-1] if len(path) == 1 else ".".join(map(str, path))] = val

    return {
        "begin": begin_info,
        "finish": {
            "url": finish_rec["url"], "method": finish_rec["method"],
            "headers": _x_headers(finish_rec),
            "template": finish,                 # captured body, overwritten by path at replay
            "credential_path": cred_path,
            "copy": copy,                       # [finish_path, begin_path] echoes
            "blob_path": blob_path,             # anti-fraud field needing a live blob
        },
        "origin": origin,
    }


def _find_finish(records: list[dict], needle: str, also: str | None) -> dict | None:
    """The request that POSTs the credential (identified by body substring)."""
    for rec in records:
        if (rec.get("method") or "").upper() not in ("POST", "PUT"):
            continue
        body = rec.get("request_body") or ""
        if needle in body and (also is None or also in body):
            return rec
    return None


def _find_begin_by_challenge(records: list[dict], challenge: str, exclude: dict) -> dict | None:
    """The begin is the request whose RESPONSE carries the challenge the finish
    signed — a value match that works regardless of field-name obfuscation or URL."""
    for rec in records:
        if rec is exclude:
            continue
        if challenge in (rec.get("response_body") or ""):
            return rec
    return None


def infer_profile(records: list[dict]) -> dict:
    """Infer register (and auth, if captured) mappings, pairing begin→finish by
    the challenge value rather than by classification (obfuscation-proof)."""
    legs: dict[str, dict] = {}
    for needle, also, name in (("attestationObject", None, "register"),
                               ("authenticatorData", "signature", "auth")):
        finish = _find_finish(records, needle, also)
        if not finish:
            continue
        _, inner = _find_stringified(_parse(finish, "request"), needle)
        challenge, _ = _challenge_origin(inner) if inner else (None, None)
        begin = _find_begin_by_challenge(records, challenge, finish) if challenge else None
        if not begin:
            legs[name] = {"error": "could not locate begin (challenge not found in any response)"}
            continue
        try:
            legs[name] = _infer_leg(begin, finish, needle)
        except Exception as e:
            legs[name] = {"error": str(e)}
    return legs
