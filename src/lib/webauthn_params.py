"""Extract the WebAuthn options an RP advertised, and project them into the
ledger + the selected-status CSV.

Source of truth is the structured event log the page hook exposes via
`window.__webauthnObserverGetLogs()` (see hook.js in the pwned-xploit repo).
`src/hook/run.py` dumps that to `observer_log.json` per run and then calls the
helpers here so every run auto-records, without a manual step:

  observer_log.json ── extract_advertised ──▶ normalized dict
                                              ├─ ledger.record_advertised_params
                                              └─ upsert_status_csv  (adv_* columns)

The status CSV stays a projection of the ledger: `sync_selected_status_notes`
reprojects the same `adv_*` columns from `entry["advertised_params"]`, so a
resync never disagrees with what a run wrote.
"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.lib.parse import _sniff_delimiter


DEFAULT_STATUS_CSV = Path("data/targets_selected_status.csv")

# Advertised-only columns for the per-RP status sheet (targets_selected_status.csv).
# One row per RP: what the RP requested. Kept as a module constant so the per-run
# writer (upsert_status_csv) and the bulk resync (sync_selected_status_notes) agree.
ADV_COLUMNS = [
    "adv_rp_id",
    "adv_attestation",
    "adv_uv",
    "adv_resident_key",
    "adv_require_resident_key",
    "adv_authenticator_attachment",
    "adv_algs",            # from the client-side options the hook saw
    "adv_attestation_formats",
    "adv_timeout",
    "adv_captured_at",
]

DEFAULT_EXPERIMENTS_CSV = Path("data/experiments.csv")

# Append-only experiment log (data/experiments.csv): one self-contained row per
# hook run — the advertised context (adv_*), what the hook returned (fab_*), and
# what the server said back (srv_*), plus a --label naming the control under test.
# Advertised is snapshotted per run too, so a change in what the RP advertises
# (control 2) is visible across rows. This is where control experiments on the
# same RP are compared, without overwriting.
EXPERIMENT_COLUMNS = [
    "captured_at",
    "rp_id",              # target label the run was invoked with
    "label",             # --label: the control/config under test
    # advertised context (what the RP requested this run)
    "adv_rp_id",
    "adv_attestation",
    "adv_uv",
    "adv_resident_key",
    "adv_require_resident_key",
    "adv_authenticator_attachment",
    "adv_algs",
    "adv_attestation_formats",
    "adv_timeout",
    # selected / returned
    "fab_alg",
    "fab_alg_offered",
    "fab_flags",
    "fab_outcome",
    # server verdict
    "srv_endpoint",
    "srv_status",
    "srv_result",
    "srv_message",
    "artifact",
]


# --- Extraction ----------------------------------------------------------


def _iter_entries(observer_log: Any) -> Iterable[dict]:
    """Yield hook event entries regardless of how observer_log was wrapped.

    Accepts the raw `getLogs()` list, a per-frame list of
    ``{"frame_url", "entries"}`` (what run.py writes), or a dict wrapper.
    """
    if observer_log is None:
        return
    if isinstance(observer_log, dict):
        if isinstance(observer_log.get("entries"), list):
            yield from (e for e in observer_log["entries"] if isinstance(e, dict))
        for key in ("frames", "logs"):
            if isinstance(observer_log.get(key), list):
                for item in observer_log[key]:
                    yield from _iter_entries(item)
        return
    if isinstance(observer_log, list):
        for item in observer_log:
            if not isinstance(item, dict):
                continue
            if "eventType" in item:            # a raw event entry
                yield item
            elif isinstance(item.get("entries"), list):  # a per-frame wrapper
                yield from _iter_entries(item)
        return


def _parse_ts(ts: Any) -> datetime | None:
    """Parse a hook ISO timestamp (`…Z`/`…+00:00`) or run.py compact `%Y%m%dT%H%M%SZ`."""
    if not isinstance(ts, str) or not ts:
        return None
    t = ts.strip()
    try:
        return datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        pass
    try:
        return datetime.strptime(t, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _filter_since(observer_log: Any, since: datetime) -> list:
    """Keep only observer entries at/after `since`.

    The hook's event log is persisted to chrome.storage and accumulates across
    runs/origins, so a fresh capture can carry stale ceremonies from earlier RPs.
    Scoping to the current run's start time isolates this run's ceremony. Entries
    without a parseable ts are kept (all real hook entries have one).
    """
    def keep(entry: dict) -> bool:
        p = _parse_ts(entry.get("ts"))
        return p is None or p >= since

    out: list = []
    for block in observer_log or []:
        if not isinstance(block, dict):
            continue
        if isinstance(block.get("entries"), list):
            kept = [e for e in block["entries"] if isinstance(e, dict) and keep(e)]
            if kept:
                out.append({**block, "entries": kept})
        elif "eventType" in block and keep(block):
            out.append(block)
    return out


def _latest_create_options(observer_log: Any) -> dict | None:
    """Return the `options` summary from the chronologically-latest `create.called`.

    Picks by timestamp (not list order) so an accumulated cross-run log still
    yields *this* run's ceremony — the most recent one.
    """
    candidates = []
    for entry in _iter_entries(observer_log):
        if entry.get("eventType") == "create.called":
            opts = (entry.get("payload") or {}).get("options")
            if isinstance(opts, dict) and opts.get("hasPublicKey"):
                candidates.append((_parse_ts(entry.get("ts")), opts))
    if not candidates:
        return None
    dated = [c for c in candidates if c[0] is not None]
    if dated:
        return max(dated, key=lambda c: c[0])[1]
    return candidates[-1][1]


def _scan_fabrication(observer_log: Any) -> dict:
    """Summarize the *given* side + outcome from the hook's fabrication events.

    Reads the latest fabrication.algSelection / fabrication.flags and infers how
    the ceremony ended, so a rejected registration still records what we offered
    the RP and that it happened — not just the RP's requested params.
    """
    alg_sel = None
    flags = None
    outcome = "called-no-result"  # create.called seen but nothing after
    error = None
    cred_id = None
    cred_ids: list = []
    reused = False
    for entry in _iter_entries(observer_log):
        et = entry.get("eventType")
        payload = entry.get("payload") or {}
        if et == "fabrication.algSelection":
            alg_sel = payload
        elif et == "fabrication.flags" and payload.get("op") == "create":
            flags = payload.get("flags")
        elif et == "fabrication.reuseCredential":
            # Control 3: the hook re-presented an existing credId (revoked-key re-register).
            reused = True
            cid = payload.get("credId")
            if cid:
                cred_id = cid
                if cid not in cred_ids:
                    cred_ids.append(cid)
        elif et == "fabrication.success":
            outcome = "fabricated"
            cid = payload.get("credId")
            if cid:
                cred_id = cid
                if cid not in cred_ids:
                    cred_ids.append(cid)
        elif et == "create.success":
            outcome = "real-create"
        elif et == "create.failed":
            outcome = "create-failed"
            error = (payload.get("error") or {}).get("name")

    # A reuse still produces a fabrication.success afterwards; mark it as reused so
    # the re-register runs are distinguishable from fresh fabrications.
    if reused and outcome == "fabricated":
        outcome = "reused"

    out: dict = {"outcome": outcome}
    if error:
        out["error"] = error
    if cred_id:
        out["cred_id"] = cred_id
    if cred_ids:
        out["cred_ids"] = cred_ids
    if alg_sel:
        out["fabrication_alg"] = alg_sel.get("fabricationAlg")
        out["fabrication_cose_alg"] = alg_sel.get("coseAlg")
        out["fabrication_alg_offered"] = alg_sel.get("algInPubKeyCredParams")
    if flags:
        out["fabrication_flags"] = flags
    return out


def _as_network(network: Any) -> tuple[list, list]:
    """Normalize the `network` arg into (requests, responses) lists.

    Accepts run.py's ``{"requests": [...], "responses": [...]}`` dict, or the
    older flat webauthn list (records tagged kind=request/response).
    """
    if isinstance(network, dict):
        return list(network.get("requests") or []), list(network.get("responses") or [])
    if isinstance(network, list):
        reqs, resps = [], []
        for r in network:
            if not isinstance(r, dict):
                continue
            if r.get("kind") == "request" or "post_data" in r:
                reqs.append(r)
            if r.get("kind") == "response" or "body" in r:
                resps.append(r)
        return reqs, resps
    return [], []


def _path(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).path or url
    except Exception:
        return url


# Structured negative markers (whitespace-stripped, lowercased) that indicate a
# real rejection — as opposed to negated fields like "error":false / "errors":[]
# that a naive "error" substring match would wrongly flag.
_ERROR_MARKERS = (
    '"error":true', '"errors":[{', '"errors":["', '"success":false',
    '"ok":false', '"status":"error"', '"status":"fail', '"result":"error"',
    '"verified":false',
)

# Strong plain-text error phrases (for non-JSON / HTML rejection bodies). Chosen
# to be unlikely to appear in a negated/positive context.
_ERROR_PHRASES = (
    "could not be verified", "verification failed", "invalid attestation",
    "attestation failed", "registration failed", "not permitted", "access denied",
)


# Endpoints that are NOT the WebAuthn finish even if their body carries the
# credential — error reporters (Sentry etc.) and analytics/telemetry echo the
# credential in their payloads and would otherwise be mistaken for the finish.
_NON_FINISH_URL = re.compile(
    r"sentry|error[-_.]?report|bugsnag|/rum\b|/crash|telemetry|/science\b|"
    r"analytics|taboola|/collect\b|/pixel|doubleclick|/beacon|/log(?:/|\b)|datadog",
    re.IGNORECASE,
)

# A URL that pairs a webauthn/passkey/enrollment token with a success/complete
# token — indicates registration succeeded (e.g. Auth0's redirect target
# /u/mfa-webauthn-enrollment-success).
_SUCCESS_URL = re.compile(
    r"(?:webauthn|passkey|enrollment|security[-_]?key|credential)"
    r"[^?#]*?(?:success|succeeded|complete|completed|enrolled|registered|confirmed)",
    re.IGNORECASE,
)


def _find_last_post(requests: list, markers: list) -> dict | None:
    """Last POST (to a non-telemetry endpoint) whose body contains any marker."""
    found = None
    for r in requests:
        try:
            url = r.get("url", "")
            if _NON_FINISH_URL.search(url):
                continue  # skip error-reporting / analytics endpoints
            if r.get("method") == "POST" and r.get("post_data") and any(
                m and m in r["post_data"] for m in markers
            ):
                found = r
        except Exception:
            continue
    return found


def _friendly_name(req: dict) -> str | None:
    """Meta tags GraphQL POSTs with fb_api_req_friendly_name — surface it so the
    endpoint cell is meaningful when every call goes to /api/graphql/."""
    pd = req.get("post_data") or ""
    marker = "fb_api_req_friendly_name="
    i = pd.find(marker)
    if i == -1:
        return None
    return pd[i + len(marker):].split("&", 1)[0][:60] or None


def _server_verdict(requests: list, responses: list, cred_ids: list | None = None) -> dict:
    """Find the registration *finish* request/response and summarize the verdict.

    The finish request is the POST whose body carries the new credential. RPs
    echo the credential id back, so we match on any fabricated credId first
    (works even when the attestation is base64-wrapped, as Meta does under
    `credential_id`/`payload`), then fall back to standard field names. The
    response is paired by position among same-URL calls (robust for the many
    same-second GraphQL POSTs). Acceptance can't be read from HTTP status alone
    (some RPs return 200 with an error body), so we record status, a body
    snippet (ground truth), and a best-effort guess. Never raises.
    """
    cred_ids = [c for c in (cred_ids or []) if c]

    # Proof of storage from ANY captured response, independent of identifying the
    # finish *request*: our fabricated credId echoed back, or an enabled/active
    # webauthn credential record. This is what lets opaque RPC flows (Google's
    # batchexecute, which base64-wraps the whole credential) still resolve to
    # accepted — there's no matchable finish POST, but the response proves storage.
    echoed = None
    echoed_resp = None
    for x in responses:
        b = _strip_xssi(x.get("body") or "")
        if not b:
            continue
        bn = "".join(b.lower().split())
        enabled_cred = "webauthn" in bn and any(
            s in bn for s in ('"status":"enabled"', '"status":"active"', '"status":"registered"')
        )
        if any(c in b for c in cred_ids) or enabled_cred:
            echoed, echoed_resp = b, x
            break

    # Prefer a credId match (strong evidence); fall back to field-name markers.
    # `webauthn.create` is the clientDataJSON type and appears in any registration
    # finish body (e.g. Salesforce VaaS sends the attestation under data.attestation
    # with type webauthn.create — no literal "attestationObject").
    finish = _find_last_post(requests, cred_ids) or _find_last_post(
        requests, ["credential_id", "attestationObject", "attestation_object",
                   '"rawId"', "authenticatorAttachment", "webauthn.create", '"attestation":"']
    )
    if finish is None:
        # No identifiable finish request (e.g. Google's opaque batchexecute RPC).
        # If a response still proves the credential was stored, it's accepted.
        if echoed is not None:
            hit = next((c for c in cred_ids if c in echoed), None)
            msg = _snippet_around(echoed, hit) if hit else _shorten(echoed)
            return {"endpoint": _path(echoed_resp.get("url", "")),
                    "status": echoed_resp.get("status"),
                    "result": "accepted", "message": msg}
        return {}

    url = finish.get("url", "")
    # Pair by position: the k-th POST to this URL → the k-th response to it.
    reqs_u = [r for r in requests if r.get("url") == url]
    resps_u = [x for x in responses if x.get("url") == url]
    try:
        pos = reqs_u.index(finish)
    except ValueError:
        pos = len(reqs_u) - 1
    resp = resps_u[pos] if 0 <= pos < len(resps_u) else (resps_u[-1] if resps_u else None)

    status = resp.get("status") if resp else None
    clean = _strip_xssi((resp.get("body") if resp else "") or "")
    snippet = _shorten(clean)

    low = clean.lower()
    norm = "".join(low.split())  # whitespace-insensitive for "error": false etc.
    # Explicit positive acceptance markers seen across RPs' finish responses.
    # Includes negated-error fields ("error":false / "errors":[]) and a stored
    # credential record (Pixiv's "credentialRecord"), which mean success.
    accepted_marker = any(m in norm for m in (
        '"success":true', '"verified":true', '"ok":true',
        '"status":"success"', '"status":"ok"', '"result":"success"',
        '"error":false', '"errors":[]', 'credentialrecord',
        'enrollmentcomplete', 'registrationcomplete',  # X: PasskeyEnrollmentCompleteSubtask
    ))
    # Real rejection: structured negative markers (not bare "error" substrings,
    # which appear negated in success bodies), or a strong plain-text phrase.
    error_marker = any(m in norm for m in _ERROR_MARKERS) or any(p in low for p in _ERROR_PHRASES)

    # (`echoed` — proof of a stored credential in any response — is computed above,
    # since it must work even when no finish request is matched.)

    # A 2xx finish response with an empty or trivial ({}/[]) body is a success
    # with nothing to report — common for /register/complete style endpoints
    # (Indeed returns empty, Ticketmaster returns {}).
    empty_2xx = status is not None and 200 <= status < 300 and clean.strip() in ("", "{}", "[]")

    # Redirect-to-success: some flows finish with a 3xx to a success URL (Auth0:
    # POST /u/mfa-webauthn-enrollment → 302 → /u/mfa-webauthn-enrollment-success).
    # A captured URL that pairs a webauthn/enrollment token with a success token
    # is a clear acceptance the status/body alone don't show.
    success_url = any(
        _SUCCESS_URL.search(x.get("url") or "") for x in (requests + responses)
    )

    if status is None:
        result = "unknown"
    elif status >= 400:
        result = "rejected"                      # hard HTTP failure
    elif accepted_marker or echoed or empty_2xx or success_url:
        result = "accepted"                      # success marker / stored credId / empty 2xx / success redirect
    elif error_marker:
        result = "rejected?"                     # a real negative marker in the body
    elif 200 <= status < 300:
        # The finish POST succeeded (2xx) and the body carries no rejection
        # signal — standard REST semantics: the RP stored the credential. RPs
        # return varied confirmations here (Dropbox's serialized_device_gid,
        # etc.); a 2xx without an error is an acceptance.
        result = "accepted"
    else:
        result = "accepted?"                     # non-2xx (e.g. 3xx) with no signal

    # When acceptance came from an echo and the matched finish body was empty or
    # uninformative, show the credId in context (the proof) as the message.
    if echoed and snippet in ("", "{}", "[]"):
        hit = next((c for c in cred_ids if c in echoed), None)
        snippet = _snippet_around(echoed, hit)

    fn = _friendly_name(finish)
    endpoint = _path(url) + (f" ({fn})" if fn else "")
    return {"endpoint": endpoint, "status": status, "result": result, "message": snippet}


def _strip_xssi(body: str) -> str:
    """Strip a leading anti-JSON-hijacking prefix (Facebook `for (;;);`, etc.)."""
    for prefix in ("for (;;);", "while(1);", ")]}'"):
        if body.startswith(prefix):
            return body[len(prefix):]
    return body


def _shorten(text: str, limit: int = 400) -> str:
    s = " ".join(text.split())
    return s[:limit] + "…" if len(s) > limit else s


def _snippet_around(body: str, needle: str, ctx: int = 200) -> str:
    """A whitespace-collapsed window around `needle` — shows the credId echo in
    context (e.g. inside a large HTML page) instead of the document header."""
    i = body.find(needle) if needle else -1
    if i == -1:
        return _shorten(body)
    start, end = max(0, i - ctx), i + len(needle) + ctx
    seg = " ".join(body[start:end].split())
    return ("…" if start > 0 else "") + seg + ("…" if end < len(body) else "")


def _server_algs_from_network(webauthn_network: Any) -> list | None:
    """Best-effort: pull pubKeyCredParams algs from a server begin-response.

    `webauthn_network` is the list captured in the run's webauthn.json. RP
    response shapes vary wildly, so this only recurses looking for a
    ``pubKeyCredParams`` array and returns the algs if found. Never raises.
    """
    def walk(node: Any) -> list | None:
        if isinstance(node, dict):
            pkcp = node.get("pubKeyCredParams")
            if isinstance(pkcp, list) and pkcp:
                algs = [p.get("alg") for p in pkcp if isinstance(p, dict)]
                if any(a is not None for a in algs):
                    return algs
            for v in node.values():
                found = walk(v)
                if found:
                    return found
        elif isinstance(node, list):
            for v in node:
                found = walk(v)
                if found:
                    return found
        return None

    try:
        for rec in webauthn_network or []:
            body = rec.get("body") if isinstance(rec, dict) else None
            if not body:
                continue
            try:
                parsed = json.loads(body)
            except (ValueError, TypeError):
                continue
            algs = walk(parsed)
            if algs:
                return algs
    except Exception:
        pass
    return None


def extract_advertised(observer_log: Any, network: Any = None,
                       since_iso: str | None = None) -> dict | None:
    """Normalize one ceremony into a flat record with three parts: what the RP
    advertised, what credential was selected/returned, and the server's verdict.

    Returns None if no `create.called` event with public-key options is present.
    `network` is run.py's {"requests", "responses"} dict (or the older flat list).
    `since_iso` scopes the (accumulated, cross-run) observer log to this run — pass
    the run's start time so stale ceremonies from earlier RPs are excluded.
    """
    since = _parse_ts(since_iso) if since_iso else None
    if since is not None:
        observer_log = _filter_since(observer_log, since)

    opts = _latest_create_options(observer_log)
    if opts is None:
        return None

    requests, responses = _as_network(network)

    record = {
        "rp_id_advertised": opts.get("rpId"),
        "rp_name": opts.get("rpName"),
        "attestation": opts.get("attestation"),
        "attestation_formats": opts.get("attestationFormats") or [],
        "user_verification": opts.get("userVerification"),
        "resident_key": opts.get("residentKey"),
        "require_resident_key": opts.get("requireResidentKey"),
        "authenticator_attachment": opts.get("authenticatorAttachment"),
        "pub_key_cred_params": opts.get("pubKeyCredParams") or [],
        "timeout": opts.get("timeout"),
        "exclude_credentials_count": opts.get("excludeCredentialsCount"),
        "extensions": opts.get("extensions") or [],
        "hints": opts.get("hints") or [],
        "challenge_length": opts.get("challengeLength"),
        "user_id_length": opts.get("userIdLength"),
    }

    # (1b) Advertised algs cross-checked against the RP's begin-response on the wire.
    server_algs = _server_algs_from_network(responses or network)
    if server_algs is not None:
        record["server_pub_key_algs"] = server_algs

    # (2) The credential that was returned (what we selected + how it ended).
    fab = _scan_fabrication(observer_log)
    record["fabrication"] = fab

    # (3) The server's verdict on the finish/registration request.
    server = _server_verdict(
        requests, responses, fab.get("cred_ids") or [fab.get("cred_id")]
    )
    # The browser fabricated a credential but the finish request/response wasn't
    # in the network capture (run.py wasn't attached to the ceremony tab when it
    # was sent). Flag it explicitly so a blank verdict isn't mistaken for
    # acceptance — re-run with the tab attached to capture the real verdict.
    if not server and fab.get("outcome") == "fabricated":
        server = {"result": "not-captured"}
    record["server"] = server

    return record


# --- Flattening to spreadsheet cells -------------------------------------


def _algs_of(pub_key_cred_params: Any) -> list:
    """Pull the COSE alg ids out of pubKeyCredParams, which may be a list of
    ``{type, alg}`` dicts (new hook.js) or bare alg ints (older logs)."""
    out = []
    for p in pub_key_cred_params or []:
        if isinstance(p, dict):
            out.append(p.get("alg"))
        else:
            out.append(p)
    return out


def _join(values: Any) -> str:
    return ",".join(str(v) for v in values) if values else ""


def flatten_adv_columns(params: dict | None) -> dict:
    """Map a normalized record to the advertised-only `adv_*` cells (status sheet).

    Nested values are compacted so each lands cleanly in one spreadsheet cell.
    Every ADV_COLUMNS key is always present (blank when unknown) so the header
    stays stable. The fab_*/srv_* results live in the experiment log instead
    (see flatten_experiment_columns).
    """
    params = params or {}
    return {
        "adv_rp_id": _cell(params.get("rp_id_advertised")),
        "adv_attestation": _cell(params.get("attestation")),
        "adv_uv": _cell(params.get("user_verification")),
        "adv_resident_key": _cell(params.get("resident_key")),
        "adv_require_resident_key": _cell(params.get("require_resident_key")),
        "adv_authenticator_attachment": _cell(params.get("authenticator_attachment")),
        "adv_algs": "|".join(
            str(a) for a in _algs_of(params.get("pub_key_cred_params")) if a is not None
        ),
        "adv_attestation_formats": _join(params.get("attestation_formats")),
        "adv_timeout": _cell(params.get("timeout")),
        "adv_captured_at": _cell(params.get("captured_at")),
    }


def flatten_experiment_columns(params: dict | None, *, rp_id: str, label: str = "",
                               artifact: str = "") -> dict:
    """One experiment-log row: the per-run fab_*/srv_* results + identity + label.

    `params` is the extracted (or ledger-stored) record; `rp_id` is the target
    label the run was invoked with, `label` the --label control name, `artifact`
    the run's artifact dir. Every EXPERIMENT_COLUMNS key is always present.
    """
    params = params or {}
    fab = params.get("fabrication") or {}
    srv = params.get("server") or {}
    # Reuse the advertised cells so both outputs stay in sync (drop adv_captured_at
    # — the row already has its own captured_at).
    adv = flatten_adv_columns(params)
    adv.pop("adv_captured_at", None)
    return {
        "captured_at": _cell(params.get("captured_at")),
        "rp_id": _cell(rp_id),
        "label": _cell(label),
        **adv,
        "fab_alg": _fab_alg_cell(fab),
        "fab_alg_offered": _cell(fab.get("fabrication_alg_offered")),
        "fab_flags": _flags_cell(fab.get("fabrication_flags")),
        "fab_outcome": _outcome_cell(fab),
        "srv_endpoint": _cell(srv.get("endpoint")),
        "srv_status": _cell(srv.get("status")),
        "srv_result": _cell(srv.get("result")),
        "srv_message": _cell(srv.get("message")),
        "artifact": _cell(artifact),
    }


def append_experiment(row: dict, *, path: Path | str = DEFAULT_EXPERIMENTS_CSV) -> None:
    """Append one experiment row to the log, writing the header if the file is new.

    Semicolon-delimited to match the status sheet's Excel locale. Append-only, so
    every control run on an RP is preserved for comparison (never overwritten).
    """
    path = Path(path)
    is_new = not path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=EXPERIMENT_COLUMNS, delimiter=";",
            restval="", extrasaction="ignore",
        )
        if is_new:
            writer.writeheader()
        writer.writerow(row)


def _fab_alg_cell(fab: dict) -> str:
    name = fab.get("fabrication_alg")
    cose = fab.get("fabrication_cose_alg")
    if name and cose is not None:
        return f"{name}({cose})"
    return _cell(name if name is not None else cose)


def _flags_cell(flags: Any) -> str:
    """Compact the flags dict to the set bits, e.g. 'UP,UV,BE'."""
    if not isinstance(flags, dict):
        return ""
    return ",".join(b for b in ("UP", "UV", "BE", "BS", "AT") if flags.get(b))


def _outcome_cell(fab: dict) -> str:
    outcome = fab.get("outcome") or ""
    err = fab.get("error")
    return f"{outcome}:{err}" if err else outcome


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# --- CSV upsert ----------------------------------------------------------


def upsert_status_csv(rp_id: str, params: dict, *, path: Path | str = DEFAULT_STATUS_CSV) -> None:
    """Write the `adv_*` columns for one RP into the selected-status CSV.

    Replaces the row whose ``etld1 == rp_id`` (case-insensitive), leaving every
    other row untouched; appends a new row if the RP isn't present. The file's
    delimiter (comma or semicolon) and existing columns are preserved. If the
    file doesn't exist yet, a minimal one is created with ``etld1`` + adv columns.
    """
    path = Path(path)
    rp_id = (rp_id or "").strip().lower()
    if not rp_id:
        return
    adv = flatten_adv_columns(params)

    if path.exists():
        with open(path, "r", encoding="utf-8", newline="") as f:
            first_line = f.readline()
            delimiter = _sniff_delimiter(first_line) if first_line else ";"
            f.seek(0)
            reader = csv.DictReader(f, delimiter=delimiter)
            fieldnames = list(reader.fieldnames or [])
            rows = [dict(r) for r in reader]
    else:
        delimiter = ";"
        fieldnames = ["etld1"]
        rows = []

    for col in ADV_COLUMNS:
        if col not in fieldnames:
            fieldnames.append(col)
    if "etld1" not in fieldnames:
        fieldnames.insert(0, "etld1")

    matched = False
    for row in rows:
        if (row.get("etld1") or "").strip().lower() == rp_id:
            row.update(adv)
            matched = True
            break
    if not matched:
        new_row = {fn: "" for fn in fieldnames}
        new_row["etld1"] = rp_id
        new_row.update(adv)
        rows.append(new_row)

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=fieldnames, delimiter=delimiter,
            restval="", extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
