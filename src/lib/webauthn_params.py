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
from pathlib import Path
from typing import Any, Iterable

from src.lib.parse import _sniff_delimiter


DEFAULT_STATUS_CSV = Path("data/targets_selected_status.csv")

# Flat spreadsheet columns, in display order. Kept as a module constant so the
# per-run writer (upsert_status_csv) and the bulk resync (sync_selected_status_notes)
# agree on names and ordering.
ADV_COLUMNS = [
    # (1) What the RP advertised in PublicKeyCredentialCreationOptions.
    "adv_rp_id",
    "adv_attestation",
    "adv_uv",
    "adv_resident_key",
    "adv_require_resident_key",
    "adv_authenticator_attachment",
    "adv_algs",            # from the client-side options the hook saw
    "adv_attestation_formats",
    "adv_timeout",
    # (2) The credential that was actually returned (the "selected"/given side).
    "fab_alg",
    "fab_alg_offered",
    "fab_flags",
    "fab_outcome",
    # (3) What the server said back to the finish/registration request.
    "srv_endpoint",
    "srv_status",
    "srv_result",
    "srv_message",
    "adv_captured_at",
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


def _latest_create_options(observer_log: Any) -> dict | None:
    """Return the `options` summary from the most recent `create.called` event."""
    options = None
    for entry in _iter_entries(observer_log):
        if entry.get("eventType") == "create.called":
            opts = (entry.get("payload") or {}).get("options")
            if isinstance(opts, dict) and opts.get("hasPublicKey"):
                options = opts
    return options


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
    for entry in _iter_entries(observer_log):
        et = entry.get("eventType")
        payload = entry.get("payload") or {}
        if et == "fabrication.algSelection":
            alg_sel = payload
        elif et == "fabrication.flags" and payload.get("op") == "create":
            flags = payload.get("flags")
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


# Substrings that, in a 2xx finish response body, suggest the RP still rejected.
_ERROR_MARKERS = (
    "error", "invalid", "failed", "failure", "denied", "reject",
    "exception", "not allowed", "unsupported", "must be",
)


def _find_last_post(requests: list, markers: list) -> dict | None:
    """Last POST whose body contains any of `markers`."""
    found = None
    for r in requests:
        try:
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
    # Prefer a credId match (strong evidence); fall back to field-name markers.
    finish = _find_last_post(requests, cred_ids) or _find_last_post(
        requests, ["credential_id", "attestationObject", "attestation_object",
                   '"rawId"', "authenticatorAttachment"]
    )
    if finish is None:
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
    body = (resp.get("body") if resp else "") or ""
    # Strip Facebook/Meta's XSSI anti-hijacking prefix before inspecting.
    clean = body
    for prefix in ("for (;;);", "while(1);", ")]}'"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
            break
    snippet = " ".join(clean.split())
    if len(snippet) > 400:
        snippet = snippet[:400] + "…"

    low = clean.lower()
    norm = "".join(low.split())  # whitespace-insensitive for "success": true
    accepted = '"success":true' in norm or '"verified":true' in norm or '"ok":true' in norm
    if status is None:
        result = "unknown"
    elif status >= 400:
        result = "rejected"
    elif '"errors"' in low or any(m in low for m in _ERROR_MARKERS):
        result = "rejected?"
    elif accepted:
        result = "accepted"
    else:
        result = "accepted?"

    fn = _friendly_name(finish)
    endpoint = _path(url) + (f" ({fn})" if fn else "")
    return {"endpoint": endpoint, "status": status, "result": result, "message": snippet}


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


def extract_advertised(observer_log: Any, network: Any = None) -> dict | None:
    """Normalize one ceremony into a flat record with three parts: what the RP
    advertised, what credential was selected/returned, and the server's verdict.

    Returns None if no `create.called` event with public-key options is present.
    `network` is run.py's {"requests", "responses"} dict (or the older flat list).
    """
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
    record["server"] = _server_verdict(
        requests, responses, fab.get("cred_ids") or [fab.get("cred_id")]
    )

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
    """Map a normalized advertised-params record to flat `adv_*` string cells.

    Nested values are compacted so each lands cleanly in one spreadsheet cell:
    algs as ``-7|-257``; lists as comma-joined. Every ADV_COLUMNS key is always
    present (blank when unknown) so the CSV header stays stable.
    """
    params = params or {}
    fab = params.get("fabrication") or {}
    srv = params.get("server") or {}
    return {
        # (1) advertised
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
        # (2) selected / returned
        "fab_alg": _fab_alg_cell(fab),
        "fab_alg_offered": _cell(fab.get("fabrication_alg_offered")),
        "fab_flags": _flags_cell(fab.get("fabrication_flags")),
        "fab_outcome": _outcome_cell(fab),
        # (3) server verdict
        "srv_endpoint": _cell(srv.get("endpoint")),
        "srv_status": _cell(srv.get("status")),
        "srv_result": _cell(srv.get("result")),
        "srv_message": _cell(srv.get("message")),
        "adv_captured_at": _cell(params.get("captured_at")),
    }


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
