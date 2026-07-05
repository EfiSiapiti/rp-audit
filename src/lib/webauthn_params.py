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
    "adv_rp_id",
    "adv_attestation",
    "adv_uv",
    "adv_resident_key",
    "adv_require_resident_key",
    "adv_authenticator_attachment",
    "adv_algs",
    "adv_attestation_formats",
    "adv_hints",
    "adv_extensions",
    "adv_timeout",
    # What the hook actually returned (the "given" side) + how the ceremony ended.
    "fab_alg",
    "fab_alg_offered",
    "fab_flags",
    "fab_outcome",
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
    for entry in _iter_entries(observer_log):
        et = entry.get("eventType")
        payload = entry.get("payload") or {}
        if et == "fabrication.algSelection":
            alg_sel = payload
        elif et == "fabrication.flags" and payload.get("op") == "create":
            flags = payload.get("flags")
        elif et == "fabrication.success":
            outcome = "fabricated"
        elif et == "create.success":
            outcome = "real-create"
        elif et == "create.failed":
            outcome = "create-failed"
            error = (payload.get("error") or {}).get("name")

    out: dict = {"outcome": outcome}
    if error:
        out["error"] = error
    if alg_sel:
        out["fabrication_alg"] = alg_sel.get("fabricationAlg")
        out["fabrication_cose_alg"] = alg_sel.get("coseAlg")
        out["fabrication_alg_offered"] = alg_sel.get("algInPubKeyCredParams")
    if flags:
        out["fabrication_flags"] = flags
    return out


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


def extract_advertised(observer_log: Any, webauthn_network: Any = None) -> dict | None:
    """Normalize the advertised WebAuthn create options into a flat record.

    Returns None if no `create.called` event with public-key options is present.
    """
    opts = _latest_create_options(observer_log)
    if opts is None:
        return None

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

    server_algs = _server_algs_from_network(webauthn_network)
    if server_algs is not None:
        record["server_pub_key_algs"] = server_algs

    # The given/outcome side (what we returned, and how the ceremony ended).
    record["fabrication"] = _scan_fabrication(observer_log)

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
        "adv_hints": _join(params.get("hints")),
        "adv_extensions": _join(params.get("extensions")),
        "adv_timeout": _cell(params.get("timeout")),
        "fab_alg": _fab_alg_cell(fab),
        "fab_alg_offered": _cell(fab.get("fabrication_alg_offered")),
        "fab_flags": _flags_cell(fab.get("fabrication_flags")),
        "fab_outcome": _outcome_cell(fab),
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
