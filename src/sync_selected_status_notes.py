"""Copy the current ledger state and last note into a selected-target CSV.

Usage:
    python -m src.sync_selected_status_notes data/targets_selected.csv data/targets_selected_status.csv

The input CSV is treated as read-only. The output CSV keeps the existing
columns and appends/updates `status` and `notes` from `data/ledger.json`.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from urllib.parse import urlparse

from .lib import ledger, webauthn_params
from .lib.parse import _sniff_delimiter


DEFAULT_INPUT = Path("data/targets_selected.csv")
DEFAULT_OUTPUT = Path("data/targets_selected_status.csv")


def _row_rp_id(row: dict[str, str]) -> str:
    rp_id = (row.get("etld1") or "").strip().lower()
    if rp_id:
        return rp_id
    origin = (row.get("canonical_origin") or "").strip()
    if origin:
        return (urlparse(origin).hostname or "").lower()
    return ""


def _last_note(entry: dict) -> str:
    history = entry.get("history") or []
    if history:
        return history[-1].get("note", "")
    return entry.get("note", "") or ""


def _sync_rows(rows: list[dict[str, str]], entries: dict[str, dict]) -> tuple[list[dict[str, str]], int, list[str]]:
    synced: list[dict[str, str]] = []
    matched = 0
    missing: list[str] = []

    for row in rows:
        rp_id = _row_rp_id(row)
        entry = entries.get(rp_id) if rp_id else None
        if entry is None:
            row["status"] = ""
            row["notes"] = ""
            row.update(webauthn_params.flatten_adv_columns(None))
            if rp_id:
                missing.append(rp_id)
        else:
            matched += 1
            row["status"] = entry.get("state", "")
            row["notes"] = _last_note(entry)
            # Reproject the advertised WebAuthn params the same way per-run
            # capture does, so a resync reproduces the adv_* columns exactly.
            row.update(
                webauthn_params.flatten_adv_columns(entry.get("advertised_params"))
            )
        synced.append(row)

    return synced, matched, missing


def main() -> None:
    ap = argparse.ArgumentParser(description="Sync selected targets with ledger status + notes.")
    ap.add_argument("input", nargs="?", default=str(DEFAULT_INPUT),
                    help=f"input CSV (default: {DEFAULT_INPUT})")
    ap.add_argument("output", nargs="?", default=str(DEFAULT_OUTPUT),
                    help=f"output CSV (default: {DEFAULT_OUTPUT})")
    args = ap.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.exists():
        raise SystemExit(f"input CSV not found: {input_path}")

    with open(input_path, "r", encoding="utf-8", newline="") as f:
        first_line = f.readline()
        if not first_line:
            raise SystemExit(f"input CSV is empty: {input_path}")
        delimiter = _sniff_delimiter(first_line)
        f.seek(0)
        reader = csv.DictReader(f, delimiter=delimiter)
        if not reader.fieldnames:
            raise SystemExit(f"input CSV has no header: {input_path}")
        rows = [dict(row) for row in reader]

    led = ledger.load()
    entries = led.get("entries", {})
    synced_rows, matched, missing = _sync_rows(rows, entries)

    fieldnames = list(reader.fieldnames)
    for col in ("status", "notes", *webauthn_params.ADV_COLUMNS):
        if col not in fieldnames:
            fieldnames.append(col)

    # Preserve the delimiter the output file already uses (the status CSV the
    # user maintains is ';'-delimited even though the input is ','), so a resync
    # doesn't reformat their file and stays consistent with the per-run writer
    # in webauthn_params.upsert_status_csv. Fall back to the input delimiter for
    # a brand-new output.
    out_delimiter = delimiter
    if output_path.exists():
        with open(output_path, "r", encoding="utf-8", newline="") as f:
            existing_header = f.readline()
        if existing_header:
            out_delimiter = _sniff_delimiter(existing_header)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=out_delimiter, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(synced_rows)

    print(f"synced {matched}/{len(rows)} selected targets from {input_path}")
    print(f"wrote {output_path}")
    if missing:
        print(f"missing ledger entries for {len(missing)} row(s): {', '.join(missing[:10])}" +
              (" ..." if len(missing) > 10 else ""))


if __name__ == "__main__":
    main()