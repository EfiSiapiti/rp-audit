"""Parse the WebAuthn scan CSV into RP records.

Your CSV columns (from the sample you provided):
  canonical_origin, etld1, entity, enroll_url, cluster_size, snapshot_count, source

Quirks handled:
- 'entity' column often contains unquoted commas ("DocuSign, Inc.").
  Standard csv module copes with quoted commas; we also tolerate the
  unquoted form by reading column-positionally from the right.
- etld1 is our canonical rp_id (used for filenames + password HMAC).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RpRow:
    rp_id: str               # etld1, canonical
    canonical_origin: str
    entity: str
    enroll_url: str
    cluster_size: int
    snapshot_count: int
    source: str

    @property
    def has_enroll_url(self) -> bool:
        return bool(self.enroll_url.strip())


def _to_int(value: str) -> int:
    """Coerce a numeric CSV cell to int, tolerating float-formatted integers
    like '133.0' (common in pandas/Excel exports) and blank cells."""
    value = (value or "").strip()
    if not value:
        return 0
    return int(float(value))


def _sniff_delimiter(header_line: str) -> str:
    """Comma or semicolon? Excel/locale exports often use ';'. Pick whichever
    separator appears more often in the header row."""
    return ";" if header_line.count(";") > header_line.count(",") else ","


def parse_csv(path: Path | str) -> list[RpRow]:
    rows: list[RpRow] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        delimiter = _sniff_delimiter(f.readline())
        f.seek(0)
        reader = csv.reader(f, delimiter=delimiter)
        header = next(reader)
        # Map header to positions defensively in case columns shift.
        idx = {name: i for i, name in enumerate(header)}
        required = ["canonical_origin", "etld1", "enroll_url",
                    "cluster_size", "snapshot_count", "source"]
        for col in required:
            if col not in idx:
                raise ValueError(f"missing column in CSV: {col}")

        n_expected = len(header)
        for raw in reader:
            if not raw:
                continue
            if len(raw) == n_expected:
                # well-formed (csv module already handled quoted commas)
                canonical_origin = raw[idx["canonical_origin"]]
                etld1 = raw[idx["etld1"]]
                entity = raw[idx["entity"]] if "entity" in idx else ""
                enroll_url = raw[idx["enroll_url"]]
                cluster_size = raw[idx["cluster_size"]]
                snapshot_count = raw[idx["snapshot_count"]]
                source = raw[idx["source"]]
            elif len(raw) > n_expected:
                # unquoted comma in entity: reconstruct by taking known
                # positions from start (canonical_origin, etld1) and end
                # (enroll_url, cluster_size, snapshot_count, source).
                # everything between collapses into entity.
                canonical_origin = raw[0]
                etld1 = raw[1]
                source = raw[-1]
                snapshot_count = raw[-2]
                cluster_size = raw[-3]
                enroll_url = raw[-4]
                entity = ",".join(raw[2:-4]).strip()
            else:
                # too few columns to even reconstruct; skip with a warning
                print(f"warn: skipping malformed row: {raw!r}")
                continue

            rows.append(RpRow(
                rp_id=etld1.strip().lower(),
                canonical_origin=canonical_origin.strip(),
                entity=entity.strip(),
                enroll_url=enroll_url.strip(),
                cluster_size=_to_int(cluster_size),
                snapshot_count=_to_int(snapshot_count),
                source=source.strip(),
            ))
    return rows


if __name__ == "__main__":
    import sys
    rows = parse_csv(sys.argv[1] if len(sys.argv) > 1 else "data/targets.csv")
    print(f"parsed {len(rows)} rows")
    for r in rows[:5]:
        print(f"  {r.rp_id:30s} entity={r.entity!r:40s} enroll={'y' if r.has_enroll_url else 'n'}")
