"""Per-RP state machine, persisted to data/ledger.json.

Atomic writes (write-temp-then-rename) so a Ctrl+C mid-write can't corrupt
the file. The ledger is the single source of truth for what's been done.

States:
  pending           — not yet attempted
  bank-skip         — excluded by triage (financial institution)
  subdomain-suspect — auth subdomain; signup likely elsewhere, needs review
  needs-review      — triage inconclusive; user decides
  discovering       — signup URL discovery in progress
  signup-able       — discovered + ready
  in-progress       — runner is currently working this RP
  captured          — session captured + validated
  phone-gated       — form required phone verification
  captcha-blocked   — manual CAPTCHA needed, paused for user
  geo-blocked       — RP refused service from this IP/region
  duplicate-account — RP rejected our email as already registered
  no-portal         — site has no web account system (informational/app-only)
  dns-dead          — domain does not resolve (ERR_NAME_NOT_RESOLVED)
  failed            — runner errored or signup failed for other reason
  redo              — user-requested retry

See lib/outcomes.py for how these states are bucketed (terminal / retryable).
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LEDGER_PATH = Path("data/ledger.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # write to sibling tmp file, then replace — safe across Ctrl+C
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load() -> dict:
    if not LEDGER_PATH.exists():
        return {"version": 1, "created": _now(), "entries": {}}
    with open(LEDGER_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save(ledger: dict) -> None:
    _atomic_write_json(LEDGER_PATH, ledger)


def init_from_triage(rows, triage_results) -> dict:
    """Build initial ledger from parsed CSV + triage output. Idempotent:
    existing entries keep their state and history; new RPs get added."""
    ledger = load()
    entries = ledger.setdefault("entries", {})
    triage_by_id = {t.rp_id: t for t in triage_results}

    for row in rows:
        if row.rp_id in entries:
            continue
        tr = triage_by_id.get(row.rp_id)
        state_map = {
            "signup-able": "pending",
            "bank-or-financial": "bank-skip",
            "subdomain-suspect": "subdomain-suspect",
            "region-locked-likely": "pending",  # still attempted per user pref
            "needs-review": "needs-review",
        }
        initial_state = state_map.get(tr.category if tr else "needs-review", "needs-review")

        entries[row.rp_id] = {
            "rp_id": row.rp_id,
            "canonical_origin": row.canonical_origin,
            "entity": row.entity,
            "enroll_url": row.enroll_url,
            "state": initial_state,
            "triage_category": tr.category if tr else "needs-review",
            "triage_reason": tr.reason if tr else "",
            "signup_url": "",          # filled by discovery
            "history": [{"at": _now(), "state": initial_state, "note": "initialized"}],
            "attempts": 0,
        }
    save(ledger)
    return ledger


def get_next_pending(ledger: dict, *, allowed_states=("pending", "redo")) -> dict | None:
    """Return the next entry in an allowed state, or None."""
    for entry in ledger["entries"].values():
        if entry["state"] in allowed_states:
            return entry
    return None


def update_state(ledger: dict, rp_id: str, new_state: str, *, note: str = "",
                 extra: dict | None = None) -> None:
    entry = ledger["entries"][rp_id]
    entry["state"] = new_state
    if extra:
        entry.update(extra)
    entry["history"].append({"at": _now(), "state": new_state, "note": note})
    save(ledger)


def increment_attempts(ledger: dict, rp_id: str) -> int:
    entry = ledger["entries"][rp_id]
    entry["attempts"] = entry.get("attempts", 0) + 1
    save(ledger)
    return entry["attempts"]


def summary(ledger: dict) -> dict[str, int]:
    from collections import Counter
    return dict(Counter(e["state"] for e in ledger["entries"].values()))


if __name__ == "__main__":
    from .outcomes import classify  # local import avoids an import cycle

    led = load()
    entries = led.get("entries", {})
    print(f"ledger has {len(entries)} entries")
    for state, count in sorted(summary(led).items()):
        print(f"  {state:25s} {count}")
    second_pass = sum(
        1 for e in entries.values()
        if classify(e.get("state", ""),
                    (e.get("history") or [{}])[-1].get("note", ""),
                    e.get("attempts", 0)) == "retry"
    )
    print(f"  {'second-pass candidates':25s} {second_pass}  (see: python -m src.report)")
