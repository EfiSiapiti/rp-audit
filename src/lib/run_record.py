"""Shared run-record writers — keep every signup run recorded identically.

The manual signup command (scripts/manual_signup.py) and session-recovery
(scripts/capture_session.py) finish a run by appending a one-line summary to
data/batch_log.jsonl. Keeping that writer here (rather than private to one
script) means every path emits the same shape, and the `source` field records
how each `captured` outcome was produced.

Kept dependency-free (no project imports) so anything can import it without cycles.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

BATCH_LOG_PATH = Path("data/batch_log.jsonl")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_batch_log(rp_id: str, outcome: str, attempts: int, note: str,
                     *, source: str = "agent") -> None:
    """Append a one-line summary of a finished run to data/batch_log.jsonl."""
    BATCH_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "at": _now_iso(),
        "rp_id": rp_id,
        "outcome": outcome,
        "attempts": attempts,
        "note": note,
        "source": source,
    }
    with open(BATCH_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
