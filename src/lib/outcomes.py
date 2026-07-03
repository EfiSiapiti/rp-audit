"""Outcome policy — the single source of truth for what each ledger state means.

The ledger stores a free-form `state` string per RP (see ledger.py). This module
classifies those states into buckets so the report and the requeue CLI agree on
which RPs are *done* (terminal), which are worth a *second pass* (retryable), and
which have been retried too many times (exhausted).

Kept dependency-free (no project imports) so anything can import it without cycles.
"""

from __future__ import annotations


# --- canonical state sets -------------------------------------------------

# The agent succeeded and we have a session.
SUCCESS = {"captured"}

# Done — never worth an automatic second pass. A human can still --force a requeue.
TERMINAL = {
    "captured",                  # success (also terminal: don't re-run)
    "phone-gated",               # phone verification required
    "geo-blocked",               # RP refuses our region
    "requires-existing-account", # bank / KYC / invite-only
    "duplicate-account",         # our email is already registered
    "captcha-blocked",           # needs a human to solve a CAPTCHA
    "no-portal",                 # site has no web account system at all
    "dns-dead",                  # domain does not resolve
    "bank-skip",                 # excluded by triage
}

# Worth re-attempting (subject to the note check + attempt cap below).
RETRYABLE = {"failed", "redo", "pending"}

# The valid outcomes a signup run may record. Imported by
# scripts/manual_signup.py so the set lives in exactly one place.
AGENT_OUTCOMES = {
    "captured", "phone-gated", "captcha-blocked", "geo-blocked",
    "duplicate-account", "requires-existing-account", "failed",
    "no-portal", "dns-dead",
}

DEFAULT_MAX_ATTEMPTS = 3


# --- note heuristics ------------------------------------------------------
# A bare `failed` is ambiguous; the note tells us whether the cause was
# transient (retry) or permanent (terminal). Transient hints win over
# permanent ones so we err toward giving a flaky run one more chance.

RETRYABLE_NOTE_HINTS = (
    "turn budget",
    "imap",
    "verification email",
    "not_found",
    "loop detected",
    "timeout",
    "navigation failed",
    "consent",
    "iframe",
    "networkidle",
    "snapshot",
    "link-email-verification",
    "did not advance",
    "did not progress",
    "not captured in snapshot",
)

TERMINAL_NOTE_HINTS = (
    "err_name_not_resolved",
    "does not resolve",
    "phone",
    "geo",
    "kyc",
    "invite-only",
    "requires-existing-account",
    "signup form not found",
    "temporarily blocked",
    "too many failures",
)


# --- classification -------------------------------------------------------

def is_retryable(state: str, note: str = "") -> bool:
    """True if this (state, note) is worth a second pass, ignoring the attempt cap."""
    if state not in RETRYABLE:
        return False
    if state in ("pending", "redo"):
        return True
    # state == "failed": disambiguate via the note.
    note_l = (note or "").lower()
    if any(h in note_l for h in RETRYABLE_NOTE_HINTS):
        return True
    if any(h in note_l for h in TERMINAL_NOTE_HINTS):
        return False
    # Bare failure with no informative note — be conservative and allow a retry.
    return True


def is_terminal(state: str, note: str = "") -> bool:
    """True if this (state, note) should never be auto-retried.

    Unknown / legacy / interrupted states (e.g. in-progress, needs-review,
    subdomain-suspect, any enroll-* state) are treated as terminal so the
    requeue sweep never disturbs them.
    """
    return not is_retryable(state, note)


def classify(state: str, note: str = "", attempts: int = 0,
             max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> str:
    """Bucket an entry: 'success' | 'terminal' | 'retry' | 'exhausted'."""
    if state in SUCCESS:
        return "success"
    if is_retryable(state, note):
        if attempts >= max_attempts:
            return "exhausted"
        return "retry"
    return "terminal"
