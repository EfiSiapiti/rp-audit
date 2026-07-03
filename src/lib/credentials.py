"""Credential vault.

The agent must never see the actual password in its message history.
Reasoning traces (especially with tool-use logging on) end up in
Anthropic's servers per their data retention policy; secrets in those
traces are a real leak even if the conversation is private.

So: the agent calls fill_credential(ref, 'password') and our tool
implementation resolves 'password' to the actual value before passing
it to Playwright. The literal string never touches the LLM context.

The fill_text tool exists separately for non-secret values (display
name, country, etc.) where the actual content doesn't matter.
"""

from __future__ import annotations

import json
from pathlib import Path


_identity_cache: dict | None = None


def load_identity() -> dict:
    global _identity_cache
    if _identity_cache is not None:
        return _identity_cache
    path = Path("identity.json")
    if not path.exists():
        raise SystemExit("identity.json not found — copy identity.example.json and fill in")
    with open(path, "r", encoding="utf-8") as f:
        _identity_cache = json.load(f)
    return _identity_cache


CREDENTIAL_FIELDS = {
    "email", "password", "first_name", "last_name", "display_name",
    "username", "dob", "country", "country_name", "city", "language",
}


def resolve(field: str, *, rp_id: str) -> str:
    """Return the value to type for a named credential field."""
    if field not in CREDENTIAL_FIELDS:
        raise ValueError(f"unknown credential field: {field}. "
                         f"Known: {sorted(CREDENTIAL_FIELDS)}")

    identity = load_identity()
    
    if field == "password":
        # Use password from identity.json only
        return identity["password"]

    if field == "username":
        import re
        base = identity.get("username_base") or identity["email"].split("@")[0]
        # Strip non-alphanumeric chars — many RPs reject dots/symbols in usernames
        return re.sub(r"[^a-zA-Z0-9]", "", base)

    val = identity.get(field)
    if val is None:
        raise ValueError(f"identity.json has no value for {field!r}")
    return str(val)


def describe_available() -> str:
    """Return a human-readable list of credential fields, for the system prompt."""
    return ", ".join(sorted(CREDENTIAL_FIELDS))
