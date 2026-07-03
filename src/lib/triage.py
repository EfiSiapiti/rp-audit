"""Classify each RP into a triage category before signup.

This is heuristic, not authoritative. The agent's system prompt requires
that the *user* review the triage output before any signup runs.

Categories:
  signup-able           — try it
  bank-or-financial     — skip, requires existing customer relationship
  subdomain-suspect     — canonical_origin is an auth/login subdomain; the
                          signup form is probably elsewhere
  region-locked-likely  — strongly country-specific RP; flagged but still
                          attempted per user preference
  needs-review          — heuristics inconclusive
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .parse import RpRow


# Substring matches in entity name (case-insensitive). Order matters:
# more specific first.
BANK_ENTITY_PATTERNS = [
    "bank of america",
    "allied irish banks",
    "nomura",
    "credit suisse",
    "deutsche bank",
    "barclays",
    "hsbc",
    "santander",
    "wells fargo",
    "jpmorgan",
    "goldman sachs",
    "morgan stanley",
]

BANK_GENERIC_TOKENS = [
    "bank",
    "banco",
    "banque",
    "bancorp",
    "securities",
    "brokerage",
    "credit union",
    "savings",
]

# eTLD+1 patterns that very strongly suggest country-specific service.
# Not exhaustive; just the ones we saw in the sample.
REGIONAL_TLD_HINTS = [
    ".jp", ".co.jp", ".de", ".no", ".cz", ".tw", ".com.tw",
    ".co.kr", ".com.br", ".com.co", ".ci", ".ie",
]

AUTH_SUBDOMAIN_HINTS = ["auth.", "accounts.", "login.", "id.", "sso.", "signin.", "online."]


@dataclass
class TriageResult:
    rp_id: str
    category: str
    reason: str


def _entity_lower(row: RpRow) -> str:
    return row.entity.lower()


def _is_bank(row: RpRow) -> tuple[bool, str]:
    el = _entity_lower(row)
    for p in BANK_ENTITY_PATTERNS:
        if p in el:
            return True, f"entity matches '{p}'"
    for tok in BANK_GENERIC_TOKENS:
        # word-boundary-ish match: avoid 'banking' false hits being missed
        if tok in el:
            return True, f"entity contains '{tok}'"
    return False, ""


def _is_subdomain_suspect(row: RpRow) -> tuple[bool, str]:
    try:
        host = urlparse(row.canonical_origin).hostname or ""
    except Exception:
        return False, ""
    for hint in AUTH_SUBDOMAIN_HINTS:
        if host.startswith(hint):
            return True, f"canonical_origin is {host} (auth subdomain)"
    return False, ""


def _is_regional(row: RpRow) -> tuple[bool, str]:
    et = row.rp_id
    for tld in REGIONAL_TLD_HINTS:
        if et.endswith(tld):
            return True, f"eTLD+1 ends in {tld}"
    return False, ""


def triage(row: RpRow) -> TriageResult:
    is_bank, bank_reason = _is_bank(row)
    if is_bank:
        return TriageResult(row.rp_id, "bank-or-financial", bank_reason)

    is_sub, sub_reason = _is_subdomain_suspect(row)
    is_reg, reg_reason = _is_regional(row)

    if is_sub and is_reg:
        return TriageResult(row.rp_id, "subdomain-suspect",
                            f"{sub_reason}; also: {reg_reason}")
    if is_sub:
        return TriageResult(row.rp_id, "subdomain-suspect", sub_reason)
    if is_reg:
        return TriageResult(row.rp_id, "region-locked-likely", reg_reason)

    if not row.entity:
        return TriageResult(row.rp_id, "needs-review", "no entity name available")

    return TriageResult(row.rp_id, "signup-able", "no exclusion heuristic matched")


def triage_all(rows: list[RpRow]) -> list[TriageResult]:
    return [triage(r) for r in rows]


if __name__ == "__main__":
    import sys
    from collections import Counter
    from .parse import parse_csv
    rows = parse_csv(sys.argv[1] if len(sys.argv) > 1 else "data/targets.csv")
    results = triage_all(rows)
    counts = Counter(r.category for r in results)
    print("triage summary:")
    for cat, n in counts.most_common():
        print(f"  {cat:25s} {n}")
    print("\nfirst 10:")
    for r in results[:10]:
        print(f"  {r.rp_id:30s} {r.category:25s} {r.reason}")
