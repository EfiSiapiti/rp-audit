"""Date-of-birth formatting helpers.

The identity stores `dob` in ISO form ("1995-01-01"). Native
`<input type="date">` accepts that directly, but many sites use a masked
text widget (e.g. "mm / dd / yyyy"): setting `.value` programmatically is
rejected, and the digit order is locale-specific. These pure helpers turn
an ISO date into the digit string / separated string a masked field
expects, in the order implied by its placeholder. The actual typing lives
in the signup tool.
"""

from __future__ import annotations

import re


def parse_iso_date(value: str) -> tuple[int, int, int] | None:
    """Parse a stored DOB into (year, month, day). Returns None if it can't.

    Handles the canonical ISO "YYYY-MM-DD" and is defensive about a few
    other shapes the identity file might contain.
    """
    s = (value or "").strip()
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})$", s)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    parts = [p for p in re.split(r"\D+", s) if p]
    if len(parts) == 3:
        if len(parts[0]) == 4:          # YYYY ? ?  -> assume Y M D
            return int(parts[0]), int(parts[1]), int(parts[2])
        if len(parts[2]) == 4:          # ? ? YYYY  -> assume M D Y
            return int(parts[2]), int(parts[0]), int(parts[1])
    return None


def date_field_order(hint: str) -> list[str]:
    """Infer field order from a placeholder/label like 'mm / dd / yyyy'.

    Returns a list of 'm'/'d'/'y' in the order they appear. Falls back to
    US month-day-year when the hint carries no clear d/m/y pattern (so prose
    like "Date of birth" doesn't produce a bogus order).

    Scans multi-character tokens, not single letters: mask tokens (mm/dd/yyyy
    and locale variants) first, then whole words. The old single-letter scan
    picked up stray d/m/y from surrounding prose — e.g. "Birthday (mm/dd/yyyy)"
    matched the d and y in "birthda-y" before reaching the real mask and
    returned a scrambled order.
    """
    h = (hint or "").lower()

    def _order(token_sets: dict[str, tuple[str, ...]]) -> list[str] | None:
        positions: list[tuple[int, str]] = []
        for comp, pats in token_sets.items():
            idxs = [h.find(p) for p in pats if p in h]
            if idxs:
                positions.append((min(idxs), comp))
        if len(positions) == 3:
            positions.sort()
            return [comp for _, comp in positions]
        return None

    # Tier 1: unambiguous mask tokens.
    order = _order({"y": ("yyyy", "aaaa", "yy"), "m": ("mm",), "d": ("dd", "jj")})
    if order:
        return order
    # Tier 2: whole words (a few locale variants we actually hit).
    order = _order({
        "y": ("year", "año", "jahr"),
        "m": ("month", "monat", "mois", "mes"),
        "d": ("day", "tag", "jour", "dia"),
    })
    if order:
        return order
    return ["m", "d", "y"]


def _parts_map(year: int, month: int, day: int) -> dict[str, str]:
    return {"m": f"{month:02d}", "d": f"{day:02d}", "y": f"{year:04d}"}


def date_digits(year: int, month: int, day: int, order: list[str]) -> str:
    """Digits only, in field order, e.g. order=[m,d,y] -> '03251995'.

    This is what gets typed into a masked widget; the mask inserts the
    separators itself as keystrokes arrive.
    """
    parts = _parts_map(year, month, day)
    return "".join(parts[k] for k in order)


def date_with_separators(year: int, month: int, day: int,
                         order: list[str], sep: str = "/") -> str:
    """Separated string in field order, e.g. '03/25/1995' — a fallback for
    widgets that accept a fully-formed value."""
    parts = _parts_map(year, month, day)
    return sep.join(parts[k] for k in order)


def _maxlen(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def assign_date_segments(fields: list[dict], year: int, month: int,
                         day: int) -> list[tuple]:
    """Map separate date-segment inputs to their values.

    `fields` is a list (DOM order) of dicts with keys: idx, placeholder,
    ariaLabel, name, maxlength. Returns [(idx, value), ...] with zero-padded
    month/day and a 4-digit year.

    Each field's component is inferred from date tokens in its
    placeholder/aria/name (mm/dd/yyyy/month/day/year and locale variants),
    with maxlength==4 as a year hint. Fields with no usable token are filled
    by elimination in default month-day-year order, so a fully unlabelled
    3-box group still gets a sensible US-style assignment. The first field to
    claim a component wins (no duplicates).
    """
    parts = {"m": f"{month:02d}", "d": f"{day:02d}", "y": f"{year:04d}"}

    comps: list[str | None] = []
    for f in fields:
        hint = " ".join(str(f.get(k) or "") for k in
                        ("placeholder", "ariaLabel", "name")).lower()
        ml = _maxlen(f.get("maxlength"))
        if "yyyy" in hint or "yy" in hint or "year" in hint or "aaaa" in hint or ml == 4:
            comps.append("y")
        elif "mm" in hint or "month" in hint:
            comps.append("m")
        elif "dd" in hint or "day" in hint or "jj" in hint:
            comps.append("d")
        else:
            comps.append(None)

    # Fill unknowns by elimination in default month-day-year order.
    assigned = {c for c in comps if c}
    remaining = [c for c in ("m", "d", "y") if c not in assigned]
    ri = 0
    for i, c in enumerate(comps):
        if c is None and ri < len(remaining):
            comps[i] = remaining[ri]
            ri += 1

    out: list[tuple] = []
    seen: set[str] = set()
    for f, c in zip(fields, comps):
        if c and c not in seen:
            out.append((f.get("idx"), parts[c]))
            seen.add(c)
    return out
