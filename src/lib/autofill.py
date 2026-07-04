"""Best-effort form autofill from identity.json.

The manual signup flow (scripts/manual_signup.py) opens each RP and lets you
drive by hand. This module does the tedious part: it scans the current page for
the usual signup inputs and fills them from identity.json (via
src/lib/credentials.py), so you only have to handle the parts a heuristic can't
— consent checkboxes, multi-step wizards, CAPTCHAs, the submit click.

It is deliberately conservative: it only fills *visible, empty* inputs, matches
one input per field, and never clicks submit. If a match is wrong, clear it and
type over it — nothing here is destructive.

Field → candidate matchers are ordered most-specific first. Matching leans on
the `autocomplete` attribute where present (the most reliable signal), then
falls back to type / name / id / placeholder substrings.
"""

from __future__ import annotations

from . import consent
from . import credentials

# Each entry: (identity field, [locator specs tried in order]).
# A locator spec is a CSS selector evaluated against the page; the first
# visible, empty, enabled match wins for that field.
_FIELD_SELECTORS: list[tuple[str, list[str]]] = [
    ("email", [
        "input[autocomplete='email']",
        "input[type='email']",
        "input[name*='email' i]",
        "input[id*='email' i]",
        "input[placeholder*='email' i]",
    ]),
    ("first_name", [
        "input[autocomplete='given-name']",
        "input[name*='first' i]",
        "input[id*='first' i]",
        "input[name*='given' i]",
        "input[placeholder*='first name' i]",
    ]),
    ("last_name", [
        "input[autocomplete='family-name']",
        "input[name*='last' i]",
        "input[id*='last' i]",
        "input[name*='surname' i]",
        "input[name*='family' i]",
        "input[placeholder*='last name' i]",
    ]),
    ("display_name", [
        "input[autocomplete='name']",
        "input[name='name']",
        "input[name*='fullname' i]",
        "input[name*='full_name' i]",
        "input[name*='display' i]",
        "input[placeholder*='full name' i]",
    ]),
    ("username", [
        "input[autocomplete='username']",
        "input[name*='username' i]",
        "input[id*='username' i]",
        "input[name='user' i]",
        "input[placeholder*='username' i]",
    ]),
    ("password", [
        "input[autocomplete='new-password']",
        "input[type='password']",
        "input[name*='password' i]",
        "input[id*='password' i]",
    ]),
    ("city", [
        "input[autocomplete='address-level2']",
        "input[name*='city' i]",
        "input[placeholder*='city' i]",
    ]),
]


async def _first_fillable(page, selector: str):
    """Return the first visible, empty, enabled locator for a selector, or None."""
    loc = page.locator(selector)
    try:
        count = await loc.count()
    except Exception:
        return None
    for i in range(min(count, 10)):
        el = loc.nth(i)
        try:
            if not await el.is_visible():
                continue
            if not await el.is_enabled():
                continue
            if (await el.input_value()).strip():
                continue  # already has a value — leave it be
            return el
        except Exception:
            continue
    return None


async def autofill(page, rp_id: str) -> dict[str, str]:
    """Fill known signup fields on `page` from identity.json.

    Returns a {field: value-or-status} map of what happened, so the caller can
    print a summary. Never raises on a per-field failure, never clicks submit,
    and never overwrites a field the user already filled.
    """
    filled: dict[str, str] = {}
    used_password = False
    for field, selectors in _FIELD_SELECTORS:
        # Only one password box gets the real password; a second password input
        # is almost always "confirm password", which we also fill.
        try:
            value = credentials.resolve(field, rp_id=rp_id)
        except Exception:
            continue  # identity.json has no value for this field — skip
        target = None
        for sel in selectors:
            target = await _first_fillable(page, sel)
            if target is not None:
                break
        if target is None:
            continue
        try:
            await target.fill(value)
            shown = "***" if field == "password" else value
            filled[field] = shown
            if field == "password":
                used_password = True
        except Exception as e:
            filled[field] = f"(failed: {e})"

    # Confirm-password: a second empty password box, filled with the same value.
    if used_password:
        try:
            pw = credentials.resolve("password", rp_id=rp_id)
            boxes = page.locator("input[type='password']")
            n = await boxes.count()
            for i in range(min(n, 4)):
                el = boxes.nth(i)
                if await el.is_visible() and not (await el.input_value()).strip():
                    await el.fill(pw)
                    filled["confirm_password"] = "***"
                    break
        except Exception:
            pass

    return filled


# JS to extract a checkbox's best-effort label text: aria-label, an associated
# <label for=id>, an enclosing <label>, then the parent element's text.
_CHECKBOX_LABEL_JS = r"""
(el) => {
    const aria = el.getAttribute('aria-label');
    if (aria) return aria;
    if (el.id) {
        const lab = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
        if (lab && lab.innerText) return lab.innerText;
    }
    const wrap = el.closest('label');
    if (wrap && wrap.innerText) return wrap.innerText;
    const p = el.parentElement;
    return (p && p.innerText) ? p.innerText : '';
}
"""


async def fill_verification_code(page, code: str) -> bool:
    """Best-effort: type a verification code into the page's OTP/code field(s).

    Handles two common layouts: a single code input, and a row of single-
    character boxes (maxlength=1) that you type one digit into each. Returns
    True if it typed the whole code somewhere, else False (type it by hand).
    Never clicks submit.
    """
    code = (code or "").strip()
    if not code:
        return False

    # 1. A single code field. Most-specific hints first; the bare numeric
    #    inputmode is last so a phone field doesn't win over a real code box.
    single_selectors = [
        "input[autocomplete='one-time-code']",
        "input[name*='otp' i]", "input[id*='otp' i]",
        "input[name*='code' i]", "input[id*='code' i]",
        "input[name*='verif' i]", "input[id*='verif' i]",
        "input[placeholder*='code' i]",
        "input[inputmode='numeric']",
    ]
    for sel in single_selectors:
        el = await _first_fillable(page, sel)
        if el is not None:
            try:
                await el.fill(code)
                return True
            except Exception:
                continue

    # 2. A row of single-character boxes — type one digit into each.
    try:
        boxes = page.locator("input[maxlength='1']")
        n = await boxes.count()
    except Exception:
        n = 0
    if n >= len(code):
        typed = 0
        for i in range(n):
            el = boxes.nth(i)
            try:
                if not await el.is_visible() or not await el.is_enabled():
                    continue
                await el.fill(code[typed])
                typed += 1
                if typed >= len(code):
                    return True
            except Exception:
                continue
    return False


async def tick_consent_checkboxes(page, rp_id: str) -> list[str]:
    """Tick required agreement checkboxes (Terms/Privacy/age), leave the rest.

    Uses consent.classify_checkbox_label so a marketing opt-in phrased as
    "I agree to receive offers" is left unticked. Only ticks visible, enabled,
    currently-unchecked boxes. Returns the labels it ticked (for logging).
    """
    ticked: list[str] = []
    boxes = page.locator("input[type='checkbox']")
    try:
        count = await boxes.count()
    except Exception:
        return ticked
    for i in range(min(count, 30)):
        el = boxes.nth(i)
        try:
            if not await el.is_visible() or not await el.is_enabled():
                continue
            if await el.is_checked():
                continue
            label = (await el.evaluate(_CHECKBOX_LABEL_JS) or "").strip()
            if consent.classify_checkbox_label(label) != "agree":
                continue
            await el.check(timeout=3_000)
            ticked.append(" ".join(label.split())[:60] or "(unlabeled)")
        except Exception:
            continue
    return ticked
