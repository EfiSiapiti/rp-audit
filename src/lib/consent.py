"""Dismiss cookie/consent banners.

Shared by the `dismiss_consent` agent tool and the gate-hint click_path
replay, so the selector/label list lives in exactly one place.
"""

from __future__ import annotations

import asyncio


# CMP-specific selectors first (precise), then 'accept all' labels across
# the languages we actually hit (Norwegian, German, French, Spanish, Italian).
_CSS_SELECTORS = [
    ".message-component button",          # SourcePoint
    "#onetrust-accept-btn-handler",       # OneTrust
    'button[title*="Accept" i]',
    'button[aria-label*="Accept" i]',
]

_LABEL_TEXTS = [
    "Accept all", "Allow all", "Accept cookies", "I accept", "I agree",
    "Agree", "Godta alle", "Tillat alle", "Aksepter alle",
    "Alle akzeptieren", "Tout accepter", "Aceptar todo", "Accetta tutto",
]


# Keywords for classifying in-form checkboxes, in priority order.
# STRONG agreement = unambiguous Terms/Privacy/age boxes we SHOULD tick — these
# win outright. MARKETING = optional newsletter/offers boxes we must NOT tick.
# WEAK agreement = "agree"/"accept"-type words that often appear in marketing
# opt-ins too ("I agree to receive offers"), so they only decide AFTER marketing
# is ruled out. The same lists are passed into the page by check_consent_boxes
# so the in-browser JS and classify_checkbox_label stay in sync.
STRONG_AGREEMENT_WORDS = (
    "terms", "privacy", "polic", "conditions", "gdpr", "eula", "age of",
    "18 year", "code of conduct", "data processing",
)

WEAK_AGREEMENT_WORDS = (
    "agree", "accept", "acknowledg", "consent", "legal", "read and underst",
)

MARKETING_WORDS = (
    "newsletter", "marketing", "promotion", "offers", "deals", "updates",
    "tips", "advertis", "subscribe", "third part", "special offers",
)


def classify_checkbox_label(text: str) -> str:
    """Classify a checkbox from its label text.

    Returns "agree" (required Terms/Privacy/age box to tick), "marketing"
    (optional box to leave alone), or "neutral". Strong agreement signals win
    outright; otherwise marketing wins over a bare "I agree", so a marketing
    opt-in phrased as "I agree to receive offers" is left unticked.
    """
    t = (text or "").lower()
    if any(w in t for w in STRONG_AGREEMENT_WORDS):
        return "agree"
    if any(w in t for w in MARKETING_WORDS):
        return "marketing"
    if any(w in t for w in WEAK_AGREEMENT_WORDS):
        return "agree"
    return "neutral"


async def dismiss_consent_banner(page) -> str | None:
    """Try to dismiss a consent banner in any frame of `page`.

    Returns a short description of what was clicked (e.g.
    ``"selector '.message-component button'"`` or ``"text 'Accept all'"``)
    so the caller can log it, or ``None`` if no banner was found.
    """
    for frame in page.frames:
        for sel in _CSS_SELECTORS:
            try:
                loc = frame.locator(sel).first
                if await loc.count() and await loc.is_visible():
                    await loc.click(timeout=3_000)
                    await asyncio.sleep(1)
                    return f"selector {sel!r}"
            except Exception:
                continue
        for txt in _LABEL_TEXTS:
            try:
                loc = frame.get_by_text(txt, exact=False).first
                if await loc.count() and await loc.is_visible():
                    await loc.click(timeout=3_000)
                    await asyncio.sleep(1)
                    return f"text {txt!r}"
            except Exception:
                continue
    return None
