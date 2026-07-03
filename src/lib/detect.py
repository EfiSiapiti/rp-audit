"""Detect blocking conditions on a signup page.

Each detector returns (bool, evidence) so the runner can log *why* it
made a decision.
"""

from __future__ import annotations


async def detect_captcha(page) -> tuple[bool, str]:
    """Look for known CAPTCHA providers' DOM markers."""
    selectors = [
        ('iframe[src*="recaptcha"]', "reCAPTCHA"),
        ('iframe[src*="hcaptcha"]', "hCaptcha"),
        ('iframe[src*="challenges.cloudflare.com"]', "Cloudflare Turnstile"),
        ('iframe[title*="recaptcha" i]', "reCAPTCHA (by title)"),
        ('iframe[title*="hcaptcha" i]', "hCaptcha (by title)"),
        ('div.g-recaptcha', "reCAPTCHA (div)"),
        ('div.h-captcha', "hCaptcha (div)"),
        ('[data-sitekey]', "captcha sitekey present"),
        ('#cf-challenge-running', "Cloudflare challenge"),
    ]
    for sel, name in selectors:
        try:
            el = await page.query_selector(sel)
            if not el:
                continue
            # Invisible reCAPTCHA / bot-protection widgets are 0×0 px; only
            # flag ones the user actually has to interact with.
            box = await el.bounding_box()
            if box and box["width"] > 10 and box["height"] > 10:
                return True, name
        except Exception:
            pass
    return False, ""


async def detect_cloudflare_challenge(page) -> tuple[bool, str]:
    """Cloudflare bot-protection: the Turnstile widget or a managed-challenge
    interstitial ("Just a moment…" / "Checking your browser").

    These can't be solved reliably and frequently loop, so the runner treats
    them as a HARD captcha-block — abort immediately, no user-solve attempt.
    """
    # Full-page interstitial markers — always a hard block.
    interstitial_selectors = [
        "#cf-challenge-running",
        "#challenge-running",
        "#challenge-form",
        "#cf-please-wait",
    ]
    for sel in interstitial_selectors:
        try:
            if await page.query_selector(sel):
                return True, f"Cloudflare challenge ({sel})"
        except Exception:
            pass

    # Visible Turnstile widget (the click-to-verify box).
    for sel in ('iframe[src*="challenges.cloudflare.com"]', ".cf-turnstile"):
        try:
            el = await page.query_selector(sel)
            if el:
                box = await el.bounding_box()
                if box and box["width"] > 10 and box["height"] > 10:
                    return True, "Cloudflare Turnstile widget"
        except Exception:
            pass

    # Interstitial body/title text.
    hay = ""
    try:
        hay += (await page.title() or "").lower()
    except Exception:
        pass
    try:
        hay += " " + (await page.inner_text("body")).lower()
    except Exception:
        pass
    phrases = [
        "just a moment",
        "checking your browser before accessing",
        "verify you are human",
        "needs to review the security of your connection",
        "attention required! | cloudflare",
        "cf-browser-verification",
        "enable javascript and cookies to continue",
    ]
    for p in phrases:
        if p in hay:
            return True, f"Cloudflare interstitial ({p!r})"
    return False, ""


async def detect_phone_required_on_page(page) -> tuple[bool, str]:
    """Detect a required phone input field on the current page."""
    try:
        result = await page.evaluate("""
            () => {
                const isVisible = el => {
                    const r = el.getBoundingClientRect();
                    const s = window.getComputedStyle(el);
                    return r.width > 0 && r.height > 0
                        && s.display !== 'none' && s.visibility !== 'hidden';
                };
                // type=tel is also used for numeric OTP / email-verification
                // code boxes. Those are not a phone gate — exclude them.
                const isCodeField = el => {
                    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
                    const im = (el.getAttribute('inputmode') || '').toLowerCase();
                    const maxLen = parseInt(el.getAttribute('maxlength') || '0', 10);
                    const hay = [ac, el.name || '', el.id || '',
                        el.placeholder || '',
                        el.getAttribute('aria-label') || ''].join(' ').toLowerCase();
                    const phoneSignal = ac.includes('tel')
                        || /\\bphone\\b|\\bmobile\\b|\\btel\\b|\\bcell\\b|whatsapp/.test(hay);
                    return ac === 'one-time-code'
                        || /otp|code|verif|pin|token|one[\\s-]?time|passcode/.test(hay)
                        || ((im === 'numeric' || (maxLen >= 4 && maxLen <= 8)) && !phoneSignal);
                };
                const phones = Array.from(
                    document.querySelectorAll('input[type="tel"]')
                ).filter(isVisible).filter(el => !isCodeField(el));
                if (!phones.length) return null;
                const required = phones.filter(
                    el => el.required || el.getAttribute('aria-required') === 'true'
                );
                if (required.length) return 'required phone input';
                // Phone is the only non-hidden non-submit visible input
                const allInputs = Array.from(document.querySelectorAll(
                    'input:not([type="hidden"]):not([type="submit"]):not([type="button"])'
                )).filter(isVisible);
                if (allInputs.length === 1 && allInputs[0].type === 'tel'
                        && !isCodeField(allInputs[0]))
                    return 'phone is the only visible input';
                return null;
            }
        """)
        if result:
            return True, result
    except Exception:
        pass
    return False, ""


async def detect_geo_block(page) -> tuple[bool, str]:
    """Look for common geo-block / 'not available in your region' signals."""
    # HTTP 451 — explicit
    # Note: page.goto status is checked in the runner, not here.
    body_text = ""
    try:
        body_text = (await page.inner_text("body")).lower()
    except Exception:
        return False, ""

    patterns = [
        ("not available in your country", "country block message"),
        ("not available in your region", "region block message"),
        ("service not available in your", "region block message"),
        ("access denied", "access denied"),
        ("blocked in your country", "country block message"),
        ("this service is restricted", "service restricted"),
        # Cloudflare access-denied page
        ("error code: 1020", "Cloudflare 1020 (access denied)"),
    ]
    for needle, evidence in patterns:
        if needle in body_text:
            return True, evidence
    return False, ""


async def detect_already_registered(page) -> tuple[bool, str]:
    """After form submit, did the RP tell us the email is already taken?"""
    body_text = ""
    try:
        body_text = (await page.inner_text("body")).lower()
    except Exception:
        return False, ""

    patterns = [
        ("already exists", "account already exists message"),
        ("already registered", "already registered message"),
        ("already in use", "email already in use"),
        ("already taken", "email already taken"),
        ("an account with this email", "existing account message"),
    ]
    for needle, evidence in patterns:
        if needle in body_text:
            return True, evidence
    return False, ""


# Visible auth field probe. Returns 'password', 'email', or null.
_SURFACE_FIELDS_JS = r"""
() => {
    const isVisible = el => {
        const r = el.getBoundingClientRect();
        const s = window.getComputedStyle(el);
        return r.width > 0 && r.height > 0
            && s.display !== 'none' && s.visibility !== 'hidden'
            && parseFloat(s.opacity) > 0.05;
    };
    const pw = Array.from(document.querySelectorAll('input[type="password"]'))
        .filter(isVisible);
    if (pw.length) return 'password';
    const email = Array.from(document.querySelectorAll(
        'input[type="email"], input[autocomplete="email"], '
        + 'input[autocomplete="username"], input[name*="email" i]'
    )).filter(isVisible);
    if (email.length) return 'email';
    return null;
}
"""

# URL path markers that mean "we're on an auth surface". Checked against the
# *current* page URL (incl. SPA hash fragments like '#/login'), not against
# links — so a homepage that merely links to /login does not match.
_URL_MARKERS = (
    "/login", "/signin", "/sign-in", "/log-in", "/signup", "/sign-up",
    "/register", "/registration", "/oneid", "/createaccount",
    "/create-account", "/create-an-account", "/join",
)

# Words that, alongside a visible email field, corroborate an auth form.
_AUTH_CONTEXT_WORDS = (
    "password", "sign in", "log in", "sign up", "create account", "register",
)

# Form-specific phrases (not generic nav links) that imply an auth form is
# actually rendered on the page.
_FORM_PHRASES = (
    "create an account", "create your account", "forgot password",
    "forgot your password", "keep me signed in",
    "don't have an account", "already have an account",
)


async def detect_login_signup_surface(page) -> tuple[bool, str]:
    """Heuristic: is the current page a login or signup surface?

    Used by the gate-hint replay path to confirm that replaying the
    click_path actually landed on an auth entry point. Deliberately
    conservative: a bare "Log in" link in a homepage nav must NOT count —
    only an actual auth form (password/email field), an auth-path URL, or a
    clear form affordance.

    Returns (is_surface, evidence).
    """
    try:
        field = await page.evaluate(_SURFACE_FIELDS_JS)
    except Exception:
        field = None

    # A visible password field is the single strongest signal — both login
    # and signup forms have one.
    if field == "password":
        return True, "visible password field"

    try:
        url = (page.url or "").lower()
    except Exception:
        url = ""
    for marker in _URL_MARKERS:
        if marker in url:
            return True, f"url marker {marker!r}"

    body_text = ""
    try:
        body_text = (await page.inner_text("body")).lower()
    except Exception:
        body_text = ""

    # An email/username field on its own can be a newsletter box; require
    # corroborating auth context before trusting it.
    if field == "email" and any(w in body_text for w in _AUTH_CONTEXT_WORDS):
        return True, "visible email field + auth context"

    for needle in _FORM_PHRASES:
        if needle in body_text:
            return True, f"page text {needle!r}"

    return False, ""