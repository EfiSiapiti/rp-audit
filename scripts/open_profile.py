#!/usr/bin/env python3
"""
Open the persistent Chrome profile with the fabrication extension (pwned-xploit
hook.js) loaded, and leave it open to drive by hand. No login is attempted —
sign in yourself in the window (whichever RP you're testing). This opener is
RP-agnostic; it just hands you a hooked, persistent Chrome.

Everything runs in ONE engine: real Chrome launched as a subprocess with the
extension, attached over CDP (the src/lib/browser.py recipe). That matters for
two reasons:
  - Playwright's launch_persistent_context won't inject MV3 content scripts
    (the "loads but does nothing" symptom); the subprocess + --load-extension
    path does.
  - Developer mode (needed for the unpacked extension to run) lives in the
    profile's HMAC-signed `Secure Preferences`, which a script can't re-sign.
    Enable it ONCE by hand (chrome://extensions → Developer mode) and it
    persists — AS LONG AS the profile is only ever opened by this same real
    Chrome. Opening it with Playwright's bundled Chromium (e.g. the old
    login_canva.py) invalidates that signature and silently flips dev mode
    back off, which is why it kept "resetting". Only ever open this profile
    with this same real Chrome.

    python -m scripts.open_profile
    python -m scripts.open_profile --url https://www.canva.com/settings/login-and-security
    python -m scripts.open_profile --no-extension       # plain open, no hook
"""
import argparse, datetime, os, subprocess, sys
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("pip install playwright && python -m playwright install chromium")

from src.lib.browser import _find_chrome, _free_port, _wait_for_cdp, _merge_chrome_prefs

DEFAULT_EXTENSION = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "pwned-xploit", "pwned-xploit"))
HOOK_MARKER = "() => !!window.__webauthnObserverInstalled"

def run_hooked(profile, url, ext):
    """Real-Chrome subprocess + CDP attach on the persistent profile, extension
    loaded. Opens the page and stays open for hands-on driving. No login."""
    profile_dir = Path(profile).absolute()
    (profile_dir / "Default").mkdir(parents=True, exist_ok=True)
    # Suppress the password/autofill bubbles ONLY. Do NOT pass extension_dir:
    # that would write extensions.ui.developer_mode into plain Preferences,
    # which Chrome ignores (dev mode lives in the signed Secure Preferences)
    # and which can disturb that signed entry. Dev mode must be enabled by hand
    # once; this engine then keeps it.
    _merge_chrome_prefs(profile_dir / "Default" / "Preferences")

    chrome = _find_chrome()
    port = _free_port(9222)
    chrome_args = [chrome, f"--remote-debugging-port={port}", f"--user-data-dir={profile_dir}",
                   "--no-first-run", "--no-default-browser-check", "--new-window",
                   "--disable-features=DisableLoadExtensionCommandLineSwitch",
                   f"--load-extension={Path(ext).absolute()}", url]
    print(f"loading extension: {ext}")
    proc = subprocess.Popen(chrome_args)
    try:
        cdp = _wait_for_cdp(port)
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(cdp)
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

            try:
                page.goto(url, wait_until="domcontentloaded")
            except Exception:
                pass
            page.wait_for_timeout(1500)
            print(f"[{datetime.datetime.now():%H:%M:%S}] profile open at {url}")

            try:
                hooked = page.evaluate(HOOK_MARKER)
            except Exception:
                hooked = False
            print(f"hook active in page: {'YES (window.__webauthnObserverInstalled)' if hooked else 'NO — enable Developer mode once (chrome://extensions) and reopen'}")

            print("Browser is yours — sign in by hand if the RP needs it. Press Enter here (or Ctrl+C) to close it.")
            try:
                input()
            except (KeyboardInterrupt, EOFError):
                pass
            try:
                browser.close()
            except Exception:
                pass
    finally:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        except Exception:
            pass


def run_plain(profile, channel, url):
    with sync_playwright() as p:
        launch = dict(headless=False, args=["--start-maximized"])
        if channel:
            launch["channel"] = channel
        ctx = p.chromium.launch_persistent_context(profile, **launch)
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        page.goto(url)
        print(f"[{datetime.datetime.now():%H:%M:%S}] profile open at {url}")
        print("Browser is yours. Press Enter here (or Ctrl+C) to close it.")
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            pass
        try:
            ctx.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="pw-profile")
    ap.add_argument("--channel", default=None, help="ignored when loading an extension (always real Chrome)")
    ap.add_argument("--url", default="https://www.canva.com")
    ap.add_argument("--extension", default=None)
    ap.add_argument("--no-extension", action="store_true", help="plain open, no hook")
    args = ap.parse_args()

    ext = None
    if not args.no_extension:
        ext = args.extension or (DEFAULT_EXTENSION if os.path.isdir(DEFAULT_EXTENSION) else None)
    if ext and not os.path.isdir(ext):
        sys.exit(f"extension dir not found: {ext}")

    if ext:
        run_hooked(args.profile, args.url, ext)
    else:
        run_plain(args.profile, args.channel, args.url)


if __name__ == "__main__":
    main()
