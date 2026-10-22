#!/usr/bin/env python3
"""
Just open the persistent Chrome profile (your logged-in Canva session).
No login, no requests fired. Optionally load extension(s).

    python open_profile.py --channel chrome
    python open_profile.py --url https://www.canva.com/settings/login-and-security
    python open_profile.py --extension "C:\\path\\to\\unpacked\\ext"   # repeatable
"""
import argparse, sys, datetime

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("pip install playwright && python -m playwright install chromium")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="pw-profile")
    ap.add_argument("--channel", default=None)
    ap.add_argument("--url", default="https://www.canva.com")
    ap.add_argument("--extension", action="append", default=[])
    args = ap.parse_args()

    a = ["--start-maximized"]
    if args.extension:
        joined = ",".join(args.extension)
        a += [f"--disable-extensions-except={joined}", f"--load-extension={joined}"]

    with sync_playwright() as p:
        launch = dict(headless=False, args=a)
        if args.channel:
            launch["channel"] = args.channel
        ctx = p.chromium.launch_persistent_context(args.profile, **launch)
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        page.goto(args.url)
        print(f"[{datetime.datetime.now():%H:%M:%S}] profile open at {args.url}")
        print("Browser is yours. Press Enter here (or Ctrl+C) to close it.")
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            pass
        try:
            ctx.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
