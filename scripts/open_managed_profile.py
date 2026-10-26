"""Open the MANAGED persistent Chrome profile (browser-profiles-manual/<rp>/)
for a given RP — the one replay_http.py's browser-fetch transport and
borrow_session() reattach to. NOT the same profile as open_profile.py's
ad-hoc pw-profile dir.

No login, no requests fired — just opens the profile so you can look at or
drive it by hand. Closes (and flushes the profile to disk) when you press
Enter.

Usage:
    python -m scripts.open_managed_profile --rp canva.com
    python -m scripts.open_managed_profile --rp canva.com --url https://www.canva.com/settings/login-and-security
"""
from __future__ import annotations

import argparse
import asyncio

from src.lib import browser


async def _main(rp_id: str, url: str) -> None:
    page = await browser.ensure_browser_for(rp_id, persist=True)
    await page.goto(url, wait_until="domcontentloaded")
    print(f"profile open at {url}  (browser-profiles-manual/{rp_id})")
    print("Browser is yours. Press Enter here to close it.")
    try:
        await asyncio.get_event_loop().run_in_executor(None, input)
    except (KeyboardInterrupt, EOFError):
        pass
    await browser.shutdown()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True)
    ap.add_argument("--url", default=None, help="default: https://<rp>/")
    args = ap.parse_args()
    asyncio.run(_main(args.rp, args.url or f"https://{args.rp}/"))


if __name__ == "__main__":
    main()
