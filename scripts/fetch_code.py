"""Fetch the latest verification code / link for an RP from the IMAP inbox.

Companion to the manual hook runs (src/hook/run.py). When an RP gates passkey
enrollment behind an email step-up (e.g. Atlassian), run this in a second
terminal to pull the code without leaving for your mail client, then type it
into the browser.

Reuses src/lib/imap_poll.find_verification — same heuristics and folder sweep
the rest of the pipeline uses. Needs IMAP_USER / IMAP_PASS in .env.

Usage:
    python -m scripts.fetch_code --rp atlassian.com
    python -m scripts.fetch_code --rp atlassian.com --newer-than 90   # after a Resend
    python -m scripts.fetch_code --rp atlassian.com --timeout 180
"""

from __future__ import annotations

import argparse

from dotenv import load_dotenv

from src.lib.imap_poll import find_verification


def main() -> int:
    load_dotenv()
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rp", required=True, help="RP id, e.g. atlassian.com")
    ap.add_argument("--timeout", type=int, default=120,
                    help="seconds to poll before giving up (default 120)")
    ap.add_argument("--newer-than", type=int, default=None,
                    help="only accept mail received within the last N seconds "
                         "(use after a Resend to skip the stale code)")
    ap.add_argument("--lookback", type=int, default=10,
                    help="how many minutes back to search (default 10)")
    args = ap.parse_args()

    print(f"→ polling IMAP for {args.rp} (timeout {args.timeout}s)…")
    found = find_verification(
        args.rp,
        timeout_seconds=args.timeout,
        newer_than_seconds=args.newer_than,
        lookback_minutes=args.lookback,
    )
    if not found:
        print("✗ no verification code/link found in the window")
        return 1

    print()
    print(f"  {found.method.upper()}:  {found.value}")
    print(f"  from:     {found.sender}")
    print(f"  subject:  {found.subject}")
    print(f"  received: {found.received_at}")
    print(f"  excerpt:  {found.raw_excerpt[:160]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
