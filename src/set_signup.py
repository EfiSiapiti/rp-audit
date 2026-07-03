"""Set or override the signup URL for a ledger entry.

Usage:
    python -m src.set_signup notion.so https://www.notion.so/signup
"""

import sys
from .lib import ledger


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: python -m src.set_signup <rp_id> <signup_url>")
    rp_id, url = sys.argv[1], sys.argv[2]
    led = ledger.load()
    if rp_id not in led.get("entries", {}):
        raise SystemExit(f"unknown rp_id: {rp_id}")
    led["entries"][rp_id]["signup_url"] = url
    # Also reset to pending if it had failed
    if led["entries"][rp_id]["state"] in ("failed", "needs-review"):
        ledger.update_state(led, rp_id, "pending", note=f"signup_url set: {url}")
    else:
        ledger.save(led)
    print(f"set signup_url for {rp_id}: {url}")


if __name__ == "__main__":
    main()
