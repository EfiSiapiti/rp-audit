"""Record the confirmed WebAuthn 'finish' endpoint for an RP.

After an RP's first hook run, check its srv_endpoint in data/experiments.csv
(e.g. "/api/graphql/ (useCreatePasskeyMutation)"). If that's really the finish
call, record it here — every later run for this RP matches it directly
instead of guessing from response-body markers (see
src.lib.webauthn_params._server_verdict).

Usage:
    python -m scripts.set_known_endpoint --rp notion.so --endpoint "/api/webauthn/register"
    python -m scripts.set_known_endpoint --rp facebook.com --endpoint "/api/graphql/ (useCreatePasskeyMutation)"
"""

from __future__ import annotations

import argparse

from src.lib import ledger


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rp", required=True, help="RP id, e.g. notion.so")
    ap.add_argument("--endpoint", required=True,
                    help="exact srv_endpoint value from data/experiments.csv, "
                         "e.g. '/api/graphql/ (useCreatePasskeyMutation)'")
    args = ap.parse_args()
    ledger.set_known_endpoint(args.rp, args.endpoint)
    print(f"✓ {args.rp} → finish endpoint locked to: {args.endpoint}")


if __name__ == "__main__":
    main()
