# RP Audit

A toolkit for auditing relying-party (RP) WebAuthn / passkey behavior **at the HTTP
layer**. It detects the HTTP requests that make up login and the passkey
register/authenticate ceremonies, then reproduces them over HTTP with a Python
software authenticator (a port of `hook.js` from the sibling `pwned-xploit` repo) —
no browser in the loop at replay time. A real browser is used only to *capture* a
hand-driven run, and as a login fallback for RPs that block raw-HTTP login.

Every passkey ceremony is two HTTP legs around one authenticator step:

```
begin  (server returns PublicKeyCredential{Creation,Request}Options)
  → authenticator (software: build clientDataJSON + attestation/assertion)
  → finish (client POSTs the fabricated credential; server verifies + stores)
```

The audit **detects** those legs (by body shape, RP-agnostic) and **replays** them.

## Setup

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e .
playwright install chromium        # only needed for capture + hybrid login
```

- **`.env`** — IMAP for email verification / OTP codes:
  ```
  IMAP_HOST=imap.gmail.com
  IMAP_PORT=993
  IMAP_USER=you@example.com
  IMAP_PASS=your-app-password    # Gmail: an app password
  ```
- **`identity.json`** (not committed) — the test account:
  ```json
  { "email": "test@example.com", "password": "...", "first_name": "Test", "last_name": "User" }
  ```
- **`hook.js`** — clone the sibling `pwned-xploit` repo next to this one
  (`../pwned-xploit/pwned-xploit/hook.js`). Used by the hybrid-login fallback and as
  the reference for the software authenticator; each fabrication *control* is a branch
  of that repo.

## 1. Capture / detect

Drive login + the passkey ceremony by hand **once** in real Chrome (same
anti-detection attach model as the hybrid path); every XHR/fetch/document
request+response is recorded, redacted, and classified.

```powershell
python -m scripts.record_http --rp github.com --url https://github.com/login
# --extension ../pwned-xploit/pwned-xploit   # fabricate create() via the hook instead
                                             # of a real authenticator (Windows Hello)
```

Outputs:
- `data/http/<rp>.raw.json` — the full redacted request/response log.
- `data/http/<rp>.json` — the **flow descriptor**: each request tagged
  `login` / `webauthn_register_begin` / `webauthn_register_finish` /
  `webauthn_auth_begin` / `webauthn_auth_finish`, with CSRF token location and
  login fields templated to `{{email}}` / `{{password}}`.

Secrets never touch disk: `http_flow.redact()` strips the identity password/email
(raw and percent-encoded) and all Cookie/Authorization/Set-Cookie **values** at
capture time.

## 2. Pure-HTTP replay

Reproduce the flow from the descriptor with `httpx` — no browser. Login scrapes the
live form (so per-request CSRF tokens, anti-bot timestamps, and honeypot fields come
along), fills the templated fields from the vault, and POSTs.

```powershell
# login only
python -m scripts.replay_http --rp github.com --login-url https://github.com/login

# login + passkey registration ceremony (software authenticator)
python -m scripts.replay_http --rp github.com --login-url https://github.com/login --register
```

`--register` GETs the begin page, extracts the creation options, fabricates an ES256
`fmt:"none"` credential with `src/lib/soft_authenticator.py`, and POSTs the finish
payload (multipart for GitHub, JSON for JSON-native RPs).

## 3. Hybrid fallback (browser login → HTTP ceremony)

Some RPs can't be logged into over raw HTTP — e.g. Dropbox client-side-encrypts the
password (`encrypted_password`) and gates login behind Arkose. For those, log in with
real Chrome (record once, replay unattended), then hand the session to the HTTP
ceremony.

```powershell
python -m scripts.record_path    --rp dropbox.com --login-url https://www.dropbox.com/login
python -m scripts.replay_passkey --rp dropbox.com --hook --label ES256
```

`replay_passkey --hook` injects `hook.js` (no extension), fabricates the passkey
in-page, and records to the ledger + `data/experiments.csv`; `hook_bridge.py` persists
the fabricated key (`data/fab_keys.json`) so register→authenticate survives.

## Software authenticator

`src/lib/soft_authenticator.py` is the Python port of `hook.js`: it builds the exact
`clientDataJSON` / `attestationObject` / assertion the browser would have POSTed.
Current baseline is **ES256 `fmt:"none"`**. The fabrication controls (RS256 downgrade,
weak RSA `e=3`/small `n`, leaked key, weak ECDSA scalar) live on `pwned-xploit`
branches and are ported here as authenticator variants.

## Targets & ledger

```powershell
python data/preprocessing/crux_sort.py data/targets.csv data/ledger_ranked.csv   # rank by CRUX
```

Advertised params (`adv_*`) per RP land in `data/targets_selected_status.csv`; one
row per fabrication run (`adv_*` context + `fab_*` result + `srv_*` verdict, named by
`--label`) is appended to `data/experiments.csv`.

## Structure

```
src/
  hook/run.py            # hybrid-path hook-observation harness
  lib/
    http_flow.py         # classify captured requests (login / webauthn *) — RP-agnostic
    soft_authenticator.py# Python WebAuthn authenticator (ES256 fmt:none; port of hook.js)
    browser.py           # real-Chrome launcher: anti-detection, ephemeral profiles
    credentials.py       # identity vault (secrets resolved live, never in output)
    imap_poll.py         # IMAP verification / OTP polling
    ledger.py webauthn_params.py parse.py   # audit results schema (adv_*/fab_*/srv_*)
scripts/
  record_http.py         # capture + classify a hand-driven run  → data/http/<rp>.json
  replay_http.py         # pure-HTTP replay: login, --register ceremony
  record_path.py         # hybrid: record a browser login click path
  replay_passkey.py      # hybrid: replay it; --hook = fabricate + observe/record
  hook_bridge.py         # persistence backend for the injected hook (data/fab_keys.json)
data/
  http/<rp>.json         # HTTP flow descriptors (+ .raw.json capture logs)
  paths/<rp>.json        # recorded browser click paths (hybrid path)
  targets*.csv ledger.json experiments.csv batch_log.jsonl
  fab_keys.json          # fabricated private keys (gitignored)
```

## Troubleshooting

- **Pure-HTTP login blocked / challenged:** the RP gates login behind client-side
  crypto or bot-detection (Arkose/Cloudflare). Use the hybrid fallback (§3).
- **`--register` can't find `pubKeyCredParams`:** the begin page redirected to a
  re-auth ("sudo") gate — a password re-confirm is needed before add-passkey.
- **Capture misses the finish request:** complete the ceremony with a real
  authenticator (Windows Hello) or `--extension`; the finish only fires once the
  browser API resolves.
- **IMAP finds nothing:** check `.env` creds (Gmail needs an app password).
