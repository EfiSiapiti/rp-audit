# RP Audit

A toolkit for auditing relying-party (RP) WebAuthn / passkey behavior **at the HTTP
layer**. The core workflow is manual-drive-once, capture-everything: you log in and
run the passkey ceremony by hand in a real, undetected Chrome; every XHR/fetch/
document request+response is recorded, redacted, and kept as the RP's HTTP log for
later analysis and for login replay.

Every passkey ceremony is two HTTP legs around one authenticator step:

```
begin  (server returns PublicKeyCredential{Creation,Request}Options)
  → authenticator (build clientDataJSON + attestation/assertion)
  → finish (client POSTs the credential; server verifies + stores)
```

`src/lib/http_flow.py` classifies those legs from a raw capture (RP-agnostic, by
body shape) into a flow descriptor; `src/lib/soft_authenticator.py` is a Python
WebAuthn authenticator (ES256 `fmt:"none"`, port of the sibling `pwned-xploit`
repo's `hook.js`) for RPs where the ceremony is replayed/fabricated rather than
driven with a real authenticator.

## Why a real, attached Chrome

Cloudflare-class bot management (Canva's login, for one) fingerprints *how* the
browser was started, not just `navigator.webdriver`. `launch_persistent_context`
injects ~40 default Chromium flags and keeps an active CDP instrumentation session
running, and that combination gets 403'd even with `navigator.webdriver` forced
false. `src/lib/browser.py` instead spawns a plain real Chrome as its own
subprocess with a minimal, benign flag set and *attaches* to it over CDP
(`connect_over_cdp`) — the running process is indistinguishable from a
hand-started Chrome. It prefers **patchright** (a patched Playwright that avoids
the `Runtime.enable` leak and hides Playwright's injected bindings) and falls back
to stock Playwright if patchright isn't installed.

Two profile modes:
- **ephemeral** (default) — a fresh temp profile per run, deleted on shutdown;
  every capture starts as a first-time visitor.
- **persistent** (`--persist` / `persist=True`) — a kept profile under
  `browser-profiles-manual/<rp>/` that you log into by hand once; later runs
  reattach already-authenticated. Used by `manual_signup.py` and
  `record_http.py --persist`.

### Profile reputation, not IP

Cloudflare/DataDome score several independent layers — TLS fingerprint
(JA3/JA4), HTTP/2 fingerprint (frame/header order), a JS challenge
(canvas/WebGL/fonts/timing, automation flags), and behavioral scoring (request
cadence, mouse/scroll, IP reputation). It's tempting to blame a flagged run on
the IP, but in practice (confirmed on Canva) the **same IP** passes fine in an
everyday, hand-used Chrome at the same time a run through this toolkit's
dedicated/automated profile gets challenged. So here the culprit is the
*profile*, not the network path: a profile that's only ever been driven by
Playwright/patchright, or that's already picked up a `cf_clearance`/`__cf_bm`
pair from an earlier challenged run, carries that history into every later
run — it's not a first-time-visitor problem (ephemeral profiles already start
clean) so much as a profile that's accumulated the *wrong* signal.

If a run gets flagged: don't reach for a proxy or a different IP first — try a
fresh profile (`--profile`/a new `browser-profiles-manual/<rp>/` dir), or drive
that same RP once by hand in your own everyday Chrome and reuse *its* profile
dir if the tooling allows it, before concluding the RP itself blocks
automation.

## Setup

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e .
playwright install chromium    # stock fallback driver
pip install patchright         # preferred driver; no browser download needed —
                                # it attaches to your own real Chrome over CDP
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
  (`../pwned-xploit/pwned-xploit/hook.js`). Reference for the software
  authenticator (`src/lib/soft_authenticator.py`); each fabrication *control*
  (RS256 downgrade, weak RSA, leaked key, weak ECDSA scalar) is a branch of
  that repo, ported here as an authenticator variant.

## 1. Manual signup (new RPs)

Before an RP can be captured it needs an account. `manual_signup.py` opens each
RP in its own persistent profile, you drive the signup by hand, and it records the
outcome to `data/ledger.json`:

```powershell
python -m scripts.manual_signup --rp bird.com
python -m scripts.manual_signup --rps hubdrive.space,blenderartists.org
```

An RP not yet in the ledger is added first, using `data/ledger_fidentikit.json`
(the HTTP-probe screening pass) for its signup URL. Outcomes: `captured`,
`captcha-blocked`, `phone-gated`, `geo-blocked`, `duplicate-account`,
`requires-existing-account`, `no-portal`, `dns-dead`, `failed`. The persistent
profile this leaves behind is what `record_http --persist` reattaches to.

## 2. Capture

Drive login + the passkey ceremony by hand **once**; every XHR/fetch/document
request+response is recorded and redacted.

```powershell
python -m scripts.record_http --rp github.com --url https://github.com/login
# --persist: reattach the browser-profiles-manual/<rp>/ profile from manual_signup
#            instead of a fresh throwaway one, e.g. for an RP already logged in:
python -m scripts.record_http --rp canva.com --persist --url https://www.canva.com/settings/login-and-security
```

Output: `data/http/<rp>.raw.json` — the full redacted request/response log.
Secrets never touch disk: `http_flow.redact()` strips the identity
password/email (raw and percent-encoded) and all Cookie/Authorization/Set-Cookie
**values** at capture time.

To capture many RPs in one sitting, `record_http_batch.py` walks the ledger's
`captured` entries that have no raw log yet (Enter to start each, `s` to skip,
`q` to quit):

```powershell
python -m scripts.record_http_batch --list                   # show the queue only
python -m scripts.record_http_batch                          # everything queued
python -m scripts.record_http_batch --rps bird.com,groups.io  # explicit list
python -m scripts.record_http_batch --redo --rps github.com  # re-record one already done
```

`open_profile.py` just opens the persistent Chrome profile (a logged-in RP
session) with no requests fired — useful to refresh a stale session, or to load
an unpacked extension into the profile by hand before a capture:

```powershell
python -m scripts.open_profile --url https://www.canva.com/settings/login-and-security
python -m scripts.open_profile --extension "C:\path\to\unpacked\ext"
```

## 3. Clean + classify

Review the raw log by hand and trim it to the requests that make up the flow
(drop telemetry/analytics/static-asset noise, CAPTCHA/bot-detection beacons,
unrelated dashboard calls). Then build the flow descriptor from the cleaned log:

```python
import json
from src.lib import http_flow, credentials

records = json.load(open("data/http/<rp>.raw.json", encoding="utf-8"))
descriptor = http_flow.build_descriptor(records, "<rp>", credentials.load_identity())
json.dump(descriptor, open("data/http/<rp>.json", "w", encoding="utf-8"), indent=2)
```

`data/http/<rp>.json` is the **flow descriptor**: each request tagged
`login` / `webauthn_register_begin` / `webauthn_register_finish` /
`webauthn_auth_begin` / `webauthn_auth_finish`, with CSRF token location and
login fields templated to `{{email}}` / `{{password}}`.

## 4. Login replay through the browser's own fetch (Cloudflare-class RPs)

For RPs whose login is gated behind a JS-engine/TLS fingerprint check
(Cloudflare `__cf_bm`/`cf_clearance`, e.g. Canva), raw-HTTP replay never clears
the challenge no matter how faithfully the request is rebuilt — the check runs
*in the browser*. `login_fetch.py` instead replays the captured login request
templates by issuing them with `fetch()` **inside a real Chrome page**
(`page.evaluate`), so each request carries the real browser's TLS fingerprint
and cookies while still needing no UI automation or selectors:

```powershell
python login_fetch.py --channel chrome --profile pw-profile
python login_fetch.py --capture canva_capture.json --identity identity.json
```

Method: open the RP's origin in a real/persistent Chrome profile so it gets its
anti-bot cookies and the real JS-engine fingerprint; pull the auth-request
templates (`user-authentication-methods`, `/login2`) from the capture; substitute
`{{email}}`/`{{password}}` from `identity.json`; fire them with in-page `fetch()`
(`credentials: 'include'`); verify with `session/validate`. Result is written to
`login_fetch_result.json`.

## Software authenticator

`src/lib/soft_authenticator.py` is the Python port of `hook.js`: it builds the
exact `clientDataJSON` / `attestationObject` / assertion a real authenticator
would have produced, for RPs where the register/authenticate *finish* leg is
reproduced from a flow descriptor rather than driven live. Current baseline is
**ES256 `fmt:"none"`**. The fabrication controls (RS256 downgrade, weak RSA
`e=3`/small `n`, leaked key, weak ECDSA scalar) live on `pwned-xploit` branches
and are ported here as authenticator variants.

`src/hook/run.py` is a separate, lighter-weight path: it attaches over CDP to a
Chrome you already have running (with `hook.js` loaded as an unpacked extension)
and just captures network/console traffic while you drive the ceremony by hand —
no profile management, no relaunch, for a one-off observation run.

## Targets & ledger

```powershell
python data/preprocessing/crux_sort.py data/targets.csv data/ledger_ranked.csv   # rank by CRUX
```

`data/ledger_fidentikit.json` is the HTTP-probe screening pass (canonical origin,
signup URL) used to seed new ledger entries. `data/ledger.json` tracks one entry
per RP (`state`, `attempts`, `history`) through signup → capture → classification.
Advertised params (`adv_*`) per RP land in `data/targets_selected_status.csv`; one
row per fabrication run (`adv_*` context + `fab_*` result + `srv_*` verdict, named
by `--label`) is appended to `data/experiments.csv`.

## Structure

```
src/
  hook/run.py            # CDP-attach to an already-running Chrome; capture-only observation run
  lib/
    http_flow.py         # classify captured requests (login / webauthn *) — RP-agnostic
    soft_authenticator.py# Python WebAuthn authenticator (ES256 fmt:none; port of hook.js)
    browser.py           # real-Chrome launcher: spawn + CDP-attach, ephemeral/persistent profiles
    credentials.py       # identity vault (secrets resolved live, never in output)
    imap_poll.py          # IMAP verification / OTP polling
    ledger.py webauthn_params.py parse.py   # audit results schema (adv_*/fab_*/srv_*)
scripts/
  manual_signup.py       # drive signup by hand per RP; record outcome → data/ledger.json
  record_http.py         # capture a hand-driven login + passkey run → data/http/<rp>.raw.json
  record_http_batch.py   # run record_http over many ledger RPs, one after another
  open_profile.py        # just open the persistent Chrome profile (no requests fired)
  login_fetch.py         # replay captured login requests via in-page fetch() (Cloudflare-class RPs)
data/
  http/<rp>.raw.json     # redacted capture logs; <rp>.json = classified flow descriptors
  ledger.json ledger_fidentikit.json targets*.csv experiments.csv batch_log.jsonl
  fab_keys.json          # fabricated private keys (gitignored)
browser-profiles-manual/<rp>/   # kept per-RP Chrome profile (gitignored)
```

## Troubleshooting

- **Login blocked / challenged over raw HTTP:** the RP gates login behind a
  JS-engine/TLS fingerprint check (Cloudflare) rather than a server-side
  comparison — raw `httpx` can't clear it no matter how the request is rebuilt.
  Use the in-page `fetch()` replay (§4) instead.
- **Capture misses the finish request:** complete the ceremony with a real
  authenticator (Windows Hello); the finish only fires once the browser API
  resolves.
- **`manual_signup` / `record_http --persist` lands on a stale/logged-out
  page:** the kept profile's session expired; use `open_profile.py` to refresh
  it by hand before capturing again.
- **Flagged/challenged even with a correct browser fingerprint (CDP-attach +
  patchright, no automation tells), while an everyday Chrome on the same IP is
  fine:** the IP isn't the problem — it's the profile (see "Profile
  reputation, not IP" above). Try a fresh profile dir before anything else.
- **IMAP finds nothing:** check `.env` creds (Gmail needs an app password).
