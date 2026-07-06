# RP Audit Agent

A semi-automated toolkit for auditing relying party (RP) WebAuthn / passkey behavior.
You drive the signup and enrollment yourself; the toolkit provides two conveniences —
**Playwright** (a persistent per-RP browser) and **IMAP** (verification-code fetching) —
plus consistent record-keeping (ledger + artifacts + batch log).

Different scenarios of abnormal passkey behaviour are exercised with modified versions
of (`hook.js`) to observe several parameters.

## Overview

The workflow has three manual phases, all human-in-the-loop:

- **Signup** (`scripts/manual_signup.py`) — opens each target RP in its own persistent
  browser profile. You create the account by hand; the tool captures the resulting
  session (cookies + localStorage) to `sessions/<rp>.json` and records the outcome.
  For heavily-defended RPs whose bot-detection blocks the Playwright browser, a second
  variant (`scripts/manual_launch.py`) opens the site in a plain, un-automated Chrome
  instead — see *Signup in a real Chrome* below.
- **Enrollment / hook observation** (`src/hook/run.py`) — attaches to a long-running
  Chrome instance with `hook.js` loaded. You drive the passkey flow yourself while the
  hook fabricates the credential; the harness captures the network + hook traffic.
- **Verification codes** (`scripts/fetch_code.py`) — pulls the latest verification
  code/link for an RP straight from your IMAP inbox, so you don't have to switch to a
  mail client mid-flow.

There is no Claude/LLM automation in this toolkit — every browser action is performed
by you. The scripts only launch the browser, fetch mail, and record outcomes.

## Prerequisites

- Python 3.11+
- Google Chrome
- The `hook.js` extension source (separate repo)

Tested on Windows 11. Other platforms have not been verified.

## Setup

### 1. Virtual environment

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -e .
playwright install chromium
```

See `.gitignore` for sensitive files that shouldn't be committed.

### 3. Environment (`.env`)

IMAP settings are required (for `fetch_code`):

```
IMAP_HOST=imap.gmail.com    # optional, this is the default
IMAP_PORT=993               # optional, this is the default
IMAP_USER=you@example.com
IMAP_PASS=your-app-password
```

### 4. Identity file

Store the test identity in `identity.json` (not committed):

```json
{
  "email": "test@example.com",
  "first_name": "Test",
  "last_name": "User",
  "password": "..."
}
```

Passwords are taken from the `password` field in `identity.json`.

### 5. Hook Chrome (one-time per machine)

The hook observation harness attaches to a Chrome instance you start manually. Launch it
with a dedicated profile and remote debugging:

```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" `
  --remote-debugging-port=9222 `
  --user-data-dir="C:\chrome-hook-profile"
```

On first launch:

1. Go to `chrome://extensions`, enable Developer mode.
2. Click "Load unpacked" and select the `hook.js` extension directory.

The extension persists in the profile, so future launches don't need this step.

Keep this Chrome running in the background while you observe enrollment. The signup
browser uses its own ephemeral/persistent profiles, so there's no conflict.

## Configuration

### Targets

Specify which RPs to audit in `data/targets.csv` (output of your WebAuthn scanner):

```csv
canonical_origin,etld1,...
https://www.notion.so,notion.so,...
```

Preprocessing is the cleanup step before and after the ledger is initialized:

1. Run the CRUX sorter so the highest-priority RPs appear first.

Use the CRUX sorter from the preprocessing directory:

```powershell
cd data/preprocessing
python crux_sort.py
```

That reads `../targets.csv`, downloads or reuses the pinned CRUX snapshot, and writes
`../ledger_ranked.csv`.

If you prefer to stay at the repo root, run it with explicit paths instead:

```powershell
python data/preprocessing/crux_sort.py data/targets.csv data/ledger_ranked.csv
```

2. Initialize the ledger

Initialize the ledger from the CSV after preprocessing:

```powershell
python -m src.init targets_selected.csv
```

This populates `data/ledger.json` with one entry per RP. It does not do the login/signup
check itself; that is part of your preprocessing and discovery workflow.

If a target needs an explicit signup URL, set or override it after init:

```powershell
python -m src.set_signup notion.so https://www.notion.so/signup
```

That command updates the ledger entry and resets failed or needs-review items back to
`pending` so they can be tried again.

If you want the triage view for the raw targets, run:

```powershell
python -m src.lib.triage data/targets.csv
```

To copy the current ledger `state` and last history `note` into a selected-target
CSV, run:

```powershell
python -m src.sync_selected_status_notes data/targets_selected.csv data/targets_selected_status.csv
```

## Running

### Signup phase (manual)

Opens each RP one at a time in its per-RP browser profile. You drive the page; when
you've reached an outcome (created the account, or hit a blocker), type it in the
console. For `captured`, the session is written to `sessions/<rp>.json`.

As a convenience it runs an **assist** bundle on the page — once on landing, and
again whenever you type `fill` at the prompt (do that after navigating to the actual
signup form). Assist is all best-effort and never clicks submit:

1. dismisses a cookie/consent banner (`src/lib/consent.py`);
2. autofills the signup fields from `identity.json` (`src/lib/autofill.py`) — visible,
   empty fields only;
3. ticks required Terms/Privacy/age checkboxes, leaving marketing opt-ins alone;
4. scans for blockers (CAPTCHA, phone, geo, duplicate account) and whether you're on an
   auth surface, and hints at the likely outcome (`src/lib/page_scan.py`).

You still handle multi-step wizards, CAPTCHAs, and the final submit yourself.

At the prompt you can also type `code` to pull the RP's latest email verification code
from IMAP and type it straight into the OTP field (see *Fetching a verification code*),
without leaving the flow. Navigation and each assist step are time-bounded, so a heavy
consent wall (e.g. onet.pl) hands you control instead of freezing the run.

```powershell
# One specific RP:
python -m scripts.manual_signup --rp notion.so

# An explicit list, in order:
python -m scripts.manual_signup --rps notion.so,figma.com

# The next N pending RPs from the ledger:
python -m scripts.manual_signup --batch 10
```

Valid outcomes are defined in `src/lib/outcomes.py`:

- `captured` — account created; session saved.
- `phone-gated`, `captcha-blocked`, `geo-blocked`, `duplicate-account`,
  `requires-existing-account`, `no-portal`, `dns-dead` — blockers (no session; a
  best-effort evidence screenshot is recorded).
- `failed` — other failure.

Each run is recorded across three tiers, flagged `source=manual`: the ledger
(`data/ledger.json`), a per-run artifact (`artifacts/<rp>/<timestamp>-result.json`), and
the batch log (`data/batch_log.jsonl`).

### Signup in a real Chrome (heavily-defended RPs)

Some RPs (Discord, X, TikTok, Canva, …) fingerprint the Playwright-launched browser and
loop their CAPTCHA forever. `scripts/manual_launch.py` launches your normal system Chrome
directly — no automation switches, its own clean profile under
`browser-profiles-manual/<rp>` — so you have the best chance of getting through by hand.
Playwright is used only at the end, over CDP, to read the resulting session; it never
drives the page during signup. Outcomes are recorded exactly like `manual_signup`
(ledger + artifact + batch log), flagged `source=manual-chrome`.

```powershell
# One RP, an explicit list, the next N pending, or every RP in a blocked state:
python -m scripts.manual_launch --rp discord.com
python -m scripts.manual_launch --rps discord.com,x.com,tiktok.com
python -m scripts.manual_launch --batch 10
python -m scripts.manual_launch --state captcha-blocked
```

Chrome is auto-detected; pass `--chrome <path>` if needed. It opens one RP per window and
closes it when you move on, so finish an RP fully before pressing Enter for the next. A
clean profile is your best shot, not a guarantee — a brand-new profile with no history can
still be challenged.

### Recovering a session (no re-signup)

If an account already exists and its `browser-profiles/<rp>` profile is still logged in,
grab a fresh session without re-walking signup:

```powershell
python -m scripts.capture_session --rp notion.so
python -m scripts.capture_session --rp notion.so --set-captured   # also flip ledger
```

### Fetching a verification code (IMAP)

When an RP gates signup or enrollment behind an email code, run this in a second terminal
to pull the latest code/link from your inbox:

```powershell
python -m scripts.fetch_code --rp atlassian.com
python -m scripts.fetch_code --rp atlassian.com --newer-than 90   # after a Resend
python -m scripts.fetch_code --rp atlassian.com --timeout 180
```

Needs `IMAP_USER` / `IMAP_PASS` in `.env`. The code is read from the message **subject** as
well as the body, and MIME-encoded (non-ASCII) subjects are decoded. During a signup you
usually don't need this script — type `code` at the `manual_signup` prompt instead, which
fetches and types the code in one step.

### Enrollment / hook observation (manual)

Drive the passkey flow yourself with network + hook capture. Make sure the hook Chrome
(step 5 above) is running first.

```powershell
python -m src.hook.run --rp notion.so --enroll-url https://www.notion.so/my-account --no-localstorage
```

You drive the browser; the harness dumps captured traffic to
`artifacts/hook-runs/<rp>/<timestamp>/` when you press Enter.

`--enroll-url` is optional. Omit it when you don't know the passkey page — just run and
navigate there yourself. Capture binds to every open tab *and* to any tab/popup opened
during the run, so it follows you even when the ceremony runs on a different origin (e.g.
`accounts.meta.com` for Facebook). Keep that tab open until you press Enter.

```powershell
python -m src.hook.run --rp facebook.com --no-restore   # navigate to the passkey page by hand
```

#### Advertised-parameter capture (automatic)

On every hook run, in addition to the raw network/console dumps, the harness pulls the
hook's own **structured** event log (`window.__webauthnObserverGetLogs()`, gathered from
every frame — some RPs run WebAuthn in a same-origin iframe) and writes it to
`observer_log.json` in the run's artifact dir. The console text capture mangles the nested
option objects, so this is the reliable source for what the RP advertised in
`PublicKeyCredentialCreationOptions`.

`hook.js` also mirrors its event log to the extension's `chrome.storage.local` on every
event, so a ceremony is recovered even if the RP closes/navigates the tab that ran it (common
right after registration — e.g. Facebook's `accounts.meta.com` popup). At capture time the
harness reads that cross-origin store back through any hooked tab, and if only a blank tab is
left it briefly opens `https://example.com` to get a hook context that can read it. So you no
longer have to keep the exact ceremony tab open — but reload the extension after updating
`hook.js`/`background.js` for this to take effect.

The advertised options are then recorded **automatically**, no extra command:

- into the ledger, under `entries[<rp>]["advertised_params"]` (state-neutral — the RP's
  `state` is not changed), via `ledger.record_advertised_params`;
- into `data/targets_selected_status.csv`, upserting the row keyed by `etld1` and leaving
  every other row untouched (`src/lib/webauthn_params.py`). Two groups of columns:
  - **`adv_*` — what the RP *requested*:** `adv_rp_id`, `adv_attestation`, `adv_uv`,
    `adv_resident_key`, `adv_require_resident_key`, `adv_authenticator_attachment`, `adv_algs`,
    `adv_attestation_formats`, `adv_timeout`, `adv_captured_at`.
    `adv_rp_id` is the id the ceremony actually advertised, which can differ from your target
    label — e.g. `facebook.com` registers under `accounts.meta.com`. (The requested `hints`,
    `extensions`, and the wire-side algorithm cross-check are still stored in the ledger's
    `advertised_params`, just not projected as columns.)
  - **`fab_*` — the credential that was *selected*/returned:** `fab_alg` (e.g. `RS256(-257)`),
    `fab_alg_offered` (was that alg in the RP's `pubKeyCredParams`? `false` = a downgrade),
    `fab_flags` (the authData bits set, e.g. `UP,UV,BE,AT`), `fab_outcome`
    (`fabricated` = browser returned a credential; `create-failed:<Error>` = the browser
    rejected it).
  - **`srv_*` — what the *server* said back:** the registration finish request/response is
    located on the wire (matched by the returned credId), giving `srv_endpoint`, `srv_status`
    (HTTP status), `srv_result` (best-effort `accepted?` / `rejected` / `rejected?`), and
    `srv_message` (a snippet of the response body — the ground truth, since some RPs return
    HTTP 200 with an error body). This is how you see whether the RP actually *enforced* a
    control: a rejected finish with the reason is the enforcement signal.

  So one row tells the whole story: **advertised → selected → server verdict**. A rejected
  registration is still fully recorded.

The ledger is the source of truth; the CSV is a projection. Re-running
`python -m src.sync_selected_status_notes` reprojects the same `adv_*` columns from the
ledger for **all** RPs — use it to backfill the sheet from runs captured earlier. The
sync now preserves the status file's existing delimiter (that file is `;`-delimited), so a
resync won't reformat it.

#### Exercising the fabrication controls (hook.js)

The fabricated credential's behavior is set by constants at the top of `hook.js` (in the
`pwned-xploit` extension repo); edit them and reload the extension between scenarios:

- `SET_USER_VERIFIED` (UV, control d), `SET_BACKUP_ELIGIBLE` / `SET_BACKUP_STATE`
  (BE/BS, control e) drive the authenticator-data flags byte. Setting `SET_BACKUP_STATE`
  without `SET_BACKUP_ELIGIBLE` is spec-invalid (BS⇒BE) and logs a warning — that
  misconfiguration is itself a probe of whether the RP rejects it.
- `FABRICATION_ALG` (ES256/RS256) and the weak-RSA `RSA_PUBLIC_EXPONENT` cover the
  algorithm-downgrade (c) and bad-key-parameter (5) controls; `AAGUID` vs `fmt:"none"`
  probes attestation handling (a).

The emitted flags are logged per operation as `fabrication.flags` in the observer log.

#### Managing fabricated keys (chrome.storage)

The fabricated keypairs `hook.js` creates are persisted in the extension's
`chrome.storage.local` (under `fabricatedKeys`, keyed by rpId) so they survive reloads and
are available across origins. This store is **separate** from the audit ledger/sessions —
"Resetting a single RP" below does not touch it.

Manage them from the DevTools **Console** of any tab where the hook is installed (the
helpers live on `window` in the page's main world):

```js
// List what's stored (rpId, credId, createdAt, hasPrivateKey):
await window.__webauthnObserverDumpKeys();

// Delete ONE RP's stored key (control 3: re-register a revoked key):
await window.__webauthnObserverDeleteKey("accounts.meta.com");

// Delete ALL stored fabricated keys (all-or-nothing):
await window.__webauthnObserverClearKeys();

// The persisted event log is stored separately; clear it if it gets noisy:
await window.__webauthnObserverClearPersistedLog();
```

`__webauthnObserverDeleteKey(rpId)` removes just that RP's key from storage and the calling
tab's cache; `__webauthnObserverClearKeys()` wipes them all. Reload any other open tabs so
their in-memory caches reset too.

## Quick Start: Single-Site Test

### 1. Make sure the site is in the ledger

Check what's already there:

```powershell
python -c "from src.lib import ledger; led = ledger.load(); [print(k, v['state']) for k, v in led.get('entries', {}).items()]"
```

If your target (e.g. `notion.so`) isn't there, add it:

```powershell
python -c "from src.lib import ledger; led = ledger.load(); led.setdefault('entries', {})['notion.so'] = {'rp_id': 'notion.so', 'canonical_origin': 'https://www.notion.so/', 'signup_url': 'https://www.notion.so/signup', 'state': 'pending'}; ledger.save(led); print('added notion.so')"
```

If it's in a terminal state from a previous run, reset it:

```powershell
python -c "from src.lib import ledger; led = ledger.load(); led['entries']['notion.so']['state'] = 'pending'; ledger.save(led)"
```

### 2. Sign up

```powershell
python -m scripts.manual_signup --rp notion.so
```

When done, the ledger entry should be `captured` and `sessions/notion.so.json` should exist.

### 3. Make sure hook Chrome is running

If not already running:

```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" `
  --remote-debugging-port=9222 `
  --user-data-dir="C:\chrome-hook-profile"
```

### 4. Observe the passkey enrollment

```powershell
python -m src.hook.run --rp notion.so --enroll-url https://www.notion.so/my-account --no-localstorage
```

### Viewing results

- **Signup artifacts:** `artifacts/<rp>/<timestamp>-result.json` — outcome, note, and any
  evidence screenshot.
- **Hook-run artifacts:** `artifacts/hook-runs/<rp>/<timestamp>/` — network and console
  captures from `src.hook.run`, plus `observer_log.json` (the hook's structured event log)
  and the advertised params it yields.
- **Ledger:** `data/ledger.json` — terminal state and history per RP (plus
  `advertised_params` once a hook run has recorded them).
- **Batch log:** `data/batch_log.jsonl` — one line per recorded run.

### Resetting a single RP

```powershell
Remove-Item sessions\notion.so.json -ErrorAction SilentlyContinue
Remove-Item artifacts\notion.so -Recurse -ErrorAction SilentlyContinue
Remove-Item artifacts\hook-runs\notion.so -Recurse -ErrorAction SilentlyContinue
python -c "from src.lib import ledger; led = ledger.load(); led['entries']['notion.so']['state'] = 'pending'; ledger.save(led)"
```

Then re-run from step 2.

## Project Structure

```
src/
├── init.py                   # Ledger initialization from targets CSV
├── set_signup.py             # CLI helper to set signup_url for an entry
├── report.py                 # Summarize ledger / batch-log results
├── requeue.py                # Requeue RPs for another attempt
├── hook/                     # Manual observation harness
│   ├── run.py
│   └── __init__.py
└── lib/                      # Shared utilities
    ├── browser.py            # Playwright launch helpers (persistent per-RP profiles)
    ├── imap_poll.py          # Verification email polling (IMAP)
    ├── autofill.py           # Best-effort signup-form autofill + consent-box ticking
    ├── page_scan.py          # Read-only blocker/auth-surface scan (outcome hints)
    ├── consent.py            # Cookie/consent banner dismissal + checkbox classifier
    ├── credentials.py        # Per-RP credential derivation (from identity.json)
    ├── detect.py             # Page-state detection heuristics
    ├── idb.py                # IndexedDB / storage helpers
    ├── ledger.py             # Ledger read/write/state transitions
    ├── outcomes.py           # Valid outcome set + retry policy
    ├── parse.py              # CSV parsing
    ├── run_record.py         # Shared run-record writers (ledger/artifact/batch log)
    ├── snapshot.py           # Page snapshot helpers
    ├── dates.py              # Date parsing helpers
    ├── webauthn_params.py    # Advertised-params extract + ledger/CSV projection
    └── triage.py             # RP triage (banks, auth subdomains, etc.)

scripts/
├── manual_signup.py          # Manual signup + outcome recording (Playwright assist)
├── manual_launch.py          # Manual signup in a plain real Chrome (heavily-defended RPs)
├── capture_session.py        # Recover a session from a logged-in profile
└── fetch_code.py             # Fetch verification codes from IMAP

data/
├── targets.csv               # Input: target RPs
├── ledger.json               # Audit state (auto-generated)
└── batch_log.jsonl           # One line per recorded run

artifacts/
├── <rp>/                     # Signup outcome artifacts + screenshots
└── hook-runs/                # Manual hook harness run artifacts

sessions/                     # Captured signup sessions (cookies + localStorage)
browser-profiles/             # Persistent profile dirs for per-RP browsers (Playwright)
browser-profiles-manual/      # Clean real-Chrome profiles for manual_launch.py
```

## Data Flow

1. `data/targets.csv` → `python -m src.init` → `data/ledger.json` (one entry per RP, triaged).
2. `python -m scripts.manual_signup` → you create the account; session written to
   `sessions/<rp>.json`; ledger state → `captured` (or a blocker outcome).
3. `python -m src.hook.run` → attach to hook Chrome, restore the session, drive passkey
   creation by hand, and capture hook + network traffic under `artifacts/hook-runs/`.

## Troubleshooting

### Chrome connection issues (hook harness)

- Verify Chrome is running with `--remote-debugging-port=9222`.
- Check that port 9222 is bound: `netstat -ano | findstr :9222`.
- Confirm `hook.js` is loaded in that profile (`chrome://extensions`).

### "no extension context detected" but extension loads manually

Chrome stable (130+) disabled `--load-extension` via command line. Attach to a Chrome you
launched manually with the extension already installed — don't try to load the extension
through Playwright.

### Session restore lands on a login page

The session in `sessions/<rp>.json` has likely expired, or the account behind it was
deleted. Reset the ledger entry to `pending` and re-run signup, or use
`scripts.capture_session` if the profile is still logged in.

### Notion-style "Failed to load record" after session restore

The captured localStorage may conflict with what the RP expects after cookie restoration.
Pass `--no-localstorage` to `src.hook.run` to restore cookies only.

### IMAP fetch finds nothing

- Confirm `IMAP_USER` / `IMAP_PASS` are set in `.env` (Gmail needs an app password).
- Widen the search window with `--lookback` / `--timeout`, and use `--newer-than` after a
  Resend to skip a stale code.
- Codes are matched from both the subject and body; if the wrong number is picked up,
  forward the email body so the body patterns can be tightened.

### Signup browser hangs, or the CAPTCHA never resolves

Heavy consent walls (e.g. onet.pl) and aggressive bot-detection are expected on some RPs.
`manual_signup` bounds navigation and each assist step, so it won't freeze — it hands you
control within ~30s (you may see `⚠ … skipped; continuing` lines; that's normal). If an
RP's CAPTCHA loops forever in the Playwright browser, retry it in a real Chrome with
`scripts/manual_launch.py`, or record it as `captcha-blocked` and move on.
