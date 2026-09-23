# RP Audit

A toolkit for auditing relying-party (RP) WebAuthn / passkey behavior. It fabricates
passkeys with a research hook (`hook.js`, from the sibling `pwned-xploit` repo) and records
what each RP advertises and accepts. No LLM/agent automation — the scripts only launch the
browser, fetch mail, inject the hook, and record.

Two workflows:

- **Manual** — you drive signup and the passkey ceremony by hand. The hook runs as a Chrome
  extension you load, and `src/hook/run.py` observes.
- **Automated (record/replay)** — record a login (or full login→Add-passkey) once, then replay
  it unattended on **real Chrome** (anti-detection; passes bot-detection that blocks a plain
  Playwright browser). The hook is *injected* (no extension), and a persistence bridge lets a
  fabricated key survive register→authenticate.

## Setup

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e .
playwright install chromium
```

- **`.env`** — IMAP for email verification codes:
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
- **`hook.js`** — clone the sibling `pwned-xploit` repo next to this one, so the hook is at
  `../pwned-xploit/pwned-xploit/hook.js`. Used by both workflows.

## Targets & ledger

```powershell
python data/preprocessing/crux_sort.py data/targets.csv data/ledger_ranked.csv   # rank by CRUX
python -m src.init targets_selected.csv                                           # build data/ledger.json
```

## Manual workflow

Human-in-the-loop; outcomes are recorded to the ledger, `artifacts/`, and `data/batch_log.jsonl`.

```powershell
# Signup (per-RP browser; an assist autofills from identity.json but never submits)
python -m scripts.manual_signup --rp notion.so          # or --rps a,b  |  --batch 10

# Signup in a plain real Chrome (heavily-defended RPs: Discord/X/Canva…)
python -m scripts.manual_launch --rp discord.com        # or --rps  |  --batch  |  --state captcha-blocked

# Fetch an email verification code (or type `code` at the signup prompt)
python -m scripts.fetch_code --rp atlassian.com

# Enrollment / hook observation: attach to your hook Chrome, drive the passkey by hand
python -m src.hook.run --rp facebook.com --label alg-downgrade-RS256
```

**Hook Chrome (one-time):** launch Chrome with
`--remote-debugging-port=9222 --user-data-dir=C:\chrome-hook-profile`, then load the `hook.js`
directory via `chrome://extensions` (Developer mode → Load unpacked). Keep it running and logged
into the RP; `run.py` only observes.

Each hook run auto-records the RP's advertised params (`adv_*`) into the ledger +
`data/targets_selected_status.csv`, and one row per run (`fab_*` results) into
`data/experiments.csv` — `--label` names the control.

## Automated workflow (record / replay)

Recorded paths live in `data/paths/<rp>.json`. Secrets are never stored — password and email OTP
are resolved live (from `identity.json` / IMAP) on replay.

```powershell
# Login: record once (drive by hand, Enter when signed in), then replay unattended
python -m scripts.record_path   --rp github.com --login-url https://github.com/login
python -m scripts.replay_passkey --rp github.com

# Passkey fabrication: --hook injects hook.js (no extension) and persists the fabricated
# key to data/fab_keys.json so it can authenticate later. Record the FULL ceremony, then replay.
python -m scripts.record_path   --rp github.com --login-url https://github.com/login --hook
python -m scripts.replay_passkey --rp github.com --hook --label ES256
```

`replay_passkey --hook` observes the ceremony and records to the ledger + `data/experiments.csv`
(artifacts under `artifacts/passkey/<rp>/<label>/`), the same schema as `src.hook.run`.

## Structure

```
src/
  init.py, report.py
  hook/run.py            # manual hook-observation harness (attaches to extension-loaded Chrome)
  lib/
    browser.py           # real-Chrome launcher: anti-detection, ephemeral profiles
    imap_poll.py         # IMAP verification-code polling
    autofill.py consent.py page_scan.py credentials.py detect.py   # manual-signup assist
    ledger.py outcomes.py webauthn_params.py run_record.py parse.py triage.py
scripts/
  manual_signup.py       # manual signup (Playwright assist)
  manual_launch.py       # manual signup in a plain real Chrome (defended RPs)
  fetch_code.py          # IMAP code fetch
  record_path.py         # record a login / login+add-passkey click path  (--hook for the hook)
  replay_passkey.py      # replay it; --hook = register fabricated passkey + observe/record
  hook_bridge.py         # persistence backend for the injected hook (data/fab_keys.json)
data/
  targets.csv ledger.json batch_log.jsonl experiments.csv
  targets_selected_status.csv   # advertised-params (adv_*) per RP
  paths/<rp>.json               # recorded click paths
  fab_keys.json                 # fabricated private keys (gitignored)
artifacts/                      # signup outcomes, hook-runs/, passkey/
browser-profiles-manual/        # clean real-Chrome profiles for manual_launch.py
```

## Troubleshooting

- **Hook extension not detected (manual):** Chrome 137+ disabled `--load-extension` via CLI —
  attach to a Chrome you loaded the extension into by hand; don't load it through Playwright.
- **Automated replay blocked / challenged:** repeated attempts burn the egress IP's reputation
  (Cloudflare/Akamai). Switch network or wait — the browser fingerprint itself is clean.
- **`replay_passkey --hook` registers but login fails:** the fabricated key must persist —
  `hook_bridge` writes it to `data/fab_keys.json`. If that's empty, the hook logged
  `persistKey.failed` (bridge not wired).
- **IMAP finds nothing:** check `.env` creds (Gmail needs an app password); use `--newer-than`
  after a Resend to skip a stale code.
