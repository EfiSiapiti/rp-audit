#!/usr/bin/env python3
"""
Canva passkey REGISTRATION audit where the EXTENSION (pwned-xploit hook.js) is
the authenticator -- it fabricates the credential in-browser via
navigator.credentials.create() -- and the HTTP layer replays everything around
it: the renamed-ajax start, the risk-scoring step-up, and the finish POST.

So this is the browser's real authenticator surface (the hook) wired into the
captured HTTP flow, rather than the Python SoftAuthenticator minting the key.
That requires the hook to actually be loaded in the page, so we launch the
profile in real Chrome with the extension (the src/lib/browser.py subprocess +
CDP recipe, same as open_profile.py) and HARD-STOP if the hook isn't there --
nothing else can create the passkey, so there's no point burning a round.

Assumes the persistent profile is already logged in to Canva.

Chain (every HTTP leg fired in-page so it shares the real session/fingerprint,
with the live x-canva-authz sniffed off Canva's own ajax calls):

  0. launch hooked Chrome, open settings page, VERIFY the hook is installed
  1. GET  registration/start            -> fresh challenge / rp id / reg id
  2. POST requestriskscoring/assess      -> assessment id, triggers the OTP email
  3. (IMAP) read the OTP Canva mailed
  4. POST requestriskscoring/stepup/complete {A: otp, B: assessment id}
  5. navigator.credentials.create(...)   -> HOOK fabricates the credential
  6. POST registration (finish) with that credential + fresh assessment id (F.G)

Setup:
    pip install playwright imapclient python-dotenv
    # .env: IMAP_USER=<gmail>  IMAP_PASS=<app password>
Run:
    python scripts/replay_canva_webauthn.py --profile pw-profile
"""
import argparse, base64, json, os, subprocess, sys, datetime

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("pip install playwright && python -m playwright install chromium")

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.lib import imap_poll
# reuse browser.py's verified real-Chrome + extension launch recipe
from src.lib.browser import _find_chrome, _free_port, _wait_for_cdp, _merge_chrome_prefs

load_dotenv()   # IMAP_USER / IMAP_PASS for imap_poll

BASE = "https://www.canva.com"
ORIGIN = BASE
SETTINGS = f"{BASE}/settings/login-and-security"
RP_MAIL = "canva.com"
DEFAULT_EXTENSION = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "pwned-xploit", "pwned-xploit"))
HOOK_MARKER = "() => !!window.__webauthnObserverInstalled"

# headers the browser owns; fetch() forbids/overrides these, so we drop them
# (same list as login_canva.py). The fresh x-canva-authz is injected back on.
FORBIDDEN = {"host","cookie","content-length","user-agent","accept-encoding",
             "origin","referer","connection","x-canva-authz"}
def is_fwd(k): return not (k.startswith(":") or k.lower() in FORBIDDEN
                           or k.lower().startswith("sec-"))

def now(): return datetime.datetime.now().isoformat(timespec="milliseconds")

def b64url_decode(s):
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))

def load_template(records, suffix, method):
    for e in records:
        if e.get("method") == method and e["url"].split("?")[0].endswith(suffix):
            return e
    sys.exit(f"no {method} request ending {suffix!r} found in capture")

def headers_of(e, authz=None):
    h = {k: v for k, v in e["request_headers"].items() if is_fwd(k)}
    if authz:
        h["x-canva-authz"] = authz
    return h

def path_of(e):
    return e["url"][len(BASE):] if e["url"].startswith(BASE) else e["url"]

def strip_prefix(t):
    i = t.find("{")
    return t[i:] if i > 0 else t

# one in-page fetch() per HTTP leg: GET (body=None) or POST (body=str)
FETCH_JS = """async (r) => {
    const opts = {method: r.method, credentials: 'include', headers: r.headers};
    if (r.body !== null && r.body !== undefined) opts.body = r.body;
    const resp = await fetch(r.path, opts);
    const text = await resp.text();
    return {status: resp.status, body: text};
}"""

def page_fetch(page, method, path, headers, body=None):
    return page.evaluate(FETCH_JS, {"method": method, "path": path,
                                    "headers": headers, "body": body})

# ask the HOOK to fabricate the credential: call navigator.credentials.create()
# in the page (hook.js intercepts in the MAIN world) and return its toJSON().
CREATE_JS = """async (o) => {
    const pk = {
        rp: {id: o.rpId, name: o.rpName || o.rpId},
        user: {id: new Uint8Array(o.userId), name: o.userName || '', displayName: o.displayName || ''},
        challenge: new Uint8Array(o.challenge),
        pubKeyCredParams: [{type: 'public-key', alg: -7}],
        timeout: 60000,
        attestation: 'none',
    };
    const cred = await navigator.credentials.create({publicKey: pk});
    if (typeof cred.toJSON === 'function') return cred.toJSON();
    // fallback (shouldn't happen with the hook): minimal manual shape
    const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    return {id: cred.id, rawId: b64(cred.rawId), type: cred.type,
            response: {attestationObject: b64(cred.response.attestationObject),
                       clientDataJSON: b64(cred.response.clientDataJSON)},
            clientExtensionResults: {}};
}"""


def run_stepup(page, data, email, authz):
    """assess -> read the OTP Canva mails -> stepup/complete. Returns the
    assessment id the finish must carry as F.G (or None if no step-up was
    demanded)."""
    assess = load_template(data, "requestriskscoring/assess", "POST")
    complete = load_template(data, "requestriskscoring/stepup/complete", "POST")

    assess_body = (assess.get("request_body") or "").replace("{{email}}", email)
    print(f"[{now()}] POST requestriskscoring/assess (triggers the OTP email)")
    res = page_fetch(page, "POST", path_of(assess), headers_of(assess, authz), assess_body)
    print(f"   <- {res['status']}  {res['body'][:200]}")
    if res["status"] != 200:
        sys.exit("assess failed -- the stale anti-bot blob in its body may have been rejected")
    a = json.loads(strip_prefix(res["body"]))
    assessment_id = a.get("F")
    if not (a.get("G") or a.get("H")):
        print("   assess did not demand a step-up -- proceeding to finish directly")
        return assessment_id
    if a.get("H"):
        print(f"   step-up required: {a['H']}")

    print(f"[{now()}] waiting for the OTP Canva mailed to {email} ...")
    found = imap_poll.find_verification(RP_MAIL, timeout_seconds=120,
                                        prefer_code=True, newer_than_seconds=120)
    if not found or found.method != "code":
        sys.exit("no OTP code found in mail within the timeout")
    print(f"   got OTP {found.value!r} (subject: {found.subject!r})")

    body = json.dumps({"A": found.value, "B": assessment_id}, separators=(",", ":"))
    print(f"[{now()}] POST requestriskscoring/stepup/complete")
    res = page_fetch(page, "POST", path_of(complete), headers_of(complete, authz), body)
    print(f"   <- {res['status']}  {res['body'][:200]}")
    if res["status"] != 200:
        sys.exit("stepup/complete rejected the OTP")
    return assessment_id


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="data\\http\\canva.com.raw.json")
    ap.add_argument("--identity", default="identity.json")
    ap.add_argument("--profile", default="pw-profile")
    ap.add_argument("--extension", default=DEFAULT_EXTENSION)
    args = ap.parse_args()

    if not os.path.isdir(args.extension):
        sys.exit(f"extension dir not found: {args.extension}")
    data = json.load(open(args.capture, encoding="utf-8"))
    email = json.load(open(args.identity, encoding="utf-8"))["email"]
    begin = load_template(data, "webauthn/registration/start", "GET")
    finish = load_template(data, "webauthn/registration", "POST")
    finish_tmpl = json.loads(finish["request_body"])   # renamed ajax body A/B/C/D/F

    # --- launch real Chrome + extension, attach over CDP (browser.py recipe) ---
    from pathlib import Path
    profile_dir = Path(args.profile).absolute()
    (profile_dir / "Default").mkdir(parents=True, exist_ok=True)
    _merge_chrome_prefs(profile_dir / "Default" / "Preferences", extension_dir=args.extension)
    chrome = _find_chrome()
    port = _free_port(9222)
    chrome_args = [chrome, f"--remote-debugging-port={port}", f"--user-data-dir={profile_dir}",
                   "--no-first-run", "--no-default-browser-check", "--new-window",
                   "--disable-features=DisableLoadExtensionCommandLineSwitch",
                   f"--load-extension={Path(args.extension).absolute()}", SETTINGS]
    print(f"[{now()}] launching real Chrome with the hook extension")
    proc = subprocess.Popen(chrome_args)
    try:
        cdp = _wait_for_cdp(port)
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(cdp)
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

            # sniff the live per-session authz off Canva's own ajax calls
            live = {}
            def on_request(req):
                v = req.headers.get("x-canva-authz")
                if v and "authz" not in live:
                    live["authz"] = v
            page.on("request", on_request)

            print(f"[{now()}] opening {SETTINGS}")
            page.goto(SETTINGS, wait_until="domcontentloaded")
            page.wait_for_timeout(2500)

            # GUARD 0: the hook must be the authenticator; nothing else creates
            # the passkey, so stop now (before any Canva call) if it's absent.
            try:
                hooked = page.evaluate(HOOK_MARKER)
            except Exception:
                hooked = False
            print(f"   hook active in page: {'YES' if hooked else 'NO'}")
            if not hooked:
                sys.exit("extension/hook NOT loaded — it is the authenticator; aborting (close other Chrome on this profile?)")

            # GUARD 1: live authz (also implies a logged-in session)
            for _ in range(20):
                if "authz" in live:
                    break
                page.wait_for_timeout(500)
            authz = live.get("authz")
            print(f"   live x-canva-authz: {'captured' if authz else 'MISSING'}")
            if not authz:
                sys.exit("no live x-canva-authz sniffed — is the profile logged in? aborting before any costly call")

            # --- 1. START ------------------------------------------------
            print(f"[{now()}] GET registration/start")
            res = page_fetch(page, "GET", path_of(begin), headers_of(begin, authz))
            print(f"   <- {res['status']}  {res['body'][:200]}")
            if res["status"] != 200:
                sys.exit("start did not return 200 -- is the profile logged in?")
            opts = json.loads(strip_prefix(res["body"]))
            # Canva renamed options: reg id="A", user="B"{id A,name B,disp C},
            # challenge="C", rp="D"{id A,name B}.
            reg_id = opts["A"]
            user = opts.get("B") or {}
            challenge_b64 = opts["C"]
            rp = opts.get("D") or {}
            rp_id, rp_name = rp.get("A") or "www.canva.com", rp.get("B") or "Canva"
            print(f"   options: rp={rp_id}  challenge={challenge_b64[:12]}…  reg_id={reg_id}")

            # --- 2-4. risk-scoring step-up -------------------------------
            assessment_id = run_stepup(page, data, email, authz)

            # --- 5. HOOK fabricates the credential via create() ----------
            print(f"[{now()}] navigator.credentials.create() — hook fabricates")
            cred = page.evaluate(CREATE_JS, {
                "rpId": rp_id, "rpName": rp_name,
                "userId": list((user.get("A") or "").encode()),
                "userName": user.get("B") or email,
                "displayName": user.get("C") or "",
                "challenge": list(b64url_decode(challenge_b64)),
            })
            print(f"   hook returned credential id={cred['id'][:12]}…")
            shaped = {
                "id": cred["id"],
                "type": "public-key",
                "response": {
                    "attestationObject": cred["response"]["attestationObject"],
                    "clientDataJSON": cred["response"]["clientDataJSON"],
                },
                "clientExtensionResults": {},
            }

            # --- 6. FINISH ------------------------------------------------
            body = dict(finish_tmpl)
            body["B"] = reg_id
            body["C"] = json.dumps(shaped, separators=(",", ":"))
            if assessment_id and isinstance(body.get("F"), dict):
                body["F"]["G"] = assessment_id
            print(f"[{now()}] POST registration (finish)")
            res = page_fetch(page, "POST", path_of(finish), headers_of(finish, authz),
                             json.dumps(body, separators=(",", ":")))
            print(f"   <- {res['status']}  {res['body'][:300]}")

            fin_body = strip_prefix(res["body"]).strip()
            accepted = res["status"] in (200, 201) and '"error"' not in fin_body.lower()
            print("\n==================== REGISTER CHECK ====================")
            print(f"finish  -> {res['status']}  body={fin_body[:120]!r}")
            print(f"VERDICT : {'CANVA ACCEPTED THE HOOK-FABRICATED PASSKEY' if accepted else 'rejected'}")
            print("========================================================")
            json.dump({"finish_status": res["status"], "finish_body": res["body"], "accepted": accepted},
                      open("canva_webauthn_result.json", "w"), indent=2)
            print("wrote canva_webauthn_result.json")
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

if __name__ == "__main__":
    main()
