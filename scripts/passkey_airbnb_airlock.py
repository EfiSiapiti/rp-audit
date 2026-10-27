"""Register a FABRICATED passkey on airbnb.com over HTTP, through its Airlock.

airbnb doesn't expose a plain WebAuthn register begin/finish pair (so the
generic replay_http.register_passkey can't drive it). Instead passkey creation
is wrapped in an Airlock flow — ACCOUNT_OWNERSHIP_VERIFICATION_FOR_PASSKEY_CREATE
— with two frictions in order: an email code, then the passkey itself. The whole
ceremony is GraphQL persisted-query mutations on an authenticated session:

    (login first — options/identify/authenticate, see scripts.login_airbnb_otp)
    POST InitiatePasskeyRegistrationViaAirlockMutation   -> 420, Airlock created,
                                                            its id in the error body
    POST EmailCodeSendCodeMutation      {airlockId}       -> mails a code
    ... wait for the email code ...
    POST EmailCodeVerifyCodeMutation    {airlockId, code} -> response's frictionData
                                                            carries the WebAuthn
                                                            challenge + expiry
    POST AirlockPasskeyRegistrationFrictionSaveMutation
         {airlockId, attestation, clientData, challengeExpiresAt}  -> account bound

The script spawns the extension's Chrome itself (the same launch recipe as
open_profile — real Chrome, pwned-xploit loaded, persistent pw-profile), so you
don't start open_profile separately. The credential is fabricated BY THE
EXTENSION, not in Python: once the Airlock hands back the WebAuthn challenge, the
script calls navigator.credentials.create() in the hooked page, so hook.js builds
the fmt:none attestation over airbnb's challenge AND persists the key to its own
chrome.storage. The script just carries that attestation to airbnb's Save
mutation over HTTP. So the extension ends up holding the credential this create
registered — ready for the in-browser authenticate step (later).

No files are written. The spawned browser is left open on success so you can see
the key in the extension; close it when done.

Templates come from the captures, newest-first per leg, because airbnb's
persisted-query hashes rotate:
  * Initiate / EmailCodeSend / EmailCodeVerify — data/http/aibnb.com.raw.json
  * Save — only ever captured in the July hook-run network.json
If a hash has since rotated airbnb answers PersistedQueryNotFound; the script
prints that verbatim so the leg can be re-captured with scripts.record_http.

Usage:
    python -m scripts.passkey_airbnb_airlock
"""
from __future__ import annotations

import json
from pathlib import Path

from curl_cffi import requests as cffi_requests

from src.lib import credentials
from scripts.login_airbnb_otp import (
    IMPERSONATE,
    RP_ID_FOR_MAIL,
    _carry_headers,
    _collect_otp,
    _new_ids,
    _raw_records,
    login,
)
from scripts.open_profile import spawn_hooked_chrome

ORIGIN = "https://www.airbnb.com"
HOOKRUN_NET = Path("artifacts/hook-runs/airbnb.com/20260709T164716Z/network.json")
PROFILE = "pw-profile"                 # the persistent profile the extension lives in


# Runs in the hooked page's MAIN world: calls create() so the EXTENSION'S hook
# fabricates the credential against airbnb's challenge (and persists the key to
# its own chrome.storage), then returns the hook's RegistrationResponseJSON.
_CREATE_JS = r"""
async ({challenge, rpId}) => {
  const toBytes = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/');
    s += '='.repeat((4 - s.length % 4) % 4);
    const bin = atob(s), a = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; };
  if (!window.__webauthnObserverInstalled) return { error: 'hook not installed on this page' };
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: toBytes(challenge),
    rp: { id: rpId, name: 'Airbnb' },
    user: { id: new Uint8Array([1, 2, 3, 4]), name: 'audit', displayName: 'audit' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  }});
  const j = cred.toJSON();
  return { id: j.id, attestation: j.response.attestationObject, clientData: j.response.clientDataJSON };
}
"""


def _fabricate_via_extension(port: int, challenge_b64url: str, rp_id: str) -> dict:
    """Drive the spawned, hooked Chrome to fabricate the credential itself: call
    navigator.credentials.create() on an airbnb page so the extension's hook
    intercepts it, builds the fmt:none attestation over airbnb's challenge, and
    persists the key to its own storage. Returns {id, attestation, clientData}
    (base64url). Raises if the browser/hook isn't reachable."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
        try:
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = next((pg for pg in ctx.pages if pg.url.startswith(ORIGIN)), None)
            if page is None:
                page = ctx.new_page()
                page.goto(ORIGIN, wait_until="domcontentloaded")
            # hook installs at document_start; reload once if it's not there yet
            if not page.evaluate("() => !!window.__webauthnObserverInstalled"):
                page.reload(wait_until="domcontentloaded")
                page.wait_for_timeout(1000)
            out = page.evaluate(_CREATE_JS, {"challenge": challenge_b64url, "rpId": rp_id})
            if out.get("error"):
                raise SystemExit(f"extension fabrication failed: {out['error']}")
            return out
        finally:
            browser.close()


def _clean_gql(op_name: str) -> dict | None:
    """The captured GraphQL request for `op_name` from the clean login trace."""
    for rec in _raw_records():
        if (rec.get("method") or "").upper() == "POST" and op_name in (rec.get("request_body") or ""):
            return rec
    return None


def _hookrun_gql(op_name: str) -> dict | None:
    """The Save mutation isn't in the clean trace — pull it from the July
    hook-run and reshape it to the clean-trace record form _post expects."""
    net = json.loads(HOOKRUN_NET.read_text(encoding="utf-8"))
    for req in net["requests"]:
        if (req.get("method") or "").upper() == "POST" and op_name in (req.get("post_data") or ""):
            return {"method": "POST", "url": req["url"],
                    "request_headers": req.get("headers") or {},
                    "request_body": req.get("post_data") or ""}
    return None


def _gql_post(client: cffi_requests.Session, rec: dict, payload_fields: dict | None) -> cffi_requests.Response:
    """POST a persisted-query mutation: keep the captured body, overwrite its
    variables.payload with `payload_fields`. No _check_challenge here — Initiate
    answers 420 with an Airlock *by design*, which that guard would misread."""
    body = json.loads(rec.get("request_body") or "{}")
    if payload_fields is not None:
        body.setdefault("variables", {}).setdefault("payload", {}).update(payload_fields)
    headers = _carry_headers(rec, _new_ids())
    return client.request("POST", rec["url"], headers=headers, data=json.dumps(body).encode())


def _gql_json(r: cffi_requests.Response) -> dict:
    try:
        return r.json()
    except ValueError:
        return {}


def _persisted_query_missing(parsed: dict) -> bool:
    errs = parsed.get("errors") or []
    return any("PersistedQueryNotFound" in str(e) for e in errs)


def _airlock_id_from_initiate(parsed: dict) -> str | None:
    """Initiate 420s and the Airlock node id lives in the error body; if it
    instead 200s (airlock already open) there's no id to read here."""
    av2 = ((parsed.get("client_error_info") or {}).get("airlockV2") or {})
    return av2.get("id")


def main() -> None:
    records = _raw_records()

    init_rec = _clean_gql("InitiatePasskeyRegistrationViaAirlockMutation")
    send_rec = _clean_gql("EmailCodeSendCodeMutation")
    verify_rec = _clean_gql("EmailCodeVerifyCodeMutation")
    save_rec = _hookrun_gql("AirlockPasskeyRegistrationFrictionSaveMutation")
    if not all((init_rec, send_rec, verify_rec, save_rec)):
        raise SystemExit("missing a passkey-ceremony template "
                         f"(init={bool(init_rec)} send={bool(send_rec)} verify={bool(verify_rec)} save={bool(save_rec)})")

    email = credentials.resolve("email", rp_id=RP_ID_FOR_MAIL)

    # Spawn the extension's Chrome ourselves (same launch recipe as open_profile),
    # so the extension is live to receive the key — no separate open_profile needed.
    print(f"== spawning the extension's Chrome ({PROFILE}) ==")
    proc, port, _cdp = spawn_hooked_chrome(PROFILE, ORIGIN)
    print(f"  up on debug port {port}")
    success = False
    try:
        _run_http_create(records, init_rec, send_rec, verify_rec, save_rec, email, port)
        success = True
    finally:
        if success:
            print("\n  browser left open so you can see the key in the extension — close it when done.")
        else:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try: proc.kill()
                except Exception: pass


def _run_http_create(records, init_rec, send_rec, verify_rec, save_rec, email, port) -> None:
    with cffi_requests.Session(impersonate=IMPERSONATE, timeout=30) as client:
        print("\n== login (to get an authenticated session) ==")
        user_id = login(client, records)
        if not user_id:
            raise SystemExit("login failed — can't register a passkey without an authenticated session")
        print(f"  logged in (userId {user_id})")
        login_otp_note = "excluding the login code so the airlock's own code is used"

        print("\n== passkey registration via Airlock ==")
        print("  POST InitiatePasskeyRegistrationViaAirlockMutation (opens the Airlock)")
        r = _gql_post(client, init_rec, None)
        parsed = _gql_json(r)
        print(f"    -> {r.status_code}")
        if _persisted_query_missing(parsed):
            raise SystemExit("Initiate: PersistedQueryNotFound — hash rotated; re-capture with record_http")
        airlock_id = _airlock_id_from_initiate(parsed)
        if not airlock_id:
            raise SystemExit(f"could not read the Airlock id from Initiate (body: {(r.text or '')[:300]!r})")
        print(f"    airlockId: {airlock_id}")

        print("  POST EmailCodeSendCodeMutation (mails the airlock code)")
        r = _gql_post(client, send_rec, {"airlockId": airlock_id})
        parsed = _gql_json(r)
        print(f"    -> {r.status_code}")
        if _persisted_query_missing(parsed):
            raise SystemExit("EmailCodeSend: PersistedQueryNotFound — hash rotated; re-capture with record_http")

        print(f"  collecting the airlock email code ({login_otp_note}) ...")
        code = _collect_otp(email)

        print("  POST EmailCodeVerifyCodeMutation (verifies the code, returns the WebAuthn challenge)")
        r = _gql_post(client, verify_rec, {"airlockId": airlock_id, "code": code})
        parsed = _gql_json(r)
        print(f"    -> {r.status_code}")
        if _persisted_query_missing(parsed):
            raise SystemExit("EmailCodeVerify: PersistedQueryNotFound — hash rotated; re-capture with record_http")
        friction = (((parsed.get("data") or {}).get("airlockEmailCodeVerificationVerifyCode") or {})
                    .get("airlock") or {}).get("viewPayload", {}).get("frictionData") or {}
        challenge = friction.get("challenge")
        expires_at = friction.get("expiresAt")
        rp_id = friction.get("rpId") or "airbnb.com"
        if not (challenge and expires_at):
            raise SystemExit(f"verify did not return a passkey challenge — friction: {friction or (r.text or '')[:300]!r}")
        print(f"    challenge: {challenge}  rpId: {rp_id}  expiresAt: {expires_at}")

        # Let the EXTENSION fabricate: call create() in the hooked page so its
        # hook builds the attestation over airbnb's challenge and stores the key.
        print("  fabricating via the extension's hook (navigator.credentials.create) ...")
        cred = _fabricate_via_extension(port, challenge, rp_id)
        attestation = cred["attestation"]
        client_data = cred["clientData"]
        print(f"    extension returned credId {cred['id']}")

        print("  POST AirlockPasskeyRegistrationFrictionSaveMutation (submits the fabricated passkey)")
        r = _gql_post(client, save_rec, {"airlockId": airlock_id, "attestation": attestation,
                                         "clientData": client_data, "challengeExpiresAt": expires_at})
        parsed = _gql_json(r)
        print(f"    -> {r.status_code}  {(r.text or '')[:400]!r}")
        if _persisted_query_missing(parsed):
            raise SystemExit("Save: PersistedQueryNotFound — hash rotated; re-capture a passkey registration with record_http")

        save = ((parsed.get("data") or {}).get("airlockPasskeyRegistrationFrictionSave") or {})
        status = (save.get("airlock") or {}).get("airlockStatus")
        errors = parsed.get("errors")
        accepted = bool(save) and not errors and status in ("SATISFIED", None)
        print(f"\n  {'PASSKEY ACCEPTED' if accepted else 'REJECTED'} "
              f"(airlockStatus={status!r}{', errors=' + str(errors) if errors else ''})")

        if accepted:
            # The extension already holds the key — its hook persisted it to
            # chrome.storage during the create() call above. Nothing to write.
            print(f"  key is in the extension (hook persisted fabricatedKeys[{rp_id}], credId {cred['id']})")


if __name__ == "__main__":
    main()
