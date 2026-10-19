"""Launch real Chrome with the fabrication hook injected, and let YOU drive.

Unlike replay_passkey (which replays a *recorded* path), this opens a hooked
browser and hands it to you: register a passkey and then sign in with it by hand,
watching the fabricated WebAuthn ceremony happen in a real browser.

The injected pwned-xploit hook.js overrides navigator.credentials.create/get;
hook_bridge persists the fabricated key to data/fab_keys.json (keyed by rpId), so
the passkey you register can authenticate later in the same — or a future — run.
A key minted over HTTP by `replay_http --register --persist-key` lands in the same
file, so you can register over HTTP and then sign in with that key here by hand.
hook.js console output and the webauthn requests print live in this terminal as
you click.

Register-over-HTTP then authenticate-in-browser (GitHub):
  1. python -m scripts.replay_http --rp github.com \
         --login-url https://github.com/login --register --persist-key
  2. python -m scripts.drive_hooked --rp github.com --url https://github.com/login
  3. click "Sign in with a passkey"  (hook loads the HTTP-minted key -> you're in)

All-in-browser alternative (register by hand too): skip step 1, and in step 2 do
Settings -> Passkeys -> Add passkey, then log out and sign in with the passkey.

Usage:
    python -m scripts.drive_hooked --rp github.com --url https://github.com/login
    python -m scripts.drive_hooked --rp github.com --url https://github.com/login --persist
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from dotenv import load_dotenv

from src.lib import browser
from src.hook import run as hookrun
from scripts import hook_bridge

DEFAULT_HOOK = "../pwned-xploit/pwned-xploit/hook.js"


def _standalone_bridge_js(keys: dict) -> str:
    """A self-contained MAIN-world bridge for hook.js's storage protocol.

    hook_bridge.inject_hook answers hook.js over a Playwright `expose_binding`
    (window.__webauthnStore) — but the anti-detection driver (patchright) HIDES
    Playwright's injected bindings, so under it __webauthnStore isn't a function
    and keyCache.load fails. This replies to the same postMessage protocol from an
    in-page copy of fab_keys.json instead, so NO Playwright binding is needed. It's
    read-mostly: `save` updates the in-page copy (e.g. signCount) but does not write
    back to disk — fine for authenticating with a key already minted over HTTP.
    """
    return (
        "(() => {"
        "  if (window.__webauthnBridgeShim) return; window.__webauthnBridgeShim = true;"
        "  let KEYS = " + json.dumps(keys) + ";"
        "  window.addEventListener('message', (event) => {"
        "    if (event.source !== window) return;"
        "    const d = event.data || {};"
        "    if (d.channel !== 'webauthn-research') return;"
        "    const { id, action, rpId, record } = d;"
        "    let response;"
        "    if (action === 'save') { if (rpId) KEYS[rpId] = record; response = { ok: true }; }"
        "    else if (action === 'loadAll') { response = { ok: true, keys: KEYS }; }"
        "    else if (action === 'delete') { const e = rpId in KEYS; delete KEYS[rpId]; response = { ok: true, existed: e }; }"
        "    else if (action === 'clearAll') { KEYS = {}; response = { ok: true }; }"
        "    else if (action === 'dump') { response = { ok: true, keys: Object.keys(KEYS).map(r => ({ rpId: r })) }; }"
        "    else { response = { ok: true }; }"  # logSave / logLoadAll / logClear → benign ok
        "    window.postMessage({ channel: 'webauthn-research-response', id, response }, '*');"
        "  });"
        "})();"
    )


async def main() -> None:
    ap = argparse.ArgumentParser(description="Drive a hook-injected real Chrome by hand")
    ap.add_argument("--rp", required=True, help="RP id, e.g. github.com")
    ap.add_argument("--url", help="page to open first (e.g. the login page)")
    ap.add_argument("--hook", nargs="?", const=DEFAULT_HOOK, default=DEFAULT_HOOK,
                    help=f"pwned-xploit hook.js to inject (default {DEFAULT_HOOK})")
    ap.add_argument("--persist", action="store_true",
                    help="reuse the prepared per-RP profile under browser-profiles-manual/<rp> "
                         "instead of a fresh throwaway profile")
    args = ap.parse_args()

    if not Path(args.hook).is_file():
        raise SystemExit(f"hook.js not found: {args.hook}")
    load_dotenv()

    print(f"\n-> drive {args.rp} in hooked real Chrome")
    page = await browser.ensure_browser_for(args.rp, persist=args.persist)
    ctx = await browser.get_context()

    # Inject a self-contained bridge (fab_keys.json baked in) + hook.js into the
    # MAIN world BEFORE any RP navigation, so create()/get() are overridden and
    # hook.js loads the persisted keys (incl. HTTP-minted ones) at startup. We do
    # NOT use hook_bridge.inject_hook here: its expose_binding is hidden by the
    # anti-detection driver (patchright), which is what broke keyCache loading.
    keys = hook_bridge._load_keys()
    await ctx.add_init_script(_standalone_bridge_js(keys))
    await ctx.add_init_script(Path(args.hook).read_text(encoding="utf-8"))
    print(f"  injected fabrication hook + in-page bridge: {args.hook}")
    print(f"  loaded {len(keys)} key(s) from {hook_bridge.FAB_KEYS_FILE}: {sorted(keys)}")
    if args.rp not in keys:
        print(f"  ! no key for {args.rp} in fab_keys.json — register first: "
              f"python -m scripts.replay_http --rp {args.rp} "
              f"--login-url https://{args.rp}/login --register --persist-key")

    captured = hookrun._new_capture()           # prints hook console + webauthn reqs live
    hookrun._attach_listeners(page, captured)
    ctx.on("page", lambda p: hookrun._attach_listeners(p, captured))

    if args.url:
        await page.goto(args.url, wait_until="domcontentloaded")

    print()
    print("  Drive it by hand in Chrome:")
    print("    if you registered the key over HTTP (--persist-key), just click")
    print("    'Sign in with a passkey' on the login page -> you're in.")
    print("    otherwise: register a passkey, then log out and sign in with it.")
    print("  hook.js fabrication + webauthn requests print here as they fire.")
    print("  Press Enter when done (the window stays open until then).")
    print()
    try:
        await asyncio.to_thread(input)
    except (KeyboardInterrupt, EOFError):
        pass
    await browser.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
