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
    no extension). Call once, before any RP navigation."""
    await ctx.expose_binding("__webauthnStore", _store)
    await ctx.add_init_script(BRIDGE_SHIM_JS)
    await ctx.add_init_script(Path(hook_path).read_text(encoding="utf-8"))
