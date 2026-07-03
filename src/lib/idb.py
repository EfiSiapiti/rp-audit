"""Capture and restore the client-side storage that `storage_state` omits.

Playwright's `storage_state` only persists cookies + localStorage, so RPs that
keep their auth token / session elsewhere come back logged-out when we restore a
captured session. Two such stores matter in practice:

- **sessionStorage** — e.g. Bitwarden's web vault keeps `token_accessToken`,
  `token_refreshToken`, and its crypto/unlock keys here.
- **IndexedDB** — other RPs persist their token/session in a database.

This module fills both gaps with symmetric in-page routines (dump + restore),
run via `page.evaluate` so they work the same whether the page belongs to a
Playwright-launched context (capture, at signup) or a CDP-attached real Chrome
with the hook.js extension (restore, in src/hook/run.py). `augment_session_file`
ties them together: call it right after `storage_state` to merge both stores
into the session JSON.

Restore note: sessionStorage and IndexedDB are both per-origin, and
sessionStorage is also per-tab — restore writes into the current tab, and the
single `page.reload()` the caller does next preserves it (same-tab navigation
keeps sessionStorage) so the app boots with the restored state.

IndexedDB-specific routines:

- `dump_indexeddb(page)`   — read every database/store/record on the page's
  current origin into a JSON-clean structure.
- `restore_indexeddb(page, dbs)` — write that structure back into IndexedDB on
  the page's current origin.

Both run via `page.evaluate`, so they work the same whether the page belongs to
a Playwright-launched context (capture, at signup) or a CDP-attached real Chrome
with the hook.js extension (restore, in src/hook/run.py). We use a custom format
(not Playwright's internal `indexed_db=True` serialization) because only the
capture side could use Playwright's restore — the CDP/extension restore path
cannot — and the two ends must share one format.

Format (per origin)::

    [
      { "name": <db>, "version": <int>,
        "stores": [
          { "name": <store>, "keyPath": <any|null>, "autoIncrement": <bool>,
            "indexes": [{"name","keyPath","unique","multiEntry"}, ...],
            "records": [{"key": <json-str, only when out-of-line>,
                         "value": <json-str>}, ...],
            "truncated": <bool>   # present when the size cap was hit
          }, ...
        ]
      }, ...
    ]

Limitations (documented on purpose):
- Record keys and values are passed through `JSON.stringify`/`JSON.parse`, so
  they must be structured-clone *and* JSON-serializable. Plain objects, strings,
  numbers, arrays, and base64 blobs (the usual shape of an encrypted token)
  round-trip fine. `Date` becomes an ISO string; `ArrayBuffer`/`Blob`/`File`
  collapse to `{}` (lossy). This is acceptable for the auth-token case.
- IndexedDB is same-origin, so only the page's *current* origin is captured.
  Multi-origin capture is out of scope for now.
"""

from __future__ import annotations

import json
from pathlib import Path

from playwright.async_api import Page


# Default per-store size cap (bytes of JSON). Keeps a large encrypted vault from
# bloating the session file; the token store is tiny and always fits.
DEFAULT_MAX_STORE_BYTES = 5 * 1024 * 1024  # 5 MB


# --- in-page routines -----------------------------------------------------

# Reads all databases on the current origin. Returns the format documented above.
# `indexedDB.databases()` is Chromium-supported; we guard everything so a single
# unreadable store/db degrades gracefully instead of throwing.
IDB_DUMP_JS = r"""
async (maxStoreBytes) => {
  const await1 = (req) => new Promise((res, rej) => {
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
  const out = [];
  if (!('indexedDB' in self) || !indexedDB.databases) return out;
  let dbInfos = [];
  try { dbInfos = await indexedDB.databases(); } catch (e) { return out; }
  for (const info of dbInfos) {
    if (!info || !info.name) continue;
    let db;
    try { db = await await1(indexedDB.open(info.name)); }
    catch (e) { continue; }
    const dbRec = { name: db.name, version: db.version, stores: [] };
    const storeNames = Array.from(db.objectStoreNames);
    for (const sName of storeNames) {
      try {
        const tx = db.transaction(sName, 'readonly');
        const store = tx.objectStore(sName);
        const sRec = {
          name: sName,
          keyPath: store.keyPath === undefined ? null : store.keyPath,
          autoIncrement: !!store.autoIncrement,
          indexes: [],
          records: [],
          truncated: false,
        };
        for (const iName of Array.from(store.indexNames)) {
          try {
            const idx = store.index(iName);
            sRec.indexes.push({
              name: iName,
              keyPath: idx.keyPath === undefined ? null : idx.keyPath,
              unique: !!idx.unique,
              multiEntry: !!idx.multiEntry,
            });
          } catch (e) {}
        }
        const outOfLine = (store.keyPath === null || store.keyPath === undefined);
        const values = await await1(store.getAll());
        const keys = outOfLine ? await await1(store.getAllKeys()) : null;
        let bytes = 0;
        for (let i = 0; i < values.length; i++) {
          let vStr, kStr;
          try { vStr = JSON.stringify(values[i]); } catch (e) { continue; }
          if (vStr === undefined) continue;
          const rec = { value: vStr };
          if (outOfLine) {
            try { kStr = JSON.stringify(keys[i]); } catch (e) { continue; }
            rec.key = kStr;
          }
          bytes += vStr.length + (kStr ? kStr.length : 0);
          if (bytes > maxStoreBytes) { sRec.truncated = true; break; }
          sRec.records.push(rec);
        }
        dbRec.stores.push(sRec);
      } catch (e) {}
    }
    try { db.close(); } catch (e) {}
    out.push(dbRec);
  }
  return out;
}
"""

# Writes the dumped structure back. Ensures each captured store exists (creating
# missing ones via a version bump in onupgradeneeded), then `put`s every record.
# Returns the number of records written.
IDB_RESTORE_JS = r"""
async (dbs) => {
  const await1 = (req) => new Promise((res, rej) => {
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
  const openWithUpgrade = (name, version, upgrade) => new Promise((res, rej) => {
    const req = version ? indexedDB.open(name, version) : indexedDB.open(name);
    req.onupgradeneeded = (ev) => { try { upgrade(req.result, ev); } catch (e) {} };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
    req.onblocked = () => {};
  });
  let written = 0;
  if (!('indexedDB' in self)) return written;
  for (const dbRec of (dbs || [])) {
    if (!dbRec || !dbRec.name) continue;
    let db;
    try { db = await openWithUpgrade(dbRec.name, null, () => {}); }
    catch (e) { continue; }
    const existing = new Set(Array.from(db.objectStoreNames));
    const missing = (dbRec.stores || []).filter(s => !existing.has(s.name));
    if (missing.length) {
      const nextV = db.version + 1;
      db.close();
      try {
        db = await openWithUpgrade(dbRec.name, nextV, (udb) => {
          for (const s of missing) {
            if (udb.objectStoreNames.contains(s.name)) continue;
            const opts = {};
            if (s.keyPath !== null && s.keyPath !== undefined) opts.keyPath = s.keyPath;
            if (s.autoIncrement) opts.autoIncrement = true;
            const os = udb.createObjectStore(s.name, opts);
            for (const idx of (s.indexes || [])) {
              try { os.createIndex(idx.name, idx.keyPath,
                                   { unique: idx.unique, multiEntry: idx.multiEntry }); }
              catch (e) {}
            }
          }
        });
      } catch (e) { try { db.close(); } catch (e2) {} continue; }
    }
    for (const s of (dbRec.stores || [])) {
      if (!db.objectStoreNames.contains(s.name)) continue;
      let tx, store;
      try { tx = db.transaction(s.name, 'readwrite'); store = tx.objectStore(s.name); }
      catch (e) { continue; }
      const outOfLine = (s.keyPath === null || s.keyPath === undefined);
      for (const rec of (s.records || [])) {
        let value, key;
        try { value = JSON.parse(rec.value); } catch (e) { continue; }
        try {
          if (outOfLine) {
            key = JSON.parse(rec.key);
            store.put(value, key);
          } else {
            store.put(value);
          }
          written++;
        } catch (e) {}
      }
      try { await new Promise((res) => { tx.oncomplete = res; tx.onerror = res; tx.onabort = res; }); }
      catch (e) {}
    }
    try { db.close(); } catch (e) {}
  }
  return written;
}
"""


# sessionStorage is a flat string key/value store, same shape as localStorage.
SESSIONSTORAGE_DUMP_JS = r"""
() => {
  const out = [];
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      out.push({ name: k, value: sessionStorage.getItem(k) });
    }
  } catch (e) {}
  return out;
}
"""

SESSIONSTORAGE_RESTORE_JS = r"""
(items) => {
  let n = 0;
  for (const it of (items || [])) {
    try { sessionStorage.setItem(it.name, it.value); n++; } catch (e) {}
  }
  return n;
}
"""


# --- async wrappers -------------------------------------------------------

async def dump_sessionstorage(page: Page) -> list[dict]:
    """Dump sessionStorage on the page's current origin. Best-effort -> []."""
    try:
        return await page.evaluate(SESSIONSTORAGE_DUMP_JS)
    except Exception:
        return []


async def restore_sessionstorage(page: Page, items: list[dict] | None) -> int:
    """Write sessionStorage items back on the current origin. Best-effort -> 0."""
    if not items:
        return 0
    try:
        return await page.evaluate(SESSIONSTORAGE_RESTORE_JS, items)
    except Exception:
        return 0


async def dump_indexeddb(page: Page, *, max_store_bytes: int = DEFAULT_MAX_STORE_BYTES) -> list[dict]:
    """Dump all IndexedDB databases on the page's current origin.

    Best-effort: returns [] on any failure rather than raising, so a capture is
    never lost to an IndexedDB hiccup.
    """
    try:
        return await page.evaluate(IDB_DUMP_JS, max_store_bytes)
    except Exception:
        return []


async def restore_indexeddb(page: Page, dbs: list[dict] | None) -> int:
    """Write `dbs` (from `dump_indexeddb`) into IndexedDB on the current origin.

    Returns the number of records written. Best-effort: returns 0 on failure.
    """
    if not dbs:
        return 0
    try:
        return await page.evaluate(IDB_RESTORE_JS, dbs)
    except Exception:
        return 0


async def augment_session_file(page: Page, session_path: str | Path) -> str:
    """Merge the current origin's sessionStorage + IndexedDB into an existing
    storage_state file, under top-level `sessionStorage` / `indexedDB` maps
    keyed by origin.

    Call this right after `context.storage_state(path=session_path)`. Additive
    and best-effort: leaves the file untouched if there's nothing extra to save
    or anything goes wrong, so a capture is never lost.

    Returns a short human summary (e.g. "sessionStorage: 26 item(s),
    IndexedDB: 0 db(s)") or "" if nothing extra was captured.
    """
    path = Path(session_path)
    try:
        origin = await page.evaluate("() => location.origin")
        session_items = await dump_sessionstorage(page)
        dbs = await dump_indexeddb(page)
        if not session_items and not dbs:
            return ""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        if not isinstance(data, dict):
            return ""
        parts = []
        if session_items:
            ss_map = data.get("sessionStorage")
            if not isinstance(ss_map, dict):
                ss_map = {}
            ss_map[origin] = session_items
            data["sessionStorage"] = ss_map
            parts.append(f"sessionStorage: {len(session_items)} item(s)")
        if dbs:
            idb_map = data.get("indexedDB")
            if not isinstance(idb_map, dict):
                idb_map = {}
            idb_map[origin] = dbs
            data["indexedDB"] = idb_map
            parts.append(f"IndexedDB: {len(dbs)} db(s)")
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return ", ".join(parts)
    except Exception:
        return ""
