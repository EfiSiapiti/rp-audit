"""Record a login click path once, for later automated replay.

You drive the login by hand ONCE; this captures your clicks, field fills, and
full-page navigations into data/paths/<rp>.json, which replay_passkey.py then
re-runs automatically (password + email OTP resolved live).

Secrets are never written to disk: password/OTP fields are classified and stored
as a field TYPE only (resolved live on replay); email likewise; other fields
keep their literal value.

Usage:
    python -m scripts.record_path --rp github.com --login-url https://github.com/login
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
from pathlib import Path

from src.lib import browser, ledger
from scripts import hook_bridge

PATHS_DIR = Path("data/paths")
DEFAULT_HOOK = "../pwned-xploit/pwned-xploit/hook.js"

# Install-and-drain, evaluated into every frame on a Python-side poll timer.
#
# We deliberately do NOT use expose_binding / add_init_script: under the
# patchright stealth driver those run in an isolated world that never reaches
# the page (verified — 0 clicks captured), which is the whole point of patchright
# (it hides exactly those automation tells from Cloudflare-class detection). But
# two page.evaluate() calls DO share a per-document world, so we install the
# capture listeners with evaluate() and read the buffer back with evaluate().
#
# This block is idempotent + self-draining: the first call in a document installs
# the listeners and seeds window.__recSteps; every call (including the first)
# returns the buffered steps and clears them. Because __recInstalled lives in the
# document, a navigation resets it and the next poll re-installs automatically.
_RECORDER_JS = r"""
(() => {
  if (window.__recInstalled) { const s = window.__recSteps || []; window.__recSteps = []; return s; }
  window.__recInstalled = true; window.__recSteps = [];
  // Reject auto-generated ids/names so we don't record selectors that change
  // every page load (Dropbox susi_email974…, React :r0:, MUI mui-123, hashes).
  function isStable(v){
    if(!v) return false;
    if(/\d{4,}/.test(v)) return false;
    if(/^:r[0-9a-z]+:$/i.test(v)) return false;         // React useId :r0:
    if(/^_+r_?\d/i.test(v)) return false;               // React useId _r_2_ (Facebook)
    if(/^«.+»$/.test(v)) return false;                  // React useId «r0»
    if(/[0-9a-f]{8,}/i.test(v)) return false;
    if(/^(mui-|radix-|headlessui-|ember|ext-gen|:r|__)/i.test(v)) return false;
    return true;
  }
  const attr = (el,a)=>{ const v=el.getAttribute(a); return v ? a+'="'+CSS.escape(v)+'"' : null; };
  function sel(el){
    if(!el || el.nodeType!==1) return null;
    const tag = el.tagName.toLowerCase();
    // 1. test hooks — the most stable thing a site can give us
    for(const a of ['data-testid','data-test-id','data-qa','data-cy','data-test']){
      const s=attr(el,a); if(s) return '['+s+']';
    }
    // 2. a NON-random id
    if(el.id && isStable(el.id)) return '#'+CSS.escape(el.id);
    // 3. a NON-random name
    const nm=el.getAttribute('name'); if(nm && isStable(nm)) return tag+'['+attr(el,'name')+']';
    // 4. inputs: autocomplete / type are stable and semantic
    if(tag==='input'){
      const ac=el.getAttribute('autocomplete'); if(ac) return 'input[autocomplete="'+CSS.escape(ac)+'"]';
      const ty=el.getAttribute('type'); if(ty && ty!=='hidden') return 'input[type="'+ty+'"]';
    }
    // 5. aria-label / placeholder
    for(const a of ['aria-label','placeholder']){ const s=attr(el,a); if(s) return tag+'['+s+']'; }
    // 6. a short text label — far more stable than a deep structural path
    //    (Facebook's buttons are attribute-less nested divs). For a CLICKABLE
    //    element, target IT via role/tag + :has-text so the click lands on the
    //    button (and its click-capturing overlay), not a deep text node inside
    //    it that sits behind that overlay. Plain text= for non-clickable labels.
    const txt = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
    if(txt && txt.length <= 40) return 'text=' + JSON.stringify(txt);
    // 7. last resort: short structural path, anchored at the nearest stable id
    let path=[], node=el;
    while(node && node.nodeType===1 && path.length<5){
      if(node.id && isStable(node.id)){ path.unshift('#'+CSS.escape(node.id)); break; }
      let s=node.tagName.toLowerCase();
      const p=node.parentElement;
      if(p){const sib=[...p.children].filter(c=>c.tagName===node.tagName);
            if(sib.length>1) s+=':nth-of-type('+(sib.indexOf(node)+1)+')';}
      path.unshift(s); node=p;
    }
    return path.join(' > ');
  }
  const FILLABLE = el => el && /^(input|textarea|select)$/i.test(el.tagName) &&
                         !/^(submit|button|checkbox|radio)$/i.test(el.type||'');
  const clickable = el => (el.closest &&
     el.closest('button,a,[role="button"],input[type="submit"],input[type="button"],[tabindex]')) || el;
  document.addEventListener('click', e => {
    try { const t = clickable(e.target);
      // Skip clicks on text fields — the fill step already targets them, and
      // recording focus-clicks just adds fragile noise.
      if(FILLABLE(t)) return;
      window.__recSteps.push({kind:'click', selector: sel(t), frame: location.href,
                         text: (t.innerText||t.value||'').trim().slice(0,40)}); } catch(_){}
  }, true);
  document.addEventListener('change', e => {
    const t = e.target; if(!t || !('value' in t)) return;
    // Skip hidden inputs (e.g. GitHub's webauthn-support/javascript-support
    // probes) — the site's own JS fills those; recording them is noise.
    if((t.type||'').toLowerCase()==='hidden') return;
    try { window.__recSteps.push({kind:'fill', selector: sel(t), frame: location.href,
      attrs:{type:t.type||'', name:t.name||'', id:t.id||'', autocomplete:t.getAttribute('autocomplete')||''},
      value: t.value||''}); } catch(_){}
  }, true);
  // OTP fields (Adobe, etc.) often auto-submit the moment the last digit lands,
  // so the `change` event above never fires and the code entry is lost — leaving
  // only the post-submit redirect chain as bare `navigate` steps. So also capture
  // on `input`, on EVERY fillable field: the per-keystroke fills give us a value
  // that lands BEFORE the auto-submit navigation tears the page down (the final
  // keystroke's binding call may race and lose, but an earlier one survives), and
  // dedupe collapses them to the last value that made it through. Secrets are
  // blanked in _normalize, so recording email/password keystrokes here is harmless.
  document.addEventListener('input', e => {
    const t = e.target; if(!t || !FILLABLE(t) || (t.type||'').toLowerCase()==='hidden') return;
    try { window.__recSteps.push({kind:'fill', selector: sel(t), frame: location.href,
      dbg:{tag:t.tagName, type:t.type||'', name:t.name||'', id:t.id||'',
           ac:t.getAttribute('autocomplete')||'', aria:t.getAttribute('aria-label')||'',
           len:(t.value||'').length},
      attrs:{type:t.type||'', name:t.name||'', id:t.id||'', autocomplete:t.getAttribute('autocomplete')||''},
      value: t.value||''}); } catch(_){}
  }, true);
})();
"""


def _classify(attrs: dict, value: str = "") -> str:
    t = (attrs.get("type") or "").lower()
    ac = (attrs.get("autocomplete") or "").lower()
    tag = f"{attrs.get('name','')} {attrs.get('id','')}".lower()
    if t == "password":
        return "password"
    if ac == "one-time-code" or re.search(r"otp|code|verif|token", tag):
        return "otp"
    # Value heuristic: a short all-digits value is almost certainly a verification
    # code (fetched live from IMAP on replay), even when the field's attributes give
    # no hint — e.g. Facebook's autocomplete="off" code input.
    if re.fullmatch(r"\d{4,8}", (value or "").strip()):
        return "otp"
    if t == "email" or ac in ("email", "username") or re.search(r"email|username|login|\buser\b", tag):
        return "email"
    return "other"


def _dedupe(steps: list[dict]) -> list[dict]:
    """Collapse consecutive duplicate steps (repeat nav to same URL, repeat
    click on same selector) that add nothing on replay."""
    out: list[dict] = []
    for s in steps:
        prev = out[-1] if out else None
        if prev and prev.get("kind") == s.get("kind"):
            if s["kind"] == "navigate" and prev.get("url") == s.get("url"):
                continue
            if s["kind"] in ("click", "fill") and prev.get("selector") == s.get("selector"):
                out[-1] = s  # keep the latest (last value wins for fills)
                continue
        out.append(s)
    return out


def _normalize(step: dict) -> dict:
    if step.get("kind") == "fill":
        field = _classify(step.get("attrs") or {}, step.get("value"))
        out = {"kind": "fill", "selector": step.get("selector"),
               "frame_url": step.get("frame"), "field": field}
        if field == "other":            # keep only non-secret literals
            out["value"] = step.get("value")
        return out
    if step.get("kind") == "click":
        return {"kind": "click", "selector": step.get("selector"),
                "frame_url": step.get("frame"), "text": step.get("text")}
    return step


async def main() -> None:
    ap = argparse.ArgumentParser(description="Record a login (or login+add-passkey) click path")
    ap.add_argument("--rp", required=True)
    ap.add_argument("--login-url", default=None,
                    help="where to start; defaults to the RP's canonical origin "
                         "(ledger.origin_for) so you can just drive to the login form yourself")
    ap.add_argument("--out", default=None)
    ap.add_argument("--hook", nargs="?", const=DEFAULT_HOOK, default=None,
                    help="inject pwned-xploit hook.js so the Add-passkey ceremony fabricates "
                         "create() in-page (no OS dialog), letting you record the full flow; "
                         f"bare --hook uses {DEFAULT_HOOK}. Omit for login-only.")
    args = ap.parse_args()

    if args.hook and not Path(args.hook).is_file():
        raise SystemExit(f"hook.js not found: {args.hook}")
    out_path = Path(args.out) if args.out else PATHS_DIR / f"{args.rp}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    steps: list[dict] = []
    page = await browser.ensure_browser_for(args.rp)  # real Chrome
    ctx = await browser.get_context()
    if args.hook:
        await hook_bridge.inject_hook(ctx, args.hook)  # hook + persistence bridge
        print(f"  injected fabrication hook + persistence bridge: {args.hook}")

    def _attach_nav(p):
        p.on("framenavigated",
             lambda fr: fr == p.main_frame and steps.append({"kind": "navigate", "url": fr.url}))
    _attach_nav(page)
    ctx.on("page", _attach_nav)

    # Capture clicks/fills by polling every frame with the install-and-drain
    # recorder (see _RECORDER_JS): the stealth driver isolates expose_binding /
    # add_init_script from the page, but repeated page.evaluate() shares a
    # per-document world, so we install the listeners and drain their buffer the
    # same way. Poll fast (the human drives slowly by hand); a click that
    # navigates within one interval still leaves its `navigate` step.
    stop = asyncio.Event()

    async def _poll_recorder() -> None:
        while not stop.is_set():
            for pg in list(ctx.pages):
                for fr in list(pg.frames):
                    try:
                        drained = await fr.evaluate(_RECORDER_JS)
                    except Exception:
                        continue  # frame navigating/detached — next tick re-installs
                    if drained:
                        steps.extend(drained)
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.15)
            except asyncio.TimeoutError:
                pass

    start_url = args.login_url or ledger.origin_for(args.rp)
    print(f"\n→ recording path for {args.rp}")
    print(f"  navigating to {start_url}" + ("" if args.login_url else "  (RP origin — drive to the login form)"))
    await page.goto(start_url, wait_until="domcontentloaded", timeout=60_000)
    poller = asyncio.create_task(_poll_recorder())

    print("  ┌" + "─" * 66 + "┐")
    if args.hook:
        print("  │  Drive the FULL lifecycle:                                      │")
        print("  │    log in → passkey settings → Add passkey (hook fabricates,    │")
        print("  │    no OS dialog) → log OUT → sign in WITH the passkey.          │")
        print("  │  Press Enter once you're logged back in (on the dashboard).     │")
    else:
        print("  │  Drive the LOGIN by hand until you are signed in.               │")
        print("  │  Every click / field / page-load is being recorded.            │")
        print("  │  Press Enter here the moment you're logged in.                 │")
    print("  └" + "─" * 66 + "┘")
    try:
        await asyncio.to_thread(input, "  > ")
    except (KeyboardInterrupt, EOFError):
        print("\n  interrupted — saving what was captured")

    # Stop polling and do one final drain so the last few steps (post the last
    # 150ms tick, before Enter) aren't lost.
    stop.set()
    try:
        await poller
    except Exception:
        pass
    for pg in list(ctx.pages):
        for fr in list(pg.frames):
            try:
                drained = await fr.evaluate(_RECORDER_JS)
            except Exception:
                continue
            if drained:
                steps.extend(drained)

    # The page's current URL is the logged-in landing — the success URL replay
    # checks it reached to decide the re-login verdict (reauth_ok).
    success_url = page.url
    # Diagnostic: show every field the `input` listener saw (tag/type/name/id/
    # autocomplete/aria/value-length), so an OTP field that didn't produce a fill
    # step can be identified. Remove once OTP capture is confirmed working.
    dbg_fills = [s["dbg"] for s in steps if s.get("kind") == "fill" and s.get("dbg")]
    if dbg_fills:
        print(f"\n  [debug] {len(dbg_fills)} raw input events on fillable fields:")
        for d in dbg_fills:
            print(f"    {d}")
    normalized = _dedupe([_normalize(s) for s in steps if s.get("kind")])
    out_path.write_text(json.dumps(
        {"rp_id": args.rp, "login_url": start_url,
         "success_url": success_url, "steps": normalized},
        indent=2), encoding="utf-8")
    n_click = sum(s["kind"] == "click" for s in normalized)
    n_fill = sum(s["kind"] == "fill" for s in normalized)
    n_nav = sum(s["kind"] == "navigate" for s in normalized)
    print(f"\n  ✓ saved {len(normalized)} steps "
          f"({n_nav} nav, {n_fill} fill, {n_click} click) → {out_path}")
    print(f"    success_url: {success_url}")
    await browser.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
