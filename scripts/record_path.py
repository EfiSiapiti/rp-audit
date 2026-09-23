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

from src.lib import browser
from scripts import hook_bridge

PATHS_DIR = Path("data/paths")
DEFAULT_HOOK = "../pwned-xploit/pwned-xploit/hook.js"

# JS injected into every frame: capture clicks + committed field values.
_RECORDER_JS = r"""
(() => {
  if (window.__recInstalled) return; window.__recInstalled = true;
  // Reject auto-generated ids/names so we don't record selectors that change
  // every page load (Dropbox susi_email974…, React :r0:, MUI mui-123, hashes).
  function isStable(v){
    if(!v) return false;
    if(/\d{4,}/.test(v)) return false;
    if(/^:r[0-9a-z]+:$/i.test(v)) return false;
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
    // 6. last resort: short structural path, anchored at the nearest stable id
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
      window.recordStep({kind:'click', selector: sel(t), frame: location.href,
                         text: (t.innerText||t.value||'').trim().slice(0,40)}); } catch(_){}
  }, true);
  document.addEventListener('change', e => {
    const t = e.target; if(!t || !('value' in t)) return;
    // Skip hidden inputs (e.g. GitHub's webauthn-support/javascript-support
    // probes) — the site's own JS fills those; recording them is noise.
    if((t.type||'').toLowerCase()==='hidden') return;
    try { window.recordStep({kind:'fill', selector: sel(t), frame: location.href,
      attrs:{type:t.type||'', name:t.name||'', id:t.id||'', autocomplete:t.getAttribute('autocomplete')||''},
      value: t.value||''}); } catch(_){}
  }, true);
})();
"""


def _classify(attrs: dict) -> str:
    t = (attrs.get("type") or "").lower()
    ac = (attrs.get("autocomplete") or "").lower()
    tag = f"{attrs.get('name','')} {attrs.get('id','')}".lower()
    if t == "password":
        return "password"
    if ac == "one-time-code" or re.search(r"otp|code|verif|token", tag):
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
        field = _classify(step.get("attrs") or {})
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
    ap.add_argument("--login-url", required=True)
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
    await ctx.expose_binding("recordStep", lambda source, data: steps.append(data))
    await ctx.add_init_script(_RECORDER_JS)

    def _attach_nav(p):
        p.on("framenavigated",
             lambda fr: fr == p.main_frame and steps.append({"kind": "navigate", "url": fr.url}))
    _attach_nav(page)
    ctx.on("page", _attach_nav)

    print(f"\n→ recording path for {args.rp}")
    print(f"  navigating to {args.login_url}")
    await page.goto(args.login_url, wait_until="domcontentloaded", timeout=60_000)

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

    # The page's current URL is the logged-in landing — the success URL replay
    # checks it reached to decide the re-login verdict (reauth_ok).
    success_url = page.url
    normalized = _dedupe([_normalize(s) for s in steps if s.get("kind")])
    out_path.write_text(json.dumps(
        {"rp_id": args.rp, "login_url": args.login_url,
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
