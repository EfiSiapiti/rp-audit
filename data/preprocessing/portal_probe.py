#!/usr/bin/env python3
"""
portal_probe.py — deterministic login gate.
Handles multi-hop menus (e.g. click account icon -> flyout -> click "Log in").

Usage:  python portal_probe.py bmw.com [--headed]
"""
import sys, json, re, argparse
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone
from playwright.sync_api import sync_playwright

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
TEXT  = re.compile(r"\b(log\s?in|sign\s?in|sign\s?up|register|create (an )?account|my account|join|anmelden)\b", re.I)
LOGIN = re.compile(r"\b(log\s?in|sign\s?in|anmelden|connexion)\b", re.I)   # for the 2nd hop (login only)
HREF  = re.compile(r"\b(login|log-in|signin|sign-in|signup|sign-up|register|account|auth|oneid|sso)\b|/my[-./]", re.I)
ARIA  = re.compile(r"(log\s?in|sign\s?in|account|my ?bmw|profile|user|person|register|anmelden)", re.I)
ICON  = re.compile(r"(account|user|profile|person|login|signin)", re.I)
ACCEPT= re.compile(r"\b(accept all|accept|agree|i agree|allow all|alle akzeptieren|akzeptieren|zustimmen)\b", re.I)
LOGINPAGE = re.compile(r"(log\s?in|sign\s?in|anmelden|bmw id)", re.I)
BLOCK = re.compile(r"(just a moment|verify you are human|checking your browser|unusual traffic|access denied|are you a robot)", re.I)

VERSION = "2026-06-03h"   # bump on every change; printed at run start
QUIET = False
STEALTH_JS = """
Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});
Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});
window.chrome = window.chrome || {runtime:{}};
const _q = window.navigator.permissions && window.navigator.permissions.query;
if(_q){window.navigator.permissions.query=(p)=>(p&&p.name==='notifications')?Promise.resolve({state:Notification.permission}):_q(p);}
"""
def log(*a):
    if not QUIET: print("   ", *a)

def describe(page, tag):
    """dump main-frame inputs, modal presence, and iframe inputs."""
    try: ins = page.eval_on_selector_all("input", "els=>els.map(e=>e.type||'text').slice(0,10)")
    except Exception: ins = []
    dlg = False
    for sel in ["[role=dialog]", "[aria-modal=true]", ".modal", "[class*=login i]"]:
        try:
            e = page.query_selector(sel)
            if e and e.is_visible(): dlg = True; break
        except Exception: pass
    frames = []
    for fr in page.frames[1:]:
        try: fi = fr.eval_on_selector_all("input", "els=>els.map(e=>e.type||'text').slice(0,6)")
        except Exception: fi = []
        frames.append((fr.url[:45], fi))
    log(f"[{tag}] main_inputs={ins} modal={dlg} iframes={frames}")

def dismiss_consent(page):
    for sel in ["#onetrust-accept-btn-handler", "#accept-recommended-btn-handler",
                "[aria-label*='accept' i]", ".fc-cta-consent", "button[mode='primary']"]:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                el.click(timeout=1500); page.wait_for_timeout(400); return
        except Exception: pass
    for fr in page.frames:
        try:
            for b in fr.query_selector_all("button, a, [role=button]"):
                if ACCEPT.search((b.inner_text() or "")[:40]):
                    b.click(timeout=1500); page.wait_for_timeout(400); return
        except Exception: pass

def has_login(page):
    # identifier fields: email / phone / user / generic text (phone covers phone-gated logins)
    INPUT = ("input[type=email], input[type=tel], input[type=number], input[type=text], "
             "input[name*=user i], input[name*=email i], input[id*=email i], "
             "input[name*=phone i], input[name*=mobile i], "
             "input[placeholder*=mobile i], input[placeholder*=phone i], input[placeholder*=email i]")
    try:
        for fr in page.frames:
            try:
                if fr.query_selector("input[type=password]"): return True, "password_field"
            except Exception: pass
        # a visible modal/dialog holding an identifier field == a login surface
        modal_open = False
        for sel in ["[role=dialog]", "[aria-modal=true]", ".modal", "[class*=login i]"]:
            try:
                m = page.query_selector(sel)
                if m and m.is_visible():
                    modal_open = True
                    if m.query_selector(INPUT): return True, "modal_input"
            except Exception: pass
        # modal open + an iframe carrying identifier inputs == embedded auth widget (e.g. Salla SSO)
        if modal_open:
            for fr in page.frames[1:]:
                try:
                    if fr.query_selector(INPUT) or fr.query_selector("input[type=password]"):
                        return True, "modal_iframe_input"
                except Exception: pass
        has_input = False
        for fr in page.frames:
            try:
                if fr.query_selector(INPUT): has_input = True; break
            except Exception: pass
        url = page.url.lower()
        if has_input and HREF.search(url): return True, "auth_url+input"
        if has_input and LOGINPAGE.search((page.inner_text("body") or "")[:4000]):
            return True, "login_heading+input"
    except Exception: pass
    return False, None

def collect(page):
    out, seen = [], set()
    try: els = page.query_selector_all("a, button, [role=button]")
    except Exception: els = []
    for e in els:
        try:
            txt = (e.inner_text() or "").strip()
            href = e.get_attribute("href") or ""
            aria = ((e.get_attribute("aria-label") or "")+" "+(e.get_attribute("title") or "")).strip()
            cls  = e.get_attribute("class") or ""
            # treat a <button> wrapping <i data-icon=person/user/account> as an account opener
            icon = ""
            ic = e.query_selector("[data-icon]")
            if ic: icon = ic.get_attribute("data-icon") or ""
            s = 0
            if TEXT.search(txt): s += 3
            if href and HREF.search(href): s += 2
            if ARIA.search(aria): s += 3
            if ICON.search(cls) or ICON.search(icon): s += 2 if not txt else 1
            if not s: continue
            absu = urljoin(page.url, href) if href and not href.startswith("javascript") else ""
            opener = bool(ARIA.search(aria) or ICON.search(cls) or ICON.search(icon)
                          or re.search(r"\b(account|my account|log\s?in)\b", txt, re.I))
            key = (txt[:30], absu, aria[:30])
            if key in seen: continue
            seen.add(key)
            out.append({"score": s, "text": txt[:30], "href": absu,
                        "aria": aria[:30], "icon": icon, "is_button": not absu, "opener": opener})
        except Exception: pass
    out.sort(key=lambda d: -d["score"])
    return out

def find_and_click(page, predicate):
    """click first visible a/button matching predicate(text,href,aria).
    returns a descriptor dict {action,by,value,href} or None."""
    for e in page.query_selector_all("a, button, [role=button]"):
        try:
            if not e.is_visible(): continue
            txt = (e.inner_text() or "").strip()
            href = e.get_attribute("href") or ""
            aria = ((e.get_attribute("aria-label") or "")+" "+(e.get_attribute("title") or "")).strip()
            if predicate(txt, href, aria):
                if href and not href.startswith("javascript"):
                    page.goto(urljoin(page.url, href), wait_until="domcontentloaded", timeout=15000)
                    return {"action":"goto","by":"href","value":urljoin(page.url,href),"label":txt[:40] or aria[:40]}
                else:
                    e.click(timeout=3000)
                    by = "aria" if aria else "text"
                    return {"action":"click","by":by,"value":(aria or txt)[:40]}
        except Exception: pass
    return None

def hop_to_login(ctx, page, url, cand):
    """reset home, click candidate; if menu opened (no login, no nav) click Log in inside it."""
    page.goto(url, wait_until="domcontentloaded", timeout=15000); dismiss_consent(page)
    before = page.url
    popup = {}
    ctx.on("page", lambda p: popup.setdefault("p", p))
    # hop 1: click the opener (match on its text or aria, located fresh)
    path = []
    d1 = find_and_click(page, lambda t,h,a: (cand["text"] and t[:30]==cand["text"]) or (cand["aria"] and a[:30]==cand["aria"]))
    if d1: path.append(d1)
    page.wait_for_timeout(1600)
    tgt = popup.get("p") or page
    try: tgt.wait_for_load_state("domcontentloaded", timeout=6000)
    except Exception: pass
    dismiss_consent(tgt)
    try: tgt.wait_for_selector("input, [role=dialog], .modal", timeout=2500)
    except Exception: pass
    describe(tgt, "hop1-dom")
    ok, why = has_login(tgt)
    log(f"[hop1] '{cand['text'] or cand['aria']}' clicked={bool(d1)} -> {tgt.url} login={ok} ({why})")
    if ok: return True, why, tgt, path
    # hop 2: a menu likely opened in place -> click "Log in"/"Sign in" now visible
    d2 = find_and_click(tgt, lambda t,h,a: LOGIN.search(t) or LOGIN.search(a) or (h and HREF.search(h)))
    if d2: path.append(d2)
    page.wait_for_timeout(1600)
    tgt2 = popup.get("p") or tgt
    try: tgt2.wait_for_load_state("domcontentloaded", timeout=6000)
    except Exception: pass
    dismiss_consent(tgt2)
    try: tgt2.wait_for_selector("input, [role=dialog], .modal", timeout=2500)
    except Exception: pass
    describe(tgt2, "hop2-dom")
    ok, why = has_login(tgt2)
    log(f"[hop2] click Log in clicked={bool(d2)} -> {tgt2.url} login={ok} ({why})")
    if ok: return True, why, tgt2, path
    return False, None, tgt2, path

def _run(b, domain, headed, stealth=False):
    """probe one domain using an existing browser; returns the result dict."""
    url = domain if domain.startswith("http") else "https://" + domain
    res = {"domain": domain, "label": "no-login", "reason": "no auth surface reached"}
    ctx = b.new_context(user_agent=UA, locale="en-US", viewport={"width":1366,"height":850})
    if stealth:
        try:
            ctx.add_init_script(STEALTH_JS)
            ctx.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9"})
        except Exception: pass
    ctx.set_default_timeout(8000); ctx.set_default_navigation_timeout(20000)
    page = ctx.new_page()
    try:
        try: page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            res = {"domain": domain, "label":"error", "reason": str(e)[:120]}; raise SystemExit
        log(f"[load] {url} -> {page.url}")
        dismiss_consent(page)
        # bounded settle: let SPA nav hydrate, capped so polling sites can't hang
        try: page.wait_for_load_state("networkidle", timeout=2500)
        except Exception: pass
        # bot-wall / challenge interstitial is NOT no-login -> route to manual review
        try: btxt = (page.title() + " " + (page.inner_text("body") or "")[:800])
        except Exception: btxt = ""
        if BLOCK.search(btxt):
            res = {"domain": domain, "label":"blocked", "reason":"bot-wall/challenge"}; raise SystemExit
        ok, why = has_login(page)
        log(f"[landing] login={ok} ({why})")
        if ok: res={"domain":domain,"label":"ok-for-agent","reason":why,"via":"landing","login_url":page.url,"click_path":[]}; raise SystemExit

        cands = collect(page)
        if not cands:
            page.wait_for_timeout(2500)            # SPA may still be hydrating
            ok, why = has_login(page)
            if ok: res={"domain":domain,"label":"ok-for-agent","reason":why,"via":"landing","login_url":page.url,"click_path":[]}; raise SystemExit
            cands = collect(page)
        log(f"[candidates] {len(cands)}:")
        for c in cands[:8]:
            log(f"   s={c['score']} text='{c['text']}' aria='{c['aria']}' icon='{c['icon']}' href={c['href'] or '(button)'} opener={c['opener']}")

        # 1) direct auth hrefs
        for c in [c for c in cands if c["href"] and HREF.search(c["href"])][:5]:
            try:
                page.goto(c["href"], wait_until="domcontentloaded", timeout=15000); dismiss_consent(page)
                ok, why = has_login(page)
                log(f"[href] {c['href']} -> login={ok} ({why})")
                if ok: res={"domain":domain,"label":"ok-for-agent","reason":why,"via":"href",
                            "login_url":page.url,
                            "click_path":[{"action":"goto","by":"href","value":c["href"],"label":c["text"] or c["aria"]}]}; raise SystemExit
            except SystemExit: raise
            except Exception as e: log(f"[href] err {str(e)[:50]}")

        # 2) openers / buttons -> two-hop menu chain
        for c in [c for c in cands if c["opener"] or c["is_button"]][:4]:
            try:
                ok, why, tgt, path = hop_to_login(ctx, page, url, c)
                if ok: res={"domain":domain,"label":"ok-for-agent","reason":why,"via":"menu",
                            "login_url":tgt.url,"click_path":path}; raise SystemExit
            except SystemExit: raise
            except Exception as e: log(f"[menu] err {str(e)[:50]}")
    except SystemExit: pass
    finally:
        try: ctx.close()
        except Exception: pass
    return res

def _worker(dom, headed, q, stealth=False):
    """run one site in a child process so a hang can be killed by the parent (Windows-safe: module-level)."""
    try:
        with sync_playwright() as p:
            args = ["--disable-blink-features=AutomationControlled"] if stealth else []
            b = p.chromium.launch(headless=not headed, args=args)
            try: q.put(_run(b, dom, headed, stealth))
            finally:
                try: b.close()
                except Exception: pass
    except Exception as e:
        q.put({"domain": dom, "label": "error", "reason": str(e)[:120]})

def probe(domain, headed=False, stealth=False):
    with sync_playwright() as p:
        args = ["--disable-blink-features=AutomationControlled"] if stealth else []
        b = p.chromium.launch(headless=not headed, args=args)
        try: return _run(b, domain, headed, stealth)
        finally:
            try: b.close()
            except Exception: pass

# ---- ledger integration (was merge_hints.py) ----------------------------
def origin(u):
    try:
        p = urlparse(u or ""); return f"{p.scheme}://{p.netloc}" if p.netloc else ""
    except Exception: return ""

def gate_block(r):
    return {"label": r.get("label"), "reason": r.get("reason"), "via": r.get("via"),
            "click_path": r.get("click_path", []),
            "login_origin": origin(r.get("login_url", "")),       # durable
            "login_url_last_seen": r.get("login_url"),            # may carry a stale token
            "checked_at": datetime.now(timezone.utc).isoformat()}

# registry-restricted suffixes -> excluded without a probe (the structural funnel step)
ACADEMIC = {'edu','ac.uk','edu.au','ac.jp','edu.cn','ac.nz','edu.sg','ac.kr','edu.in',
            'ac.in','edu.pk','ac.za','edu.tr','ac.at','edu.hk','ac.il','edu.my','ac.id'}
GOV = {'gov','mil','gov.uk','gov.au','gov.cn','gc.ca','gov.in','gob.es','gouv.fr',
       'go.jp','gov.sg','gov.za','gov.br','gov.tr','gov.il'}
def structural(host):
    h = host.lower().strip()
    for S, label in ((ACADEMIC,"academic"), (GOV,"government")):
        for s in sorted(S, key=lambda x:-x.count('.')):
            if h == s or h.endswith('.'+s): return label
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("domain", nargs="?", help="single domain (omit for --ledger batch)")
    ap.add_argument("--ledger", help="ledger JSON to write gate blocks into")
    ap.add_argument("--limit", type=int, help="cap number of entries this run")
    ap.add_argument("--refresh", action="store_true", help="re-probe entries that already have a gate")
    ap.add_argument("--no-structural-skip", action="store_true", help="probe .edu/.gov instead of excluding")
    ap.add_argument("--only", nargs="+", metavar="LABEL",
                    help="re-probe entries whose current gate label is one of these (e.g. --only error blocked)")
    ap.add_argument("--stealth", action="store_true",
                    help="anti-bot recovery: mask automation signals + realistic headers")
    ap.add_argument("--budget", type=int, default=45, help="hard per-site wall-clock seconds (default 45)")
    ap.add_argument("--headed", action="store_true")
    a = ap.parse_args()

    # (A) single domain, no ledger -> print (unchanged behaviour)
    if a.domain and not a.ledger:
        print(f"=== portal_probe v{VERSION} :: {a.domain} ===")
        r = probe(a.domain, a.headed, a.stealth)
        print(f"LABEL = {r['label']:12s} reason={r.get('reason')}  via={r.get('via','-')}")
        print(json.dumps(r)); sys.exit()

    if not a.ledger:
        ap.error("provide a domain, or --ledger PATH for batch mode")

    led = json.load(open(a.ledger, encoding="utf-8")); E = led["entries"]
    def save(): json.dump(led, open(a.ledger, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    if a.domain:
        targets = [a.domain]
    elif a.only:
        want = set(a.only)
        targets = [k for k, e in E.items() if e.get("gate", {}).get("label") in want]
    else:
        targets = [k for k, e in E.items() if e.get("state") == "pending" and (a.refresh or "gate" not in e)]
    if a.limit: targets = targets[:a.limit]
    QUIET = True   # silence the per-step trace during batch
    print(f"portal_probe v{VERSION}: {len(targets)} target(s) -> {a.ledger}"      + (f"  [stealth, budget {a.budget}s]" if a.stealth else ""))

    import multiprocessing as mp
    SITE_BUDGET = a.budget   # hard wall-clock seconds per site; exceed -> error, move on
    done = 0
    try:
        for dom in targets:
            if dom not in E: print(f"  skip {dom}: not in ledger"); continue
            lab = None if a.no_structural_skip else structural(dom)
            if lab:
                E[dom]["gate"] = {"label": f"excluded-{lab}", "reason": "registry-restricted suffix",
                                  "via": "structural", "checked_at": datetime.now(timezone.utc).isoformat()}
                print(f"  [{done+1}/{len(targets)}] {dom:28s} excluded-{lab}")
            else:
                q = mp.Queue()
                proc = mp.Process(target=_worker, args=(dom, a.headed, q, a.stealth), daemon=True)
                proc.start(); proc.join(SITE_BUDGET)
                if proc.is_alive():          # blew the budget -> kill, record, continue
                    proc.terminate(); proc.join()
                    r = {"domain": dom, "label": "error", "reason": f"timeout >{SITE_BUDGET}s"}
                else:
                    try: r = q.get_nowait()
                    except Exception: r = {"domain": dom, "label": "error", "reason": "no result"}
                E[dom]["gate"] = gate_block(r)
                print(f"  [{done+1}/{len(targets)}] {dom:28s} {r['label']} ({r.get('reason')})")
            done += 1
            if done % 5 == 0: save()
    except KeyboardInterrupt:
        print("\n[interrupted] saving progress...")
    finally:
        save()

    from collections import Counter
    dist = Counter(e.get("gate", {}).get("label") for e in E.values() if "gate" in e)
    print("\ngate distribution:", dict(dist))