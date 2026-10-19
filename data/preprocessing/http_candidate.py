#!/usr/bin/env python3
"""
http_candidate.py — cheap, browser-less check of whether an RP's SIGNUP surface looks
replayable over plain HTTP (the rp-audit replay_http route). No account is created.

Stage 1  GET the login/auth page (what replay_http needs for the login leg).
Stage 2  Follow the page's "sign up / register" link (falling back to /signup, /register,
         /join) and inspect THAT page, because captchas, paid walls, B2B-only portals and
         extension prompts live on the signup page, not the login page.

It does NOT see the real register request (that needs a submit); it judges the pages that
produce it.

Labels
  http-friendly   signup page has a server-rendered form with email + password, no challenge
  http-maybe      signup form is identifier-first, or a signup page was found with no form
  ajax-spa        signup/auth form is JS-rendered (not in the HTML)
  challenged      captcha / bot-wall / client-side crypto on the login or signup page
  gated           signup page is paid, B2B/invite-only, or needs an extension/app
  no-signup-link  login page is fine but no signup page could be found
  unreachable     request failed or non-2xx

Usage
  python data/preprocessing/http_candidate.py https://www.head-fi.org/login
  python data/preprocessing/http_candidate.py --ledger data/ledger_fidentikit.json --only-gate ok-for-agent --refresh
"""
import argparse, json, re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9",
           "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
           "Upgrade-Insecure-Requests": "1"}

# marker -> regex searched in the HTML (scripts, iframes, attributes included)
CHALLENGE = {
    "recaptcha":  r"google\.com/recaptcha|g-recaptcha|grecaptcha",
    "hcaptcha":   r"hcaptcha\.com|h-captcha",
    "turnstile":  r"challenges\.cloudflare\.com/turnstile|cf-turnstile",
    "arkose":     r"arkoselabs|funcaptcha|client-api\.arkose",
    "geetest":    r"geetest",
    "datadome":   r"datadome|captcha-delivery\.com",
    "perimeterx": r"perimeterx|px-captcha|_pxhd|px-cdn",
    "kasada":     r"ips\.js|kpsdk|x-kpsdk",
    "akamai-bm":  r"_abck|akamai.*bot",
}
CRYPTO = {  # client-side password handling that raw POSTs can't reproduce
    "encrypted_password": r"encrypted[_-]?password",
    "password_hash_js":   r"(sha256|sha512|md5|pbkdf2|bcrypt|srp)[^\"']{0,30}password|password[^\"']{0,30}(sha256|sha512|pbkdf2|srp)",
}
# signup-page walls, only counted when the page has no usable password form
GATES = {
    "paid":      r"credit card|payment (is )?required|per month|/ ?month|billing (details|information)|choose (a|your) plan|pricing",
    "b2b":       r"contact (our )?sales|request (a )?demo|book a demo|talk to sales|partner portal|invitation[- ]only|invite[- ]only|by invitation",
    "extension": r"install (the |our )?(browser )?extension|add to (chrome|firefox|browser)|download (the |our )?(app|extension|installer)",
}
WALL_TITLE = re.compile(r"just a moment|attention required|access denied|verify you are human|"
                        r"are you a robot|unusual traffic|checking your browser", re.I)
SPA_ROOT = re.compile(r'<div[^>]+id=["\'](root|app|__next|__nuxt|svelte)["\']', re.I)

SIGNUP_TEXT = re.compile(r"sign ?up|register|registration|create (an? )?(free )?(new )?account|join( now| free| us)?|"
                         r"get started|registrier|inscri|crear cuenta|регистрац|neues konto|konto erstellen", re.I)
SIGNUP_HREF = re.compile(r"sign-?up|register|registration|create-?account|/join\b|/new\b|/regist", re.I)
FALLBACK_PATHS = ("/signup", "/register", "/join", "/sign-up", "/registration", "/users/sign_up")


class _Form:
    def __init__(self, action, method):
        self.action, self.method = action, (method or "get").lower()
        self.inputs = []   # (name, type, autocomplete)


class _P(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self._cur, self.title, self._in_title = [], None, "", False
        self.n_script, self.anchors, self._a, self._skip = 0, [], None, 0
        self.text = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title": self._in_title = True
        elif tag in ("script", "style"):
            self._skip += 1
            if tag == "script": self.n_script += 1
        elif tag == "a" and a.get("href"):
            self._a = {"href": a["href"], "text": ""}; self.anchors.append(self._a)
        elif tag == "form":
            self._cur = _Form(a.get("action", ""), a.get("method", "get")); self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            self._cur.inputs.append((a.get("name", ""), a.get("type", "text" if tag == "input" else tag).lower(),
                                     a.get("autocomplete", "").lower()))

    def handle_data(self, d):
        if self._in_title: self.title += d
        if self._skip: return
        self.text.append(d)
        if self._a is not None: self._a["text"] += d

    def handle_endtag(self, tag):
        if tag == "title": self._in_title = False
        elif tag in ("script", "style") and self._skip: self._skip -= 1
        elif tag == "a": self._a = None
        elif tag == "form": self._cur = None


def _best_form(forms):
    """auth-like form: has a password input, or an email/user field; GET without password is a search box."""
    def score(f):
        has_pw = any(t == "password" for _, t, _ in f.inputs)
        if f.method == "get" and not has_pw:
            return 0
        return (2 if has_pw else 0) + \
               (1 if any(t == "email" or "email" in n.lower() or "user" in n.lower() for n, t, _ in f.inputs) else 0)
    best = max(forms, key=score, default=None)
    return (best, score(best)) if best and score(best) else (None, 0)


def fetch(client, url):
    """GET + parse. Returns (info dict, parser|None). info['dead'] set when the page cannot be judged."""
    info = {"url": url, "challenges": [], "crypto": [], "forms": 0, "password_form": False, "hidden_fields": 0}
    try:
        r = client.get(url)
    except Exception as e:
        info.update(dead="unreachable", reason=f"{type(e).__name__}: {str(e)[:80]}"); return info, None
    info["final_url"], info["status"] = str(r.url), r.status_code
    if r.headers.get("cf-mitigated") == "challenge":
        info.update(dead="challenged", reason="cloudflare managed challenge (cf-mitigated)", challenges=["cloudflare"]); return info, None
    if r.status_code >= 400:
        if r.status_code in (401, 403, 429, 503):
            info.update(dead="challenged", reason=f"HTTP {r.status_code} (likely bot-wall)")
        else:
            info.update(dead="unreachable", reason=f"HTTP {r.status_code}")
        return info, None
    html = r.text or ""
    p = _P(); p.feed(html)
    if WALL_TITLE.search(p.title or ""):
        info.update(dead="challenged", reason=f"bot-wall page: {p.title.strip()[:50]}", challenges=["interstitial"]); return info, None
    info["challenges"] = [k for k, rx in CHALLENGE.items() if re.search(rx, html, re.I)]
    info["crypto"] = [k for k, rx in CRYPTO.items() if re.search(rx, html, re.I)]
    info["forms"] = len(p.forms)
    best, sc = _best_form(p.forms)
    if best:
        info["password_form"] = any(t == "password" for _, t, _ in best.inputs)
        info["hidden_fields"] = sum(1 for _, t, _ in best.inputs if t == "hidden")
        info["form_action"], info["form_method"] = urljoin(str(r.url), best.action), best.method
        info["has_email"] = any(t == "email" or "email" in n.lower() for n, t, _ in best.inputs)
    info["has_form"] = bool(best)
    info["spa"] = bool(SPA_ROOT.search(html) or p.n_script >= 8)
    info["n_script"] = p.n_script
    info["_text"] = " ".join(" ".join(p.text).split())[:60000]
    return info, p


def signup_links(p, base):
    """candidate signup URLs from the page's anchors, best first."""
    seen, scored = set(), []
    for a in p.anchors:
        href = a["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        txt = " ".join(a["text"].split())[:60]
        s = (3 if SIGNUP_TEXT.search(txt) else 0) + (2 if SIGNUP_HREF.search(href) else 0)
        if not s:
            continue
        u = urljoin(base, href).split("#")[0]
        if u in seen or u.rstrip("/") == base.rstrip("/"):
            continue
        seen.add(u); scored.append((s, u))
    scored.sort(key=lambda t: -t[0])
    return [u for _, u in scored[:3]]


def judge_signup(info):
    """label for one fetched signup page, or None if it is not a usable signup page."""
    if info.get("dead"):
        return info["dead"], info["reason"]
    if info["crypto"]:
        return "challenged", "client-side password crypto on signup: " + ",".join(info["crypto"])
    if info["challenges"]:
        return "challenged", "challenge vendor on signup page: " + ",".join(info["challenges"])
    if info["password_form"]:
        return "http-friendly", "signup page has a server-rendered form with a password field"
    text = info.get("_text", "")
    for g, rx in GATES.items():
        m = re.search(rx, text, re.I)
        if m:
            return "gated", f"signup page looks {g} ('{m.group(0)[:30]}') and has no password form"
    if info["has_form"]:
        return "http-maybe", "signup page has an identifier-first form (no password field yet)"
    if info["spa"]:
        return "ajax-spa", f"signup page has no form in HTML; JS-rendered ({info['n_script']} scripts)"
    return None, "no auth form on this page"


def analyze(url, timeout=15):
    out = {"url": url, "label": "unreachable", "reason": "", "challenges": [], "crypto": [],
           "checked_at": datetime.now(timezone.utc).isoformat()}
    with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=timeout) as c:
        login, lp = fetch(c, url)
        out.update({k: login[k] for k in ("final_url", "status", "forms", "password_form", "hidden_fields",
                                          "form_action", "form_method", "challenges", "crypto") if k in login})
        if login.get("dead"):
            out.update(label=login["dead"], reason="login page: " + login["reason"]); return out
        if login["crypto"]:
            out.update(label="challenged", reason="client-side password crypto on login: " + ",".join(login["crypto"])); return out

        # stage 2: find and judge the signup page
        base = login["final_url"]
        cands = signup_links(lp, base) if lp else []
        o = urlparse(base); root = f"{o.scheme}://{o.netloc}"
        for pth in FALLBACK_PATHS:
            u = root + pth
            if u not in cands and len(cands) < 6:
                cands.append(u)
        tried, verdict = [], None
        for u in cands:
            sinfo, _ = fetch(c, u)
            lab, why = judge_signup(sinfo)
            tried.append({"url": sinfo.get("final_url", u), "label": lab, "reason": why})
            # a real verdict on a real signup page; a 404 on a guessed path means keep looking
            if lab and not (lab == "unreachable"):
                verdict = (lab, why, sinfo); break
        out["signup_tried"] = tried
        if verdict:
            lab, why, sinfo = verdict
            out.update(label=lab, reason=why, signup_url=sinfo.get("final_url"),
                       challenges=sorted(set(out["challenges"]) | set(sinfo["challenges"])),
                       signup_form_action=sinfo.get("form_action"), signup_form_method=sinfo.get("form_method"),
                       signup_hidden_fields=sinfo.get("hidden_fields"))
            return out

        # login page itself may be the combined auth surface (signup tab on the same page)
        if login["challenges"]:
            out.update(label="challenged", reason="challenge vendor on login page: " + ",".join(login["challenges"])); return out
        out.update(label="no-signup-link", reason="login page ok but no signup page found")
        return out


def target_url(entry):
    g = entry.get("gate") or {}
    return g.get("login_url_last_seen") or entry.get("signup_url") or entry.get("canonical_origin")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", nargs="?", help="single URL to check")
    ap.add_argument("--ledger", help="ledger JSON; writes an http_probe block per entry")
    ap.add_argument("--only-gate", nargs="+", metavar="LABEL", help="only entries whose portal_probe gate label is one of these")
    ap.add_argument("--rp", nargs="+", help="only these rp_ids")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--refresh", action="store_true", help="re-check entries that already have http_probe")
    ap.add_argument("--workers", type=int, default=16)
    a = ap.parse_args()

    if a.url:
        r = analyze(a.url if a.url.startswith("http") else "https://" + a.url)
        print(f"LABEL = {r['label']:14s} {r['reason']}")
        print(json.dumps(r, indent=2)); return
    if not a.ledger:
        ap.error("provide a URL, or --ledger PATH")

    led = json.load(open(a.ledger, encoding="utf-8")); E = led["entries"]
    targets = [k for k, e in E.items()
               if (a.refresh or "http_probe" not in e)
               and (not a.only_gate or (e.get("gate") or {}).get("label") in a.only_gate)
               and (not a.rp or k in a.rp)]
    if a.limit: targets = targets[:a.limit]
    print(f"http_candidate: {len(targets)} target(s) -> {a.ledger}")

    def work(k): return k, analyze(target_url(E[k]))
    done = 0
    try:
        with ThreadPoolExecutor(a.workers) as ex:
            for k, r in ex.map(work, targets):
                E[k]["http_probe"] = r
                done += 1
                print(f"  [{done}/{len(targets)}] {k:28s} {r['label']:14s} {r['reason']}")
                if done % 25 == 0: json.dump(led, open(a.ledger, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    except KeyboardInterrupt:
        print("\n[interrupted] saving progress...")
    finally:
        json.dump(led, open(a.ledger, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("\nhttp_probe distribution:", dict(Counter((e.get("http_probe") or {}).get("label") for e in E.values() if "http_probe" in e)))


if __name__ == "__main__":
    main()
