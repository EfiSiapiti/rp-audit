#!/usr/bin/env python3
"""
Canva login by replaying the captured auth requests THROUGH Playwright's JS
engine (page.evaluate + fetch), so each request carries the real browser's TLS
fingerprint and cookies -- Cloudflare cleared, no UI automation, no selectors.

Method (matches the Tier-2 "real browser" idea, but issuing the API calls
in-page instead of only rendering):
  1. Launch a real Chrome (persistent profile) and open canva.com so the origin
     gets its cookies (__cf_bm / cf_clearance) and we inherit the JS-engine fp.
  2. Pull the `user-authentication-methods` and `login2` request TEMPLATES from
     the capture, substitute {{email}}/{{password}} from identity.json.
  3. Run them with fetch() inside the page context (credentials:'include').
  4. Verify with session/validate.

Setup:
    pip install playwright ; python -m playwright install chromium
Run:
    python login_fetch.py --channel chrome --profile pw-profile
    python login_fetch.py --capture canva_capture.json --identity identity.json
"""
import argparse, json, os, re, sys, datetime

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("pip install playwright && python -m playwright install chromium")

BASE = "https://www.canva.com"
# headers the browser must own; fetch() forbids/overrides these, so we drop them
FORBIDDEN = {"host","cookie","content-length","user-agent","accept-encoding",
             "origin","referer","connection","x-canva-authz"}  # authz is pre-auth-stale here
def is_fwd(k): return not (k.startswith(":") or k.lower() in FORBIDDEN
                           or k.lower().startswith("sec-"))

def now(): return datetime.datetime.now().isoformat(timespec="milliseconds")

def esc(v):  # safe insertion into a JSON string literal
    return json.dumps(v)[1:-1]

def load_template(posts, suffix):
    for e in posts:
        if e["url"].split("?")[0].endswith(suffix):
            return e
    sys.exit(f"no {suffix} request found in capture")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="data\\http\\canva.com.raw.json")
    ap.add_argument("--identity", default="identity.json")
    ap.add_argument("--channel", default=None)
    ap.add_argument("--profile", default="pw-profile")
    ap.add_argument("--headless", action="store_true")
    args = ap.parse_args()

    ident = json.load(open(args.identity, encoding="utf-8"))
    email, pw = ident.get("email"), ident.get("password")
    if not isinstance(email, str) or not isinstance(pw, str):
        sys.exit('identity.json must be {"email":"...","password":"..."} (strings)')

    data = json.load(open(args.capture, encoding="utf-8"))
    posts = [e for e in data if e.get("method") == "POST"]
    uam = load_template(posts, "user-authentication-methods")
    login = load_template(posts, "/login2")
    sval = load_template(posts, "session/validate")

    def prep(e):
        body = (e.get("request_body") or "")
        body = body.replace("{{email}}", esc(email)).replace("{{password}}", esc(pw))
        headers = {k: v for k, v in e["request_headers"].items() if is_fwd(k)}
        # relative path so fetch is same-origin
        path = e["url"][len(BASE):] if e["url"].startswith(BASE) else e["url"]
        return {"path": path, "headers": headers, "body": body,
                "label": e["request_headers"].get("x-canva-request", path)}

    reqs = [prep(uam), prep(login)]

    with sync_playwright() as p:
        launch = dict(headless=args.headless, args=["--start-maximized"])
        if args.channel: launch["channel"] = args.channel
        if args.headless: launch["args"] = ["--headless=new"] + launch["args"]
        ctx = p.chromium.launch_persistent_context(args.profile, **launch)
        page = ctx.pages[0] if ctx.pages else ctx.new_page()

        print(f"[{now()}] opening {BASE}/login to establish origin cookies + fingerprint")
        page.goto(f"{BASE}/login", wait_until="domcontentloaded")
        page.wait_for_timeout(2500)

        print(f"[{now()}] firing auth requests through the page's fetch():")
        results = page.evaluate("""async (reqs) => {
            const out = [];
            for (const r of reqs) {
                try {
                    const resp = await fetch(r.path, {
                        method: 'POST', credentials: 'include',
                        headers: r.headers, body: r.body,
                    });
                    const text = await resp.text();
                    out.push({label: r.label, status: resp.status,
                              body: text.slice(0, 1500)});
                } catch (e) {
                    out.push({label: r.label, status: 'ERR', body: String(e)});
                }
            }
            return out;
        }""", reqs)

        login_ok = False
        for r in results:
            print(f"   <- {r['status']}  {r['label']}")
            print(f"      {r['body'][:300]}")
            if r["label"] == "loginv2" and r["status"] == 200 and ident["email"] in r["body"]:
                login_ok = True

        # verify with the REAL session/validate template (correct body + headers)
        sv = prep(sval)
        sess = page.evaluate("""async (r) => {
            const resp = await fetch(r.path, {method:'POST', credentials:'include',
                headers:r.headers, body:r.body});
            let t = await resp.text();
            // strip Canva's anti-JSON-hijacking prefix if present
            const i = t.indexOf('{'); if (i > 0) t = t.slice(i);
            return {status: resp.status, body: t.slice(0,400)};
        }""", sv)
        sess_ok = sess.get("status") == 200
        authed = login_ok or sess_ok
        print("\n==================== LOGIN CHECK ====================")
        print(f"login2        -> {'OK (account returned)' if login_ok else 'no'}")
        print(f"session/validate -> {sess}")
        print(f"VERDICT       : {'LOGGED IN' if authed else 'NOT logged in'}")
        print("=====================================================")
        json.dump({"results": results, "session": sess},
                  open("login_fetch_result.json","w"), indent=2)
        print("wrote login_fetch_result.json")
        ctx.close()

if __name__ == "__main__":
    main()
