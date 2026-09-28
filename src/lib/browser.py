"""Shared browser session.

The agent invokes many tools per RP — navigate, snapshot, fill, click,
snapshot again. Each one needs the same page/context, so we keep a
module-level singleton.

Design:
- Headed real Chrome (visible). User watches and solves CAPTCHAs.
- We do NOT let Playwright *launch* the browser. Playwright's
  launch_persistent_context injects ~40 default command-line switches and
  keeps an active CDP instrumentation session running; that combination is
  fingerprinted by Cloudflare-class bot detection (e.g. Canva 403s) even with
  navigator.webdriver forced false. Instead we spawn a plain real Chrome as
  its own subprocess with a minimal, benign flag set (exactly the manual_launch.py
  recipe that is verified to get past Canva) and then *attach* to it over CDP
  via connect_over_cdp. The running browser process is then indistinguishable
  from a hand-started Chrome — webdriver is never set at all — while Playwright
  still fully drives it for record/replay.
- Each launch gets a throwaway temp profile — we never create or reuse a
  persistent per-RP profile, so every run starts as a first-time visitor
  with an empty cookie jar. The temp dir is removed on shutdown.

History: commit bb6b309 ("first test passed: playwright attached and not
detected as a bot") used this attach-over-CDP approach; a later switch to
launch_persistent_context regressed it. This restores the attach model.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

# Driver: prefer patchright — a drop-in patched Playwright that removes the
# CDP-attach tells Cloudflare-class bot management fingerprints (it avoids the
# main-world `Runtime.enable` leak, acquires execution contexts via isolated
# worlds, and hides Playwright's injected bindings). The residual signal that
# challenged Canva's authnflow POST was this instrumentation, NOT behaviour:
# during record the human physically drives the real Chrome, so input events
# are genuine/trusted. Falls back to stock Playwright if patchright isn't
# installed (`pip install patchright`; no browser download needed since we
# attach to our own real Chrome over CDP).
try:
    from patchright.async_api import async_playwright  # type: ignore
    _DRIVER = "patchright"
except ImportError:
    from playwright.async_api import async_playwright
    _DRIVER = "playwright"

# Type-only imports (structurally compatible with patchright's objects).
from playwright.async_api import Browser, BrowserContext, Page, Playwright


def _ephemeral_profile_dir(rp_id: str) -> Path:
    """A throwaway profile directory for a single launch.

    We deliberately do NOT create or reuse a persistent per-RP profile under
    browser-profiles/ — every launch gets a fresh temp dir, so each run is a
    first-time visitor. The dir is our own scratch space (removed on
    shutdown), never a directory the user manages.
    """
    safe = rp_id.replace("/", "_").replace("\\", "_")
    return Path(tempfile.mkdtemp(prefix=f"rp-audit-{safe}-"))


def _merge_chrome_prefs(prefs_path: Path) -> None:
    """Re-assert the password-manager / autofill / permission-prompt suppression
    keys every launch.

    Each launch uses a fresh temp profile, so this normally writes into a
    new Preferences file. Merge (rather than overwrite) the keys anyway so
    that if Chrome has already written a Preferences file this run, the
    "Save password?" bubble — which can sit on top of the form and block
    submission — stays suppressed; preserve everything else and tolerate a
    missing/corrupt file. Also default-blocks notification/geolocation prompts
    (a site's "Show notifications?" bubble would otherwise cover buttons and
    break a replay click).
    """
    data: dict = {}
    if prefs_path.exists():
        try:
            loaded = json.loads(prefs_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}
    data["credentials_enable_service"] = False
    data["credentials_enable_autosignin"] = False
    profile = data.get("profile")
    if not isinstance(profile, dict):
        profile = {}
    profile["password_manager_enabled"] = False
    profile["password_manager_leak_detection"] = False
    # Auto-deny permission prompts (2 = block) so "Show notifications?" /
    # location bubbles never cover the page or intercept a replay click.
    # (Ruled out as the Canva 403 cause on 2026-09-24 — block still 403s with
    # this disabled.)
    csv = profile.get("default_content_setting_values")
    if not isinstance(csv, dict):
        csv = {}
    csv["notifications"] = 2
    csv["geolocation"] = 2
    profile["default_content_setting_values"] = csv
    data["profile"] = profile
    autofill = data.get("autofill")
    if not isinstance(autofill, dict):
        autofill = {}
    autofill.update({"enabled": False, "profile_enabled": False, "credit_card_enabled": False})
    data["autofill"] = autofill
    try:
        prefs_path.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


async def _page_healthy(page: Page | None) -> bool:
    """True if `page` is open and its JS context responds.

    A persistent Chrome profile that is reopened immediately after being
    closed can come up wedged (the profile lock hasn't been released yet):
    launch_persistent_context returns without error, but the page is dead.
    A live page answers a trivial evaluate; a wedged/closed one raises or
    hangs, so we bound the probe with a timeout.
    """
    if page is None:
        return False
    try:
        if page.is_closed():
            return False
        await asyncio.wait_for(page.evaluate("1"), timeout=5)
        return True
    except Exception:
        return False


def _find_chrome() -> str:
    """Locate a real Chrome executable, or raise with guidance.

    We deliberately want *real* Chrome (channel), not Playwright's bundled
    Chromium — the fingerprint of a stock Chrome install is what passes.
    """
    candidates: list[Path] = []
    for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if base:
            candidates.append(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe")
    candidates.append(Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    for c in candidates:
        if c and c.exists():
            return str(c)
    raise RuntimeError(
        "could not find a real Chrome executable — install Chrome or set one on PATH"
    )


def _free_port(preferred: int = 9222) -> int:
    """Return `preferred` if free, else the next free port in a small range."""
    for port in [preferred, *range(preferred + 1, preferred + 40)]:
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred


def _wait_for_cdp(port: int, timeout: float = 30.0) -> str:
    """Block until Chrome's DevTools endpoint answers, then return its base URL.

    Blocking (urllib + sleep) — call via asyncio.to_thread from async code.
    """
    probe = f"http://127.0.0.1:{port}/json/version"
    deadline = time.time() + timeout
    last = "no response"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(probe, timeout=2) as r:
                json.loads(r.read())  # ensure it's really up
                return f"http://127.0.0.1:{port}"
        except Exception as e:
            last = str(e)
            time.sleep(0.5)
    raise RuntimeError(f"Chrome DevTools endpoint on port {port} did not come up in {timeout:.0f}s ({last})")


class BrowserSession:
    def __init__(self) -> None:
        self.pw: Playwright | None = None
        self.browser: Browser | None = None
        self.ctx: BrowserContext | None = None
        self.page: Page | None = None
        self.rp_id: str | None = None
        self._profile_dir: Path | None = None
        self._proc: subprocess.Popen | None = None

    async def _launch_for_rp(self, rp_id: str) -> Page:

        chrome = _find_chrome()  # fail fast & clearly if Chrome is missing
        last_problem = "unknown"
        for attempt in range(1, 4):
            profile_dir = _ephemeral_profile_dir(rp_id)
            self._profile_dir = profile_dir
            default_dir = profile_dir / "Default"
            default_dir.mkdir(parents=True, exist_ok=True)
            _merge_chrome_prefs(default_dir / "Preferences")

            port = _free_port(9222)
            # Minimal, benign flag set — the exact manual_launch.py recipe.
            # No automation switches, no --disable-blink-features, no big
            # --disable-features list: a subprocess Chrome never sets
            # navigator.webdriver, so there is nothing to suppress, and every
            # extra flag is just another thing that differs from a stock
            # Chrome. Playwright attaches afterwards over CDP and drives it.
            chrome_args = [
                chrome,
                f"--remote-debugging-port={port}",
                f"--user-data-dir={profile_dir.absolute()}",
                "--no-first-run",
                "--no-default-browser-check",
                "--new-window",
                "about:blank",
            ]

            try:
                self._proc = subprocess.Popen(chrome_args)
                cdp_url = await asyncio.to_thread(_wait_for_cdp, port)
                self.pw = await async_playwright().start()
                self.browser = await self.pw.chromium.connect_over_cdp(cdp_url)
                self.ctx = (self.browser.contexts[0] if self.browser.contexts
                            else await self.browser.new_context())
                self.page = self.ctx.pages[0] if self.ctx.pages else await self.ctx.new_page()
                self.rp_id = rp_id
                if await _page_healthy(self.page):
                    print(f"  (browser: real Chrome over CDP :{port} via {_DRIVER}, "
                          f"profile={profile_dir})")
                    return self.page
                last_problem = "attached browser was unresponsive"
            except Exception as e:
                last_problem = str(e)
            await self.shutdown()
            if attempt < 3:
                print(f"  (browser launch attempt {attempt} failed: {last_problem}; retrying…)")
                await asyncio.sleep(1.5 * attempt)

        raise RuntimeError(f"browser launch failed for {rp_id!r} after 3 attempts: {last_problem}")

    async def ensure_browser_for(self, rp_id: str) -> Page:
        if self.rp_id == rp_id and self.page and not self.page.is_closed():
            return self.page
        if self.rp_id is not None:
            await self.shutdown()
        return await self._launch_for_rp(rp_id)

    async def ensure_browser(self) -> Page:
        if self.page and not self.page.is_closed():
            return self.page
        raise RuntimeError("no browser running — call ensure_browser_for(rp_id) first via start_rp tool")

    def set_active_page(self, page: Page) -> None:
        """Adopt an already-open page (e.g. a popup from click_path replay)
        as the active page, so later ensure_browser() calls return it."""
        self.page = page

    async def get_context(self) -> BrowserContext:
        if self.ctx is None:
            raise RuntimeError("no browser context — call ensure_browser_for(rp_id) first")
        return self.ctx

    async def shutdown(self) -> None:
        try:
            # connect_over_cdp: browser.close() only disconnects Playwright; it
            # does NOT kill the Chrome we spawned. Do the disconnect first, then
            # terminate the subprocess ourselves.
            if self.browser:
                try:
                    await self.browser.close()
                except Exception:
                    pass
            if self.pw:
                await self.pw.stop()
        finally:
            if self._proc is not None:
                try:
                    self._proc.terminate()
                    try:
                        self._proc.wait(timeout=5)
                    except Exception:
                        self._proc.kill()
                except Exception:
                    pass
                self._proc = None
            self.pw = None
            self.browser = None
            self.ctx = None
            self.page = None
            self.rp_id = None
            # Remove the throwaway profile so nothing persists to be reused.
            if self._profile_dir is not None:
                shutil.rmtree(self._profile_dir, ignore_errors=True)
                self._profile_dir = None


_session = BrowserSession()


async def ensure_browser_for(rp_id: str) -> Page:
    return await _session.ensure_browser_for(rp_id)


async def ensure_browser() -> Page:
    return await _session.ensure_browser()


def set_active_page(page: Page) -> None:
    _session.set_active_page(page)


async def is_page_alive(page: Page | None) -> bool:
    return await _page_healthy(page)


async def get_context() -> BrowserContext:
    return await _session.get_context()


async def shutdown() -> None:
    await _session.shutdown()
