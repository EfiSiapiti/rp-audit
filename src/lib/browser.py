"""Shared browser session.

The agent invokes many tools per RP — navigate, snapshot, fill, click,
snapshot again. Each one needs the same page/context, so we keep a
module-level singleton.

Design:
- Headed Chromium / Chrome (visible). User watches and solves CAPTCHAs.
- Each launch gets a throwaway temp profile — we never create or reuse a
  persistent per-RP profile, so every run starts as a first-time visitor
  with an empty cookie jar. The temp dir is removed on shutdown.
- playwright-stealth patches injected on every page to hide the most
  obvious automation tells (navigator.webdriver, plugin arrays, etc).

Stealth notes:
- After busting my patience, the automation passes the browser attached to playwright test though the flag --disable-blink-features=AutomationControlle.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from playwright.async_api import async_playwright, BrowserContext, Page, Playwright

try:
    from playwright_stealth import Stealth
    _STEALTH_AVAILABLE = True
except ImportError:
    _STEALTH_AVAILABLE = False


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
    """Re-assert the password-manager / autofill suppression keys every launch.

    Each launch uses a fresh temp profile, so this normally writes into a
    new Preferences file. Merge (rather than overwrite) the keys anyway so
    that if Chrome has already written a Preferences file this run, the
    "Save password?" bubble — which can sit on top of the form and block
    submission — stays suppressed; preserve everything else and tolerate a
    missing/corrupt file.
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


class BrowserSession:
    def __init__(self) -> None:
        self.pw: Playwright | None = None
        self.ctx: BrowserContext | None = None
        self.page: Page | None = None
        self.rp_id: str | None = None
        self._profile_dir: Path | None = None

    async def _apply_stealth(self, page: Page) -> None:
        if not _STEALTH_AVAILABLE:
            return
        try:
            await Stealth().apply_stealth_async(page)
        except Exception as e:
            print(f"  (stealth patches failed: {e})")

    async def _launch_for_rp(self, rp_id: str) -> Page:

        last_problem = "unknown"
        for attempt in range(1, 4):
            profile_dir = _ephemeral_profile_dir(rp_id)
            self._profile_dir = profile_dir
            default_dir = profile_dir / "Default"
            default_dir.mkdir(parents=True, exist_ok=True)
            _merge_chrome_prefs(default_dir / "Preferences")

            launch_kwargs = dict(
                user_data_dir=str(profile_dir.absolute()),
                headless=False,
                
                no_viewport=True,
               
                args=[
                    "--disable-features=IsolateOrigins,site-per-process,"
                    "AutofillServerCommunication,AutofillEnableAccountWalletStorage",
                    "--disable-autofill-keyboard-accessory-view",
               
                    "--disable-blink-features=AutomationControlled",
                ],
                ignore_default_args=["--enable-automation"],
            )

            self.pw = await async_playwright().start()
            try:
                try:
                    self.ctx = await self.pw.chromium.launch_persistent_context(channel="chrome", **launch_kwargs)
                    channel = "real Chrome"
                except Exception:
                    self.ctx = await self.pw.chromium.launch_persistent_context(**launch_kwargs)
                    channel = "Chromium fallback"
                self.page = self.ctx.pages[0] if self.ctx.pages else await self.ctx.new_page()
                await self._apply_stealth(self.page)
                # No UA / Client-Hints override: native Chrome already emits a
                # correct, machine-accurate and self-consistent UA + Sec-CH-UA-*
                # set (verified: platform-version, arch, bitness, full-version
                # all match a normally-launched Chrome). A CDP override could
                # only introduce a mismatch — e.g. a hardcoded platformVersion
                # that Cloudflare's critical-CH retry would catch.
                self.rp_id = rp_id
                if await _page_healthy(self.page):
                    print(f"  (browser: {channel}, profile={profile_dir})")
                    return self.page
                last_problem = "launched browser was unresponsive"
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
            if self.ctx:
                await self.ctx.close()
            if self.pw:
                await self.pw.stop()
        finally:
            self.pw = None
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
