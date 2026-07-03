"""Read-only page scan — surface blockers and the likely outcome.

Runs the src/lib/detect.py detectors against the current page and reports what
it found, so the manual signup flow can hint at the right outcome (and confirm
whether you're actually on an auth surface yet). Purely diagnostic: it clicks
nothing and changes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import detect


@dataclass
class ScanResult:
    on_surface: bool = False
    surface_evidence: str = ""
    # (suggested_outcome, evidence) for each blocker detected.
    blockers: list[tuple[str, str]] = field(default_factory=list)

    @property
    def suggested_outcome(self) -> str | None:
        """The most specific blocker outcome, if any (first one wins)."""
        return self.blockers[0][0] if self.blockers else None


async def scan(page) -> ScanResult:
    """Detect blockers + auth surface on `page`. Never raises."""
    res = ScanResult()

    # Blockers, in priority order — the first is treated as the suggestion.
    # Cloudflare is a hard captcha block; a visible CAPTCHA is captcha-blocked.
    checks: list[tuple[str, object]] = [
        ("captcha-blocked", detect.detect_cloudflare_challenge),
        ("captcha-blocked", detect.detect_captcha),
        ("geo-blocked", detect.detect_geo_block),
        ("phone-gated", detect.detect_phone_required_on_page),
        ("duplicate-account", detect.detect_already_registered),
    ]
    for outcome, fn in checks:
        try:
            hit, evidence = await fn(page)
        except Exception:
            continue
        if hit:
            res.blockers.append((outcome, evidence))

    try:
        res.on_surface, res.surface_evidence = await detect.detect_login_signup_surface(page)
    except Exception:
        res.on_surface, res.surface_evidence = False, ""

    return res
