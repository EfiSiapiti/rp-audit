"""Capture an LLM-friendly snapshot of a page's interactable elements.

The snapshot is a compact text representation: every visible input,
button, link, and select gets a numeric ref like [12]. The agent
addresses elements by ref via the click/fill tools.

Refs are stable for the lifetime of one snapshot — the agent must
re-snapshot after any action that might change the DOM.

Design notes:
- We strip hidden elements aggressively. A typical Notion signup page
  has ~50 inputs in the DOM but only 2-5 visible; we want only the
  visible ones in context.
- Labels are pulled from <label for=>, parent <label>, aria-label,
  or nearby text. For unlabeled buttons we use innerText.
- Element type is normalized: 'input[type=email]' -> 'email_input',
  'button' -> 'button', etc. This is what the agent sees, not raw HTML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from playwright.async_api import Page


@dataclass
class Snapshot:
    url: str
    title: str
    elements: list[dict]               # numbered, agent-visible
    page_text_excerpt: str             # first ~500 chars of body for context
    raw_selectors: dict[int, str] = field(default_factory=dict)  # ref -> CSS selector
    raw_frames: dict[int, str] = field(default_factory=dict)     # ref -> owning frame url

    def to_agent_text(self) -> str:
        """Format the snapshot as text for the LLM."""
        lines = [
            f"URL: {self.url}",
            f"Title: {self.title}",
            "",
            "Page text (excerpt):",
            self.page_text_excerpt[:500],
            "",
            "Interactable elements:",
        ]
        for el in self.elements:
            ref = el["ref"]
            kind = el["kind"]
            label = el.get("label", "")
            extra = []
            if el.get("required"):
                extra.append("required")
            if el.get("checked") is True:
                extra.append("checked")
            if el.get("placeholder"):
                extra.append(f'placeholder="{el["placeholder"]}"')
            if el.get("in_iframe"):
                extra.append("in iframe")
            tail = f" ({', '.join(extra)})" if extra else ""
            lines.append(f"  [{ref}] {kind}: {label!r}{tail}")
        return "\n".join(lines)


_SNAPSHOT_JS = r"""
() => {
    function isVisible(el) {
        const rect = el.getBoundingClientRect();
        const style = window.getComputedStyle(el);
        return (
            rect.width > 0 && rect.height > 0
            && style.display !== 'none'
            && style.visibility !== 'hidden'
            && parseFloat(style.opacity) > 0.05
        );
    }

    function labelFor(el) {
        // 1. <label for="id">
        if (el.id) {
            const lbl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
            if (lbl && lbl.innerText) return lbl.innerText.trim();
        }
        // 2. wrapping <label>
        const parent = el.closest('label');
        if (parent) {
            // exclude the input's own value
            const clone = parent.cloneNode(true);
            clone.querySelectorAll('input,select,textarea').forEach(n => n.remove());
            const t = clone.innerText.trim();
            if (t) return t;
        }
        // 3. aria-labelledby
        const labelledBy = el.getAttribute('aria-labelledby');
        if (labelledBy) {
            const ref = document.getElementById(labelledBy);
            if (ref && ref.innerText) return ref.innerText.trim();
        }
        // 4. aria-label
        const al = el.getAttribute('aria-label');
        if (al) return al.trim();
        // 5. placeholder
        if (el.placeholder) return el.placeholder.trim();
        // 6. name attribute
        if (el.name) return el.name;
        return '';
    }

    // An <input type="tel"> is ambiguous: a real phone field, or a numeric
    // OTP / email-verification code box (devs use type=tel for the numeric
    // mobile keyboard). Misreading a code box as a phone field makes the
    // agent bail 'phone-gated' on a step it could actually complete.
    function telKind(el) {
        const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
        const im = (el.getAttribute('inputmode') || '').toLowerCase();
        const maxLen = parseInt(el.getAttribute('maxlength') || '0', 10);
        const hay = [
            ac, el.name || '', el.id || '', el.placeholder || '', labelFor(el),
        ].join(' ').toLowerCase();
        const codeRe = /otp|code|verif|pin|token|one[\s-]?time|passcode/;
        const phoneRe = /\bphone\b|\bmobile\b|\btel\b|\bcell\b|whatsapp/;
        const phoneSignal = ac.includes('tel') || phoneRe.test(hay);
        const codeSignal = ac === 'one-time-code'
            || codeRe.test(hay)
            || ((im === 'numeric' || (maxLen >= 4 && maxLen <= 8)) && !phoneSignal);
        if (codeSignal) return 'code_input';
        if (phoneSignal) return 'phone_input';
        return 'phone_input';  // bare tel, no hints: keep prior behavior
    }

    function selectorFor(el, idx) {
        if (el.id) return '#' + CSS.escape(el.id);
        if (el.name) return `${el.tagName.toLowerCase()}[name="${el.name}"]`;
        // Fall back to xpath-like positional selector via data attribute we inject
        el.setAttribute('data-rp-snapshot-ref', idx.toString());
        return `[data-rp-snapshot-ref="${idx}"]`;
    }

    // Collect interactables from this document AND any open shadow roots
    // beneath it. Plain querySelectorAll stops at shadow boundaries, which
    // hides web-component auth widgets (e.g. embedded sign-in forms).
    const SEL = 'input, select, textarea, button, a, [role="button"], [role="link"], [role="checkbox"]';
    function collect(root, acc) {
        let nodes;
        try { nodes = root.querySelectorAll(SEL); } catch (e) { nodes = []; }
        for (const n of nodes) acc.push(n);
        let all;
        try { all = root.querySelectorAll('*'); } catch (e) { all = []; }
        for (const el of all) {
            if (el.shadowRoot) collect(el.shadowRoot, acc);
        }
    }
    const interactables = [];
    collect(document, interactables);

    const out = [];
    let ref = 0;
    for (const el of interactables) {
        if (!isVisible(el)) continue;
        if (el.disabled) continue;

        const tag = el.tagName.toLowerCase();
        const type = (el.type || '').toLowerCase();
        let kind;
        if (tag === 'input') {
            if (type === 'checkbox') kind = 'checkbox';
            else if (type === 'radio') kind = 'radio';
            else if (type === 'submit' || type === 'button') kind = 'button';
            else if (type === 'password') kind = 'password_input';
            else if (type === 'email') kind = 'email_input';
            else if (type === 'tel') kind = telKind(el);
            else if (type === 'date') kind = 'date_input';
            else if (type === 'hidden') continue;
            else kind = 'text_input';
        } else if (tag === 'select') {
            kind = 'select';
        } else if (tag === 'textarea') {
            kind = 'textarea';
        } else if (tag === 'button' || el.getAttribute('role') === 'button') {
            kind = 'button';
        } else if (tag === 'a' || el.getAttribute('role') === 'link') {
            // Only include links that look navigation-relevant
            const text = (el.innerText || '').trim();
            if (!text || text.length > 80) continue;
            kind = 'link';
        } else {
            continue;
        }

        ref += 1;
        out.push({
            ref,
            kind,
            label: labelFor(el).slice(0, 120),
            placeholder: el.placeholder || '',
            required: el.required || el.getAttribute('aria-required') === 'true',
            checked: kind === 'checkbox' ? el.checked : null,
            autocomplete: el.autocomplete || '',
            selector: selectorFor(el, ref),
        });
    }

    return {
        url: location.href,
        title: document.title,
        body_text: (document.body && document.body.innerText || '').slice(0, 2000),
        elements: out,
    };
}
"""


async def snapshot(page: Page) -> Snapshot:
    """Snapshot the main frame AND every child iframe.

    Embedded auth widgets (Agoda, Salla, some SSO providers) render their
    sign-in form inside a cross-origin iframe. Each frame is its own document,
    so we run the snapshot JS in every frame and merge the results under one
    globally-numbered ref space. Per-ref we remember the owning frame's URL so
    the fill/click tools can act inside the right frame.

    The local CSS selectors (`#id`, `[data-rp-snapshot-ref=N]`) stay valid
    because they're resolved against the frame that produced them.
    """
    url = title = body_text = ""
    public_elements: list[dict] = []
    raw_selectors: dict[int, str] = {}
    raw_frames: dict[int, str] = {}
    gref = 0
    main = page.main_frame
    for frame in page.frames:
        try:
            data: dict[str, Any] = await frame.evaluate(_SNAPSHOT_JS)
        except Exception:
            # detached / still-loading / hostile frame — skip it
            continue
        if frame is main:
            url = data.get("url", "")
            title = data.get("title", "")
            body_text = data.get("body_text", "")
        for e in data.get("elements", []):
            gref += 1
            raw_selectors[gref] = e["selector"]
            raw_frames[gref] = frame.url
            pe = {k: v for k, v in e.items() if k != "selector"}
            pe["ref"] = gref
            if frame is not main:
                pe["in_iframe"] = True
            public_elements.append(pe)
    return Snapshot(
        url=url,
        title=title,
        elements=public_elements,
        page_text_excerpt=body_text,
        raw_selectors=raw_selectors,
        raw_frames=raw_frames,
    )
