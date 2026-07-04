"""IMAP polling for verification emails.

Connects to Gmail (or any IMAP server) and looks for a recent email
related to the current RP. Extracts either a numeric verification code
or a verification URL.

Matching is heuristic:
- Sender domain matches rp_id (e.g. notion.so → @notion.so or @notion.com)
- OR subject/body contains the rp_id stem ("notion") or the entity name
- AND received within the last `lookback_minutes` (default 10 min)

Code extraction looks for the most common patterns: 4-8 digit standalone
numbers, "code: ABC123", "your code is XYZ", etc. URL extraction grabs
the first HTTPS link from a known "verify/confirm/activate" context.

Body preprocessing:
- Prefer text/plain alternative parts when present (cleanest source).
- For text/html, strip <style> and <script> blocks ENTIRELY before
  tag-stripping, so CSS hex values and JS literals don't end up
  matching as verification codes.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from typing import Iterator

from imapclient import IMAPClient


@dataclass
class FoundVerification:
    method: str               # "code" or "link"
    value: str                # the digits or the URL
    sender: str
    subject: str
    received_at: str          # ISO timestamp
    raw_excerpt: str          # ~300 chars of body, for the agent to sanity-check


# --- email parsing -------------------------------------------------------

def _decode_header(raw: str | None) -> str:
    """Decode a possibly MIME-encoded header (=?UTF-8?B?...?=) to plain text.

    Subjects from non-English RPs (e.g. 日経ID / Nikkei) arrive encoded; without
    decoding, neither code extraction nor the rp-relation check can read them.
    """
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return str(raw)


def _clean_html_to_text(html: str) -> str:
    """Strip HTML to plain text, removing CSS/JS contents (not just tags).

    Crude tag removal alone leaves the contents of <style> and <script>
    blocks behind, which means CSS values and JS literals leak into the
    body text and can match as verification codes.
    """
    html = re.sub(r"<style\b[^>]*>.*?</style>", " ", html, flags=re.I | re.S)
    html = re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.I | re.S)
    html = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    html = re.sub(r"<[^>]+>", " ", html)
    html = (html.replace("&nbsp;", " ")
                .replace("&amp;", "&")
                .replace("&#39;", "'")
                .replace("&quot;", '"'))
    return html


def _get_part_text(part: Message) -> str | None:
    ctype = part.get_content_type()
    if ctype not in ("text/plain", "text/html"):
        return None
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return None
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        if ctype == "text/html":
            text = _clean_html_to_text(text)
        return text
    except Exception:
        return None


def _walk_text_parts(msg: Message) -> Iterator[str]:
    """Yield text from every text/plain and text/html part."""
    for part in msg.walk():
        text = _get_part_text(part)
        if text:
            yield text


def _get_preferred_body(msg: Message) -> str:
    """Return the cleanest available body for code/link extraction.

    Preference order:
    1. All text/plain parts concatenated.
    2. Fall back to text/html parts (with style/script stripped).
    """
    plain_parts = []
    html_parts = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "text/plain":
            t = _get_part_text(part)
            if t:
                plain_parts.append(t)
        elif ctype == "text/html":
            t = _get_part_text(part)
            if t:
                html_parts.append(t)

    if plain_parts:
        return "\n".join(plain_parts)
    return "\n".join(html_parts)


# High-precision, labeled patterns — safe to run against the subject line too.
_LABELED_CODE_PATTERNS = [
    r"(?:verification|confirmation|security|access|login|sign[\s-]?in|one[\s-]?time)\s+code(?:\s+is)?[:\s]*([0-9]{4,8})",
    r"\b([0-9]{4,8})\s+is\s+your\s+(?:verification|confirmation|security|login|sign[\s-]?in|one[\s-]?time)\s+code\b",
    r"\b[Cc]ode[:\s]+([0-9]{4,8})\b",
    r"\b([0-9]{4,8})\b\s*(?:to\s+(?:verify|confirm|continue|sign))",
    r"\benter\s+(?:the\s+)?(?:code\s+)?([0-9]{4,8})\b",
]


def _extract_code(body: str, subject: str = "") -> str | None:
    """Find a likely verification code.

    Checks the subject FIRST with the labeled patterns — many providers put the
    code right in it ("Sign in to Indeed with code: 958619"), and the subject is
    far less noisy than the body, so this avoids the greedy body fallbacks
    grabbing an unrelated number (zip codes, order numbers, years).
    """
    for text in (subject, body):
        if not text:
            continue
        for pat in _LABELED_CODE_PATTERNS:
            m = re.search(pat, text, flags=re.I)
            if m:
                return m.group(1)

    # Body-only fallbacks — loose, so never run against the subject.
    # 4-8 digit code alone on a line (handles line breaks / whitespace).
    m = re.search(r"(?:^|\s)\s*([0-9]{4,8})\s+(?:\n|$)", body, flags=re.M)
    if m:
        return m.group(1)

    # Last resort: a 6-digit code anywhere with surrounding whitespace.
    m = re.search(r"\s([0-9]{6})\s", body)
    if m:
        return m.group(1)

    return None


def _extract_link(body: str, rp_id_stem: str) -> str | None:
    """Find a likely verification URL."""
    url_pat = r"https?://[^\s<>\"']+"
    urls = re.findall(url_pat, body)
    if not urls:
        return None

    keywords = re.compile(
        r"verify|confirm|activate|complete\s+your\s+signup|set\s+up\s+your\s+account",
        re.I,
    )
    asset_penalty = re.compile(
        r"fonts\.googleapis|fonts\.gstatic|cdn|googletagmanager|"
        r"\.(?:png|jpe?g|gif|svg|css|woff2?|ttf|eot|ico)(?:[?#]|$)|"
        r"unsubscribe|preferences|view.*browser|privacy|terms",
        re.I,
    )
    rp_keywords = re.compile(r"verify|confirm|activate|auth|token|magic", re.I)

    best, best_score = None, -1
    for u in urls:
        idx = body.find(u)
        score = 0
        window = body[max(0, idx - 200):idx + 200]
        if keywords.search(window):
            score += 10
        if rp_id_stem in u.lower():
            score += 5
        if rp_keywords.search(u):
            score += 3
        if asset_penalty.search(u):
            score -= 50
        if score > best_score:
            best, best_score = u, score

    return best if best and best_score > 0 else None


def _is_related_to_rp(msg: Message, rp_id: str) -> bool:
    """Heuristic: does this email look like it's from/about the RP?"""
    stem = rp_id.split(".")[0].lower()  # "ameblo.jp" -> "ameblo"
    # Match stems: the bare stem, plus a hand-added alias for the one RP whose
    # mail domain differs from its stem (ameblo.jp sends from ameba.jp). The old
    # code ran stem.replace("lo","") for *every* RP, which produced junk match
    # strings (lowes -> "wes", roblox -> "robx") that matched unrelated mail.
    stems = [stem]
    if stem == "ameblo":
        stems.append("ameba")

    sender = _decode_header(msg.get("From")).lower()
    subject = _decode_header(msg.get("Subject")).lower()

    # Extract domain from sender email (e.g., "info@auth.user.ameba.jp" -> "ameba.jp")
    sender_domain = None
    if "@" in sender:
        sender_domain = sender.split("@", 1)[1].strip(">").lower()

    # Check if sender domain is related to RP (match base domain)
    # e.g., "ameblo.jp" and "ameba.jp" are related, "ameba.jp" and "auth.user.ameba.jp" are related
    if sender_domain:
        # Extract base domain (last two components of sender)
        sender_parts = sender_domain.split(".")
        sender_base = ".".join(sender_parts[-2:]) if len(sender_parts) >= 2 else sender_domain
        
        # Check if stem appears in sender domain at all (covers ameba/ameblo variations)
        if any(s in sender_domain for s in stems):
            return True
        
        # Check if base domains match
        rp_base = ".".join(rp_id.split(".")[-2:])
        if sender_base == rp_base:
            return True

    # Check subject and body
    if any(s in subject for s in stems):
        return True
    
    for body in _walk_text_parts(msg):
        body_lower = body.lower()
        if any(s in body_lower for s in stems):
            return True
    
    return False


# --- IMAP search ---------------------------------------------------------

def _imap_connect() -> IMAPClient:
    host = os.environ.get("IMAP_HOST", "imap.gmail.com")
    port = int(os.environ.get("IMAP_PORT", "993"))
    user = os.environ.get("IMAP_USER")
    pw = os.environ.get("IMAP_PASS")
    if not user or not pw:
        raise RuntimeError("IMAP_USER / IMAP_PASS not set in .env")
    client = IMAPClient(host, port=port, ssl=True)
    client.login(user, pw)
    return client


def _verification_folders(client: IMAPClient) -> list[str]:
    """Folders to sweep for verification mail.

    Gmail routes transactional mail to Spam often enough that INBOX-only
    polling silently loses verification emails. "All Mail" covers
    Inbox + Promotions + archived mail; Spam/Trash are separate, hence the
    explicit Junk folder. Resolve via special-use flags (not hardcoded
    English names) so non-English Gmail accounts work too.
    """
    folders = ["INBOX"]
    for flag in (b"\\Junk", b"\\All"):
        try:
            name = client.find_special_folder(flag)
        except Exception:
            name = None
        if name and name not in folders:
            folders.append(name)
    return folders


def find_verification(
    rp_id: str,
    *,
    timeout_seconds: int = 120,
    poll_interval: int = 5,
    lookback_minutes: int = 10,
    newer_than_seconds: int | None = None,
    exclude_values: list[str] | None = None,
) -> FoundVerification | None:
    """Poll IMAP until we find a verification email for this RP, or timeout.

    When multiple matching emails exist (e.g. user clicked Resend), the
    NEWEST one wins.

    `newer_than_seconds`: if set, only consider emails received within
    the last N seconds.

    `exclude_values`: if set, skip emails whose extracted code/link
    matches any value in this list. Use AFTER a Resend to skip the
    already-rejected code.
    """
    stem = rp_id.split(".")[0].lower()
    run_start = datetime.now(timezone.utc)
    deadline = time.time() + timeout_seconds
    since_dt = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    min_received_dt = (
        datetime.now(timezone.utc) - timedelta(seconds=newer_than_seconds)
        if newer_than_seconds else None
    )
    # Unrelated mail is only trusted as a fallback if it arrived after we
    # started waiting — the verification email is triggered by the signup
    # submit that just happened. 60s grace covers client/server clock skew.
    fallback_floor = run_start - timedelta(seconds=60)
    excluded = set(exclude_values or [])

    def _build(msg: Message, internal) -> FoundVerification | None:
        """Extract a code/link from msg, honoring the date + exclude filters."""
        if internal and internal.replace(tzinfo=timezone.utc) < since_dt:
            return None
        if (min_received_dt and internal and
                internal.replace(tzinfo=timezone.utc) < min_received_dt):
            return None
        subject = _decode_header(msg.get("Subject"))
        body = _get_preferred_body(msg)
        code = _extract_code(body, subject)
        link = _extract_link(body, stem)
        if not code and not link:
            return None
        if code and code in excluded:
            return None
        if link and link in excluded:
            return None
        received_iso = (
            internal.replace(tzinfo=timezone.utc).isoformat()
            if internal else datetime.now(timezone.utc).isoformat()
        )
        excerpt = re.sub(r"\s+", " ", body).strip()[:300]
        method, value = ("code", code) if code else ("link", link or "")
        return FoundVerification(
            method=method, value=value,
            sender=(msg.get("From") or "").strip(),
            subject=subject.strip(),
            received_at=received_iso, raw_excerpt=excerpt,
        )

    client = _imap_connect()
    try:
        folders = _verification_folders(client)
        # seen is keyed by (folder, uid) — UIDs are only unique within a folder.
        seen: set[tuple[str, int]] = set()
        search_arg = ["SINCE", since_dt.strftime("%d-%b-%Y")]
        while time.time() < deadline:
            # Best (related) match wins immediately; otherwise the newest
            # recent code/link-bearing email is kept as a fallback.
            fallback: FoundVerification | None = None
            for folder in folders:
                try:
                    client.select_folder(folder)
                except Exception:
                    continue
                # CRITICAL: NOOP forces Gmail to surface mail that arrived
                # since the last poll. Without it, client.search() returns
                # the same UIDs it saw at select time and new emails are
                # invisible until reselect.
                try:
                    client.noop()
                except Exception:
                    pass

                uids = client.search(search_arg)
                new_uids = [u for u in uids if (folder, u) not in seen]
                if not new_uids:
                    continue
                # Newest first — first match wins, so Resend > original.
                new_uids.sort(reverse=True)
                fetched = client.fetch(new_uids, ["RFC822", "INTERNALDATE"])
                for uid in new_uids:
                    seen.add((folder, uid))
                    item = fetched.get(uid)
                    if not item:
                        continue
                    internal = item.get(b"INTERNALDATE")
                    msg = message_from_bytes(item[b"RFC822"])
                    found = _build(msg, internal)
                    if not found:
                        continue
                    if _is_related_to_rp(msg, rp_id):
                        # Sender/subject/body match the RP — strongest signal.
                        return found
                    # Unrelated sender (e.g. a brand/ESP domain): trust it only
                    # if it arrived after we started waiting. Keep the newest.
                    if (fallback is None and internal and
                            internal.replace(tzinfo=timezone.utc) >= fallback_floor):
                        fallback = found
            if fallback is not None:
                return fallback
            time.sleep(poll_interval)
        return None
    finally:
        try:
            client.logout()
        except Exception:
            pass