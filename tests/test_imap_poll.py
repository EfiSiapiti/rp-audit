"""Tests for imap_poll folder sweep + relatedness fallback.

A FakeIMAPClient stands in for a live Gmail connection so we can assert:
  - verification mail in the Spam folder is found (not just INBOX),
  - an unrelated-sender email (brand/ESP domain) with a fresh code is
    accepted via the fallback path,
  - a stale unrelated email is NOT accepted.
"""

import unittest
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from unittest import mock

from src.lib import imap_poll


def _raw(from_addr: str, subject: str, body: str) -> bytes:
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["Subject"] = subject
    msg.set_content(body)
    return msg.as_bytes()


def _naive_utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


class FakeIMAPClient:
    """Minimal IMAPClient stand-in. `folders` maps name -> list of
    (uid, raw_bytes, internaldate)."""

    SPECIAL = {b"\\Junk": "[Gmail]/Spam", b"\\All": "[Gmail]/All Mail"}

    def __init__(self, folders: dict[str, list[tuple]]):
        self.folders = folders
        self.current = None

    def find_special_folder(self, flag):
        name = self.SPECIAL.get(flag)
        return name if name in self.folders else None

    def select_folder(self, name):
        if name not in self.folders:
            raise ValueError(f"no such folder: {name}")
        self.current = name

    def noop(self):
        pass

    def search(self, _arg):
        return [u for (u, _r, _d) in self.folders[self.current]]

    def fetch(self, uids, _fields):
        out = {}
        for (u, raw, dt) in self.folders[self.current]:
            if u in uids:
                out[u] = {b"RFC822": raw, b"INTERNALDATE": dt}
        return out

    def logout(self):
        pass


class TestImapPoll(unittest.TestCase):
    def _run(self, folders, rp_id, **kw):
        fake = FakeIMAPClient(folders)
        with mock.patch.object(imap_poll, "_imap_connect", return_value=fake):
            return imap_poll.find_verification(rp_id, **kw)

    def test_related_match_in_inbox(self):
        now = _naive_utc(datetime.now(timezone.utc))
        folders = {
            "INBOX": [(1, _raw("noreply@example.com", "Confirm",
                               "Your verification code is 123456"), now)],
            "[Gmail]/Spam": [], "[Gmail]/All Mail": [],
        }
        found = self._run(folders, "example.com")
        self.assertIsNotNone(found)
        self.assertEqual(found.value, "123456")

    def test_found_in_spam_folder(self):
        """Verification mail routed to Spam is still found (the billgenerator case)."""
        now = _naive_utc(datetime.now(timezone.utc))
        folders = {
            "INBOX": [],
            "[Gmail]/Spam": [(7, _raw("noreply@example.com", "Confirm",
                                      "Your verification code is 222333"), now)],
            "[Gmail]/All Mail": [],
        }
        found = self._run(folders, "example.com")
        self.assertIsNotNone(found)
        self.assertEqual(found.value, "222333")

    def test_unrelated_recent_email_accepted_as_fallback(self):
        """Brand/ESP sender that never names the RP, but a fresh code → accept
        (the braunhousehold case)."""
        now = _naive_utc(datetime.now(timezone.utc))
        folders = {
            "INBOX": [(3, _raw("noreply@some-esp.io", "Verify your email",
                               "Your verification code is 654321"), now)],
            "[Gmail]/Spam": [], "[Gmail]/All Mail": [],
        }
        found = self._run(folders, "braunhousehold.com")
        self.assertIsNotNone(found)
        self.assertEqual(found.value, "654321")

    def test_stale_unrelated_email_not_accepted(self):
        """An unrelated code email that predates the wait must NOT be grabbed."""
        stale = _naive_utc(datetime.now(timezone.utc) - timedelta(minutes=5))
        folders = {
            "INBOX": [(4, _raw("noreply@some-esp.io", "Verify your email",
                               "Your verification code is 999000"), stale)],
            "[Gmail]/Spam": [], "[Gmail]/All Mail": [],
        }
        found = self._run(folders, "braunhousehold.com",
                          timeout_seconds=0.3, poll_interval=0)
        self.assertIsNone(found)


if __name__ == "__main__":
    unittest.main()
