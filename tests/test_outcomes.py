"""Tests for outcome classification (terminal vs retryable vs exhausted)."""

import unittest

from src.lib import outcomes


class TestOutcomes(unittest.TestCase):
    def test_success(self):
        self.assertEqual(outcomes.classify("captured", "", 1), "success")

    def test_terminal_states(self):
        for st in ["phone-gated", "geo-blocked", "requires-existing-account",
                   "duplicate-account", "captcha-blocked", "no-portal", "dns-dead"]:
            self.assertEqual(outcomes.classify(st, "", 1), "terminal", st)

    def test_failed_transient_is_retry(self):
        self.assertEqual(outcomes.classify("failed", "turn budget exceeded", 1), "retry")
        self.assertEqual(outcomes.classify("failed", "email verification required but IMAP found nothing", 1), "retry")
        self.assertEqual(outcomes.classify("failed", "consent dialog iframe blocks interaction", 1), "retry")

    def test_failed_permanent_is_terminal(self):
        self.assertEqual(outcomes.classify("failed", "ERR_NAME_NOT_RESOLVED", 1), "terminal")
        self.assertEqual(outcomes.classify("failed", "phone number required", 1), "terminal")
        self.assertEqual(outcomes.classify("failed", "signup form not found at provided URL", 1), "terminal")

    def test_bare_failed_defaults_retry(self):
        self.assertEqual(outcomes.classify("failed", "", 0), "retry")

    def test_attempt_cap_exhausted(self):
        # afternic.com: 12 attempts -> exhausted, not an endless retry.
        self.assertEqual(outcomes.classify("failed", "username validation error", 12), "exhausted")
        self.assertEqual(outcomes.classify("failed", "turn budget", 3), "exhausted")
        self.assertEqual(outcomes.classify("failed", "turn budget", 2), "retry")

    def test_temporarily_blocked_is_terminal(self):
        self.assertEqual(outcomes.classify("failed", "Account is temporarily blocked", 1), "terminal")

    def test_legacy_unknown_states_are_terminal(self):
        for st in ["in-progress", "needs-review", "subdomain-suspect", "enroll-failed", "weird"]:
            self.assertEqual(outcomes.classify(st, "", 0), "terminal", st)

    def test_pending_and_redo_are_retry(self):
        self.assertEqual(outcomes.classify("pending", "", 0), "retry")
        self.assertEqual(outcomes.classify("redo", "", 0), "retry")

    def test_helpers(self):
        self.assertTrue(outcomes.is_retryable("failed", "turn budget"))
        self.assertFalse(outcomes.is_retryable("phone-gated"))
        self.assertTrue(outcomes.is_terminal("phone-gated"))
        self.assertFalse(outcomes.is_terminal("failed", "turn budget"))


if __name__ == "__main__":
    unittest.main()
