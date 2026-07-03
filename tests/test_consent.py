"""Tests for the consent-checkbox label classifier (pure, no browser)."""

import unittest

from src.lib import consent


class TestClassifyCheckboxLabel(unittest.TestCase):
    def test_agreement(self):
        for t in [
            "I agree to the Terms of Service",
            "I have read and understood the Privacy Policy",
            # The verbatim Battle.net / Blizzard label from the failing run:
            "By checking this box, you acknowledge that you have read and "
            "understood the Blizzard Entertainment Privacy Policy",
            "I confirm I am over 18 years of age",
            "Accept the terms and conditions",
            "I consent to the processing of my data (GDPR)",
        ]:
            self.assertEqual(consent.classify_checkbox_label(t), "agree", t)

    def test_marketing(self):
        for t in [
            "Sign me up for the newsletter",
            "I'd like to receive marketing offers",
            "Send me product tips and updates",
        ]:
            self.assertEqual(consent.classify_checkbox_label(t), "marketing", t)

    def test_strong_agreement_wins_over_marketing(self):
        # Strong signal (terms) present alongside marketing -> still agree.
        t = "I agree to the Terms and would like to receive the newsletter"
        self.assertEqual(consent.classify_checkbox_label(t), "agree")

    def test_weak_agree_does_not_override_marketing(self):
        # The battle.net bug: a marketing opt-in phrased with a weak "I agree"
        # / "I accept" must stay marketing (not get ticked).
        for t in [
            "I agree to receive marketing emails and special offers",
            "Yes, I accept promotional offers and deals",
            "I agree to receive the newsletter",
        ]:
            self.assertEqual(consent.classify_checkbox_label(t), "marketing", t)

    def test_neutral(self):
        for t in ["Remember me", "Keep me signed in", "", None]:
            self.assertEqual(consent.classify_checkbox_label(t), "neutral", repr(t))


if __name__ == "__main__":
    unittest.main()
