"""Tests for syncing selected targets with ledger state + last note."""

import unittest

from src import sync_selected_status_notes as sync


class TestSyncSelectedStatusNotes(unittest.TestCase):
    def test_sync_rows_uses_state_and_last_history_note(self):
        rows = [
            {"canonical_origin": "https://example.com", "etld1": "example.com"},
            {"canonical_origin": "https://missing.com", "etld1": "missing.com"},
        ]
        entries = {
            "example.com": {
                "state": "captured",
                "history": [
                    {"state": "pending", "note": "initialized"},
                    {"state": "captured", "note": "session captured"},
                ],
            }
        }

        synced, matched, missing = sync._sync_rows(rows, entries)

        self.assertEqual(matched, 1)
        self.assertEqual(missing, ["missing.com"])
        self.assertEqual(synced[0]["status"], "captured")
        self.assertEqual(synced[0]["notes"], "session captured")
        self.assertEqual(synced[1]["status"], "")
        self.assertEqual(synced[1]["notes"], "")

    def test_row_rp_id_falls_back_to_origin_host(self):
        row = {"canonical_origin": "https://www.example.com/path", "etld1": ""}
        self.assertEqual(sync._row_rp_id(row), "www.example.com")


if __name__ == "__main__":
    unittest.main()