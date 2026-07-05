"""Tests for advertised-params extraction + status-CSV projection."""

import csv
import tempfile
import unittest
from pathlib import Path

from src.lib import webauthn_params


def _create_called(options, ts="2026-07-05T10:00:00.000Z"):
    return {
        "ts": ts,
        "level": "info",
        "eventType": "create.called",
        "page": "https://example.com/settings",
        "payload": {"atMsSinceInstall": 12, "fabricate": True, "options": options},
    }


SAMPLE_OPTIONS = {
    "hasPublicKey": True,
    "rpId": "example.com",
    "rpName": "Example",
    "userIdLength": 16,
    "userName": "test@example.com",
    "userDisplayName": "Test User",
    "challengeLength": 32,
    "timeout": 60000,
    "attestation": "direct",
    "attestationFormats": ["packed", "tpm"],
    "hints": ["client-device"],
    "authenticatorAttachment": "platform",
    "residentKey": "required",
    "requireResidentKey": True,
    "userVerification": "required",
    "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
    "pubKeyCredParamsCount": 2,
    "excludeCredentialsCount": 1,
    "excludeCredentials": [],
    "allowCredentialsCount": 0,
    "allowCredentials": [],
    "extensions": ["credProps", "prf"],
}


class TestExtractAdvertised(unittest.TestCase):
    def test_per_frame_wrapper(self):
        observer_log = [{"frame_url": "https://example.com/", "entries": [_create_called(SAMPLE_OPTIONS)]}]
        rec = webauthn_params.extract_advertised(observer_log)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["rp_id_advertised"], "example.com")
        self.assertEqual(rec["attestation"], "direct")
        self.assertEqual(rec["user_verification"], "required")
        self.assertEqual(rec["resident_key"], "required")
        self.assertEqual(rec["require_resident_key"], True)
        self.assertEqual(
            [p["alg"] for p in rec["pub_key_cred_params"]], [-7, -257]
        )
        self.assertEqual(rec["extensions"], ["credProps", "prf"])
        self.assertEqual(rec["attestation_formats"], ["packed", "tpm"])

    def test_raw_entry_list(self):
        rec = webauthn_params.extract_advertised([_create_called(SAMPLE_OPTIONS)])
        self.assertEqual(rec["rp_id_advertised"], "example.com")

    def test_latest_create_wins(self):
        first = dict(SAMPLE_OPTIONS, attestation="none")
        second = dict(SAMPLE_OPTIONS, attestation="enterprise")
        observer_log = [
            _create_called(first, ts="2026-07-05T10:00:00Z"),
            _create_called(second, ts="2026-07-05T10:05:00Z"),
        ]
        rec = webauthn_params.extract_advertised(observer_log)
        self.assertEqual(rec["attestation"], "enterprise")

    def test_no_create_returns_none(self):
        observer_log = [{"eventType": "observer.installed", "payload": {}}]
        self.assertIsNone(webauthn_params.extract_advertised(observer_log))

    def test_fabrication_and_outcome(self):
        # A downgrade probe that the browser fabricated (RP acceptance is separate).
        observer_log = [
            _create_called(SAMPLE_OPTIONS),
            {"eventType": "fabrication.algSelection", "payload": {
                "fabricationAlg": "RS256", "coseAlg": -257, "algInPubKeyCredParams": False}},
            {"eventType": "fabrication.flags", "payload": {
                "op": "create", "flags": {"UP": True, "UV": True, "BE": True, "BS": False, "AT": True}}},
            {"eventType": "fabrication.success", "payload": {"rpId": "example.com"}},
        ]
        rec = webauthn_params.extract_advertised(observer_log)
        fab = rec["fabrication"]
        self.assertEqual(fab["outcome"], "fabricated")
        self.assertEqual(fab["fabrication_alg"], "RS256")
        self.assertEqual(fab["fabrication_alg_offered"], False)
        cells = webauthn_params.flatten_adv_columns(rec)
        self.assertEqual(cells["fab_alg"], "RS256(-257)")
        self.assertEqual(cells["fab_alg_offered"], "false")   # downgrade: not in offered set
        self.assertEqual(cells["fab_flags"], "UP,UV,BE,AT")
        self.assertEqual(cells["fab_outcome"], "fabricated")

    def test_outcome_create_failed(self):
        observer_log = [
            _create_called(SAMPLE_OPTIONS),
            {"eventType": "create.failed", "payload": {"error": {"name": "NotAllowedError"}}},
        ]
        rec = webauthn_params.extract_advertised(observer_log)
        self.assertEqual(webauthn_params.flatten_adv_columns(rec)["fab_outcome"], "create-failed:NotAllowedError")

    def test_server_algs_crosscheck(self):
        network = [{"kind": "response", "body": '{"publicKey":{"pubKeyCredParams":[{"type":"public-key","alg":-8}]}}'}]
        rec = webauthn_params.extract_advertised([_create_called(SAMPLE_OPTIONS)], network)
        self.assertEqual(rec["server_pub_key_algs"], [-8])


class TestFlatten(unittest.TestCase):
    def test_flatten_cells(self):
        rec = webauthn_params.extract_advertised([_create_called(SAMPLE_OPTIONS)])
        rec["captured_at"] = "2026-07-05T10:00:00+00:00"
        cells = webauthn_params.flatten_adv_columns(rec)
        self.assertEqual(cells["adv_rp_id"], "example.com")
        self.assertEqual(cells["adv_algs"], "-7|-257")
        self.assertEqual(cells["adv_attestation"], "direct")
        self.assertEqual(cells["adv_uv"], "required")
        self.assertEqual(cells["adv_require_resident_key"], "true")
        self.assertEqual(cells["adv_extensions"], "credProps,prf")
        self.assertEqual(cells["adv_attestation_formats"], "packed,tpm")
        self.assertEqual(cells["adv_captured_at"], "2026-07-05T10:00:00+00:00")
        # Every declared column is present even for a None record.
        self.assertEqual(set(webauthn_params.flatten_adv_columns(None)), set(webauthn_params.ADV_COLUMNS))


class TestUpsertStatusCsv(unittest.TestCase):
    def _write_csv(self, path):
        # Semicolon-delimited, matching data/targets_selected_status.csv.
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["canonical_origin", "etld1", "status", "notes"])
            w.writerow(["https://a.com", "a.com", "captured", "note a"])
            w.writerow(["https://example.com", "example.com", "captured", "note e"])

    def _read(self, path):
        with open(path, "r", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f, delimiter=";"))

    def test_replaces_matching_row(self):
        rec = webauthn_params.extract_advertised([_create_called(SAMPLE_OPTIONS)])
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "status.csv"
            self._write_csv(path)
            webauthn_params.upsert_status_csv("example.com", rec, path=path)
            webauthn_params.upsert_status_csv("example.com", rec, path=path)  # second: still no dup
            rows = self._read(path)
            self.assertEqual(len(rows), 2)  # no duplicate row added
            e = next(r for r in rows if r["etld1"] == "example.com")
            self.assertEqual(e["adv_algs"], "-7|-257")
            self.assertEqual(e["adv_attestation"], "direct")
            # Other row + its columns preserved.
            a = next(r for r in rows if r["etld1"] == "a.com")
            self.assertEqual(a["status"], "captured")
            self.assertEqual(a["notes"], "note a")
            self.assertEqual(a["adv_algs"], "")

    def test_appends_when_absent(self):
        rec = webauthn_params.extract_advertised([_create_called(SAMPLE_OPTIONS)])
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "status.csv"
            self._write_csv(path)
            webauthn_params.upsert_status_csv("newsite.com", rec, path=path)
            rows = self._read(path)
            self.assertEqual(len(rows), 3)
            n = next(r for r in rows if r["etld1"] == "newsite.com")
            self.assertEqual(n["adv_attestation"], "direct")
            self.assertEqual(n["canonical_origin"], "")  # blank, not crashed


if __name__ == "__main__":
    unittest.main()
