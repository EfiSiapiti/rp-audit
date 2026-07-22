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

    def test_since_filter_ignores_stale_cross_run_ceremony(self):
        # chrome.storage accumulates: a stale meta ceremony + this run's nintendo one.
        stale = dict(SAMPLE_OPTIONS, rpId="accounts.meta.com")
        fresh = dict(SAMPLE_OPTIONS, rpId="accounts.nintendo.com")
        observer_log = [
            _create_called(stale, ts="2026-07-05T14:00:00Z"),
            _create_called(fresh, ts="2026-07-06T08:36:07Z"),
        ]
        # No since: still picks the chronologically-latest (nintendo), not list order.
        self.assertEqual(
            webauthn_params.extract_advertised(observer_log)["rp_id_advertised"],
            "accounts.nintendo.com")
        # since inside this run's window: the stale meta ceremony is excluded.
        rec = webauthn_params.extract_advertised(observer_log, since_iso="2026-07-06T08:34:00Z")
        self.assertEqual(rec["rp_id_advertised"], "accounts.nintendo.com")
        # since after everything → nothing in window → None.
        self.assertIsNone(
            webauthn_params.extract_advertised(observer_log, since_iso="2026-07-06T09:00:00Z"))

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
        cells = webauthn_params.flatten_experiment_columns(rec, rp_id="example.com", label="alg-downgrade")
        self.assertEqual(cells["label"], "alg-downgrade")
        self.assertEqual(cells["rp_id"], "example.com")
        self.assertEqual(cells["adv_attestation"], "direct")   # advertised context in the row
        self.assertEqual(cells["adv_algs"], "-7|-257")
        self.assertEqual(cells["fab_alg"], "RS256(-257)")
        self.assertEqual(cells["fab_alg_offered"], "false")   # downgrade: not in offered set
        self.assertEqual(cells["fab_flags"], "UP,UV,BE,AT")
        self.assertEqual(cells["fab_outcome"], "fabricated")

    def test_fabrication_leaked_key(self):
        # Leaked-key control (key-test): the hook injects a publicly-known private
        # key. fabrication.algSelection carries keySource="leaked" + leakOrigin,
        # which surface as fab_key_source / fab_key_leak_origin in the experiment row.
        observer_log = [
            _create_called(SAMPLE_OPTIONS),
            {"eventType": "fabrication.algSelection", "payload": {
                "fabricationAlg": "ES256", "coseAlg": -7, "algInPubKeyCredParams": True,
                "keySource": "leaked", "keyCurve": "P-256",
                "leakOrigin": "google/keytransparency#1530"}},
            {"eventType": "fabrication.flags", "payload": {
                "op": "create", "flags": {"UP": True, "UV": True, "AT": True}}},
            {"eventType": "fabrication.success", "payload": {"rpId": "example.com"}},
        ]
        rec = webauthn_params.extract_advertised(observer_log)
        fab = rec["fabrication"]
        self.assertEqual(fab["fabrication_key_source"], "leaked")
        self.assertEqual(fab["fabrication_key_leak_origin"], "google/keytransparency#1530")
        cells = webauthn_params.flatten_experiment_columns(rec, rp_id="example.com", label="leaked-key-test")
        self.assertEqual(cells["label"], "leaked-key-test")
        self.assertEqual(cells["fab_alg"], "ES256(-7)")
        self.assertEqual(cells["fab_key_source"], "leaked")
        self.assertEqual(cells["fab_key_leak_origin"], "google/keytransparency#1530")
        self.assertEqual(cells["fab_rsa_e"], "")       # blank: not an RSA run
        self.assertEqual(cells["fab_outcome"], "fabricated")

    def test_fabrication_weak_scalar(self):
        # Weak-scalar control (weak-scalar-test): the hook presents an ES256 key
        # whose private scalar is a small known value d (public key Q=d*G).
        # fabrication.algSelection carries weakScalarD, which surfaces as
        # fab_ec_scalar in the experiment row. The key is a conformant P-256 key,
        # so fab_alg stays ES256 and the RSA/leaked cells stay blank.
        observer_log = [
            _create_called(SAMPLE_OPTIONS),
            {"eventType": "fabrication.algSelection", "payload": {
                "fabricationAlg": "ES256", "coseAlg": -7, "algInPubKeyCredParams": True,
                "weakScalarD": 2}},
            {"eventType": "fabrication.flags", "payload": {
                "op": "create", "flags": {"UP": True, "UV": True, "AT": True}}},
            {"eventType": "fabrication.success", "payload": {"rpId": "example.com"}},
        ]
        rec = webauthn_params.extract_advertised(observer_log)
        fab = rec["fabrication"]
        self.assertEqual(fab["fabrication_ec_scalar"], 2)
        cells = webauthn_params.flatten_experiment_columns(rec, rp_id="example.com", label="weak-scalar-test")
        self.assertEqual(cells["label"], "weak-scalar-test")
        self.assertEqual(cells["fab_alg"], "ES256(-7)")
        self.assertEqual(cells["fab_ec_scalar"], "2")
        self.assertEqual(cells["fab_rsa_e"], "")        # blank: not an RSA run
        self.assertEqual(cells["fab_key_source"], "")   # blank: not a leaked-key run
        self.assertEqual(cells["fab_outcome"], "fabricated")

    def test_outcome_create_failed(self):
        observer_log = [
            _create_called(SAMPLE_OPTIONS),
            {"eventType": "create.failed", "payload": {"error": {"name": "NotAllowedError"}}},
        ]
        rec = webauthn_params.extract_advertised(observer_log)
        cells = webauthn_params.flatten_experiment_columns(rec, rp_id="example.com")
        self.assertEqual(cells["fab_outcome"], "create-failed:NotAllowedError")

    def test_server_algs_crosscheck(self):
        network = [{"kind": "response", "body": '{"publicKey":{"pubKeyCredParams":[{"type":"public-key","alg":-8}]}}'}]
        rec = webauthn_params.extract_advertised([_create_called(SAMPLE_OPTIONS)], network)
        self.assertEqual(rec["server_pub_key_algs"], [-8])

    def test_server_verdict_from_finish(self):
        # A finish POST carrying the credId, and its error response.
        observer_log = [
            _create_called(SAMPLE_OPTIONS),
            {"eventType": "fabrication.success", "payload": {"credId": "ABC123cred"}},
        ]
        network = {
            "requests": [
                {"method": "POST", "url": "https://rp.example/api/graphql/",
                 "post_data": 'variables={"rawId":"ABC123cred","attestationObject":"..."}',
                 "ts": "20260705T100000Z"},
            ],
            "responses": [
                {"url": "https://rp.example/api/graphql/", "status": 200,
                 "body": '{"errors":[{"message":"Invalid attestation: AAGUID mismatch"}]}',
                 "ts": "20260705T100001Z"},
            ],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        srv = rec["server"]
        self.assertEqual(srv["endpoint"], "/api/graphql/")
        self.assertEqual(srv["status"], 200)
        self.assertEqual(srv["result"], "rejected?")  # 200 but error body
        self.assertIn("AAGUID mismatch", srv["message"])
        cells = webauthn_params.flatten_experiment_columns(rec, rp_id="example.com")
        self.assertEqual(cells["srv_status"], "200")
        self.assertEqual(cells["srv_result"], "rejected?")
        self.assertIn("AAGUID mismatch", cells["srv_message"])

    def test_server_verdict_accepted(self):
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": "XYZ"}}]
        network = {
            "requests": [{"method": "POST", "url": "https://rp/finish",
                          "post_data": '{"rawId":"XYZ"}', "ts": "20260705T100000Z"}],
            "responses": [{"url": "https://rp/finish", "status": 200,
                           "body": '{"status":"ok","verified":true}', "ts": "20260705T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")  # verified:true → confident accept

    def test_server_verdict_meta_style(self):
        # Meta: credential_id + base64 payload, XSSI prefix, success:true, all same URL.
        observer_log = [
            _create_called(SAMPLE_OPTIONS),
            {"eventType": "fabrication.success", "payload": {"credId": "EUOi6ty1cred"}},
        ]
        url = "https://accountscenter.facebook.com/api/graphql/"
        network = {
            "requests": [
                {"method": "POST", "url": url, "post_data": "fb_api_req_friendly_name=OtherMutation&variables={}", "ts": "20260705T100000Z"},
                {"method": "POST", "url": url,
                 "post_data": 'fb_api_req_friendly_name=useCreatePasskeyMutation&variables={"credential_id":"EUOi6ty1cred","payload":"eyJ..."}',
                 "ts": "20260705T100001Z"},
            ],
            "responses": [
                {"url": url, "status": 200, "body": '{"data":{"other":1}}', "ts": "20260705T100000Z"},
                {"url": url, "status": 200, "body": 'for (;;);{"data":{"xfb_fx_settings_create_passkey":{"success":true}}}', "ts": "20260705T100001Z"},
            ],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        srv = rec["server"]
        self.assertIn("useCreatePasskeyMutation", srv["endpoint"])   # friendly name surfaced
        self.assertEqual(srv["result"], "accepted")                 # success:true past the XSSI prefix
        self.assertNotIn("for (;;);", srv["message"])               # prefix stripped

    def test_finish_matcher_skips_error_reporting(self):
        # A Sentry error-report POST echoes the credential in its payload but must
        # NOT be treated as the finish (its 204 would otherwise look like success).
        cred = "dcCred1"
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": cred}}]
        network = {
            "requests": [{"method": "POST", "url": "https://discord.com/error-reporting-proxy/web",
                          "post_data": "...attestationObject...%s..." % cred, "ts": "20260706T100000Z"}],
            "responses": [{"url": "https://discord.com/error-reporting-proxy/web",
                           "status": 204, "body": "", "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        # No real finish endpoint → fabricated-but-not-submitted, not "accepted".
        self.assertEqual(rec["server"]["result"], "not-captured")

    def test_server_verdict_not_captured(self):
        # Browser fabricated a credential, but the finish request never made it
        # into the network capture (run.py not attached to the ceremony tab).
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": "ABC"}}]
        network = {"requests": [{"method": "POST", "url": "https://discord/api/v9/science",
                                 "post_data": "{}", "ts": "20260706T100000Z"}],
                   "responses": []}
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "not-captured")

    def test_server_verdict_status_success(self):
        # X/Twitter signals acceptance with "status":"success" (not "success":true),
        # and its large response also contains a stray "error" substring.
        cred = "xComCred123"
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": cred}}]
        body = ('{"flow_token":"u;123","status":"success","subtasks":[{"subtask_id":'
                '"PasskeyEnrollmentCompleteSubtask"}],"error_message":null}')
        network = {
            "requests": [{"method": "POST", "url": "https://x.com/1.1/onboarding/task.json",
                          "post_data": '{"credential_id":"%s"}' % cred, "ts": "20260706T100000Z"}],
            "responses": [{"url": "https://x.com/1.1/onboarding/task.json", "status": 200,
                           "body": body, "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")  # status:success wins over stray "error"

    def test_server_verdict_201_echo_beats_error_substring(self):
        # GitHub: multipart finish → 201, body is large options that echo our
        # credId AND contain a stray error-ish substring ("must be"). The echo
        # (proof of storage) must outrank the weak error heuristic.
        cred = "ghCred789xyz"
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": cred}}]
        body = ('{"webauthn_register_request":{"publicKey":{"rp":{"id":"github.com"}}},'
                '"registered_credential_id":"%s","hint":"key name must be unique"}') % cred
        network = {
            "requests": [{"method": "POST", "url": "https://github.com/u2f/trusted_devices",
                          "post_data": "------WebKitFormBoundary...%s..." % cred, "ts": "20260706T100000Z"}],
            "responses": [{"url": "https://github.com/u2f/trusted_devices", "status": 201,
                           "body": body, "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")

    def test_server_verdict_negated_error_is_accepted(self):
        # Pixiv: 200 with "error":false, empty "errors":[], and a stored
        # credentialRecord — a naive "error"/"errors" substring must NOT flag it.
        cred = "pixivCred1"
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": cred}}]
        body = ('{"error":false,"message":"","reauthenticationRequired":false,'
                '"body":{"credentialRecord":{"id":1147177,"nickname":"Windows Hello"},"errors":[]}}')
        network = {
            "requests": [{"method": "POST", "url": "https://accounts.pixiv.net/ajax/passkeys/create/verify",
                          "post_data": '{"credential_id":"%s"}' % cred, "ts": "20260706T100000Z"}],
            "responses": [{"url": "https://accounts.pixiv.net/ajax/passkeys/create/verify",
                           "status": 200, "body": body, "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")

    def test_server_verdict_2xx_nonempty_no_error_is_accepted(self):
        # Dropbox: finish → 200 with a device confirmation body, no error, no
        # generic success keyword, no credId echo. 2xx + no error = accepted.
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": "dbxCred"}}]
        body = ('{"serialized_device_gid":"pid_2fadevice:AFALrf3A",'
                '"vendor":"Windows Hello Hardware Authenticator"}')
        network = {
            "requests": [{"method": "POST", "url": "https://www.dropbox.com/2/catapult/passkeys/finish_registration",
                          "post_data": '{"credential_id":"dbxCred"}', "ts": "20260706T100000Z"}],
            "responses": [{"url": "https://www.dropbox.com/2/catapult/passkeys/finish_registration",
                           "status": 200, "body": body, "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")

    def test_server_verdict_empty_2xx_is_accepted(self):
        # Indeed: finish POST → 200 with an empty body = success, nothing to report.
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": "indeedCred"}}]
        network = {
            "requests": [{"method": "POST", "url": "https://secure.indeed.com/webauthn/register/complete",
                          "post_data": '{"credential_id":"indeedCred"}', "ts": "20260706T100000Z"}],
            "responses": [{"url": "https://secure.indeed.com/webauthn/register/complete",
                           "status": 200, "body": "", "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")

    def test_server_verdict_empty_object_2xx_is_accepted(self):
        # Ticketmaster: finish → 200 with body "{}" (trivially empty = success).
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": "tmCred"}}]
        network = {
            "requests": [{"method": "POST", "url": "https://ticketmaster.com/account/json/passkey/register/complete",
                          "post_data": '{"credential_id":"tmCred"}', "ts": "20260706T100000Z"}],
            "responses": [{"url": "https://ticketmaster.com/account/json/passkey/register/complete",
                           "status": 200, "body": "{}", "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")

    def test_server_verdict_enabled_webauthn_credential(self):
        # Salesforce VaaS (Heroku): finish sends attestation under data.attestation
        # with type webauthn.create; response is a credential record status:enabled
        # (Salesforce mints its own id, so our credId is never echoed).
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": "hkCred"}}]
        network = {
            "requests": [{"method": "POST",
                          "url": "https://vaas.salesforce.com/vaas/v1/resources/identity-verifiers/abc",
                          "post_data": '{"type":"webauthn.cross-platform","data":{"type":"webauthn.create","attestation":"o2Nm.."}}',
                          "ts": "20260706T100000Z"}],
            "responses": [{"url": "https://vaas.salesforce.com/vaas/v1/resources/identity-verifiers/abc",
                           "status": 200,
                           "body": '{"id":"abc","display_name":"Security Key #1","type":"webauthn.cross-platform","status":"enabled"}',
                           "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")

    def test_server_verdict_redirect_to_success_url(self):
        # Auth0 (trustworthy): finish POST → 302, then a redirect to
        # /u/mfa-webauthn-enrollment-success. The success URL is the accept signal.
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": "twCred"}}]
        network = {
            "requests": [
                {"method": "POST", "url": "https://trustworthy.com/u/mfa-webauthn-enrollment",
                 "post_data": '{"credential_id":"twCred"}', "ts": "20260706T100000Z"},
                {"method": "GET", "url": "https://trustworthy.com/u/mfa-webauthn-enrollment-success",
                 "post_data": "", "ts": "20260706T100001Z"},
            ],
            "responses": [{"url": "https://trustworthy.com/u/mfa-webauthn-enrollment",
                           "status": 302, "body": "", "ts": "20260706T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")

    def test_server_verdict_echo_without_finish_request(self):
        # Google batchexecute: no matchable finish POST (opaque f.req blob), but a
        # response echoes the credId → still accepted (proof works without a finish).
        cred = "gCred1echo"
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": cred}}]
        network = {
            "requests": [{"method": "POST",
                          "url": "https://myaccount.google.com/_/AccountSettingsStrongauthUi/data/batchexecute",
                          "post_data": "f.req=%5B%5Bopaque-base64-blob%5D%5D", "ts": "20260707T100000Z"}],
            "responses": [{"url": "https://myaccount.google.com/_/AccountSettingsStrongauthUi/data/batchexecute",
                           "status": 200, "body": '[["wrb.fr",null,"[null,\\"%s\\",null]"]]' % cred,
                           "ts": "20260707T100000Z"}],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        self.assertEqual(rec["server"]["result"], "accepted")

    def test_fabrication_reused_outcome(self):
        # Control 3: fabrication.reuseCredential (+ the fabrication.success it triggers)
        # marks the run as reused, distinguishing re-register runs from fresh ones.
        observer_log = [
            _create_called(SAMPLE_OPTIONS),
            {"eventType": "fabrication.reuseCredential", "payload": {"credId": "reCred", "note": "reuse"}},
            {"eventType": "fabrication.success", "payload": {"credId": "reCred"}},
        ]
        rec = webauthn_params.extract_advertised(observer_log)
        self.assertEqual(rec["fabrication"]["outcome"], "reused")
        cells = webauthn_params.flatten_experiment_columns(rec, rp_id="rp.com", label="revoked-reregister")
        self.assertEqual(cells["fab_outcome"], "reused")

    def test_server_verdict_credid_echo(self):
        # Canva-style: finish response empty (→ accepted?), but a later profile
        # query echoes the fabricated credId → confident "accepted".
        cred = "w37nkCKa80KvCanvaCred"
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": cred}}]
        network = {
            "requests": [
                {"method": "POST", "url": "https://canva/finish",
                 "post_data": '{"credential_id":"%s"}' % cred, "ts": "20260706T100000Z"},
            ],
            "responses": [
                {"url": "https://canva/finish", "status": 200, "body": "", "ts": "20260706T100000Z"},
                {"url": "https://canva/_ajax/profile", "status": 200,
                 "body": '{"webauthnCredentials":[{"A":"%s","C":"08987058-..."}],"verified":true}' % cred,
                 "ts": "20260706T100002Z"},
            ],
        }
        rec = webauthn_params.extract_advertised(observer_log, network)
        srv = rec["server"]
        self.assertEqual(srv["result"], "accepted")           # upgraded from accepted? by the echo
        self.assertIn("webauthnCredentials", srv["message"])  # evidence body used when finish empty


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
        self.assertEqual(cells["adv_attestation_formats"], "packed,tpm")
        # Removed columns must not reappear in the projection.
        self.assertNotIn("adv_extensions", cells)
        self.assertNotIn("adv_hints", cells)
        self.assertNotIn("adv_algs_server", cells)
        # fab_*/srv_* now belong to the experiment log, not the advertised sheet.
        self.assertNotIn("fab_alg", cells)
        self.assertNotIn("srv_result", cells)
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


class TestAppendExperiment(unittest.TestCase):
    def _rec(self, credid="XYZ"):
        observer_log = [_create_called(SAMPLE_OPTIONS),
                        {"eventType": "fabrication.success", "payload": {"credId": credid}}]
        network = {
            "requests": [{"method": "POST", "url": "https://rp/finish",
                          "post_data": '{"rawId":"%s"}' % credid, "ts": "20260705T100000Z"}],
            "responses": [{"url": "https://rp/finish", "status": 200,
                           "body": '{"verified":true}', "ts": "20260705T100000Z"}],
        }
        return webauthn_params.extract_advertised(observer_log, network)

    def test_header_written_once_then_appends(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "experiments.csv"
            rec = self._rec()
            r1 = webauthn_params.flatten_experiment_columns(rec, rp_id="rp.com", label="ctrl-a", artifact="art/1")
            r2 = webauthn_params.flatten_experiment_columns(rec, rp_id="rp.com", label="ctrl-b", artifact="art/2")
            webauthn_params.append_experiment(r1, path=path)
            webauthn_params.append_experiment(r2, path=path)

            with open(path, encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f, delimiter=";"))
            # Two data rows appended (not overwritten), single header.
            self.assertEqual(len(rows), 2)
            self.assertEqual([r["label"] for r in rows], ["ctrl-a", "ctrl-b"])
            self.assertEqual(rows[0]["rp_id"], "rp.com")
            self.assertEqual(rows[0]["srv_result"], "accepted")
            self.assertEqual(rows[0]["artifact"], "art/1")
            # Header line appears exactly once.
            self.assertEqual(path.read_text(encoding="utf-8").count("captured_at;rp_id;label"), 1)


if __name__ == "__main__":
    unittest.main()
