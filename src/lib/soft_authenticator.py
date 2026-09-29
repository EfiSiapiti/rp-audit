"""A software WebAuthn authenticator, in Python — the HTTP-audit port of hook.js.

hook.js fabricates a spec-conformant fmt:"none" attestation signed with ES256
(ECDSA P-256, COSE alg -7) inside the browser by overriding
navigator.credentials.create/get. The pure-HTTP audit has no browser, so this
reproduces the same wire output in Python: given the RP's creation/request
options, it builds the exact clientDataJSON / attestationObject / assertion the
browser would have POSTed to the finish endpoint.

This is the ES256 fmt:"none" baseline (matches the checked-out hook.js). The
fab_* controls (alg downgrade, weak RSA, leaked key, weak scalar) live on other
pwned-xploit branches and become parameters/subclasses here later.

Only `cryptography` is used (already a dependency). CBOR is a direct port of
hook.js's minimal encoder; ECDSA-DER comes free from `cryptography` (WebCrypto
returned raw P1363, which hook.js had to convert — we don't).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

COSE_ES256 = -7
AAGUID = b"\x00" * 16          # spec mandates all-zero AAGUID for fmt:"none"
# authenticator-data flags: UP (0x01) + UV (0x04); AT (0x40) on create only.
FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40


# ---------------------------------------------------------------------------
# minimal CBOR encoder (RFC 8949) — port of hook.js cborEncode
# ---------------------------------------------------------------------------

def _cbor_head(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) | length])
    if length < 256:
        return bytes([(major << 5) | 24, length])
    if length < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", length)
    if length < 2**32:
        return bytes([(major << 5) | 26]) + struct.pack(">I", length)
    raise ValueError("cbor: length too large")


def cbor_encode(value) -> bytes:
    if isinstance(value, bool):
        raise TypeError("cbor: bool not supported here")
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head(0, value)
        return _cbor_head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _cbor_head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        b = value.encode("utf-8")
        return _cbor_head(3, len(b)) + b
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        # insertion order preserved (like a JS Map), for byte-fidelity with hook.js
        out = _cbor_head(5, len(value))
        for k, v in value.items():
            out += cbor_encode(k) + cbor_encode(v)
        return out
    raise TypeError(f"cbor: unsupported value {type(value)}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _cose_key_es256(pub: ec.EllipticCurvePublicKey) -> bytes:
    # EC2: kty=2, alg=-7, crv=1 (P-256), x, y  (32-byte big-endian coordinates)
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    return cbor_encode({1: 2, 3: -7, -1: 1, -2: x, -3: y})


def _spki(pub: ec.EllipticCurvePublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


@dataclass
class Credential:
    """A fabricated credential the authenticator remembers between create and get."""
    rp_id: str
    private_key: ec.EllipticCurvePrivateKey
    cred_id: bytes
    alg: int = COSE_ES256
    sign_count: int = 0


@dataclass
class SoftAuthenticator:
    """Holds fabricated credentials per rp_id, like hook.js's keyCache."""
    set_up: bool = True
    set_uv: bool = True
    _creds: dict[str, Credential] = field(default_factory=dict)

    def _flags(self, attested: bool) -> int:
        f = 0
        if self.set_up:
            f |= FLAG_UP
        if self.set_uv:
            f |= FLAG_UV
        if attested:
            f |= FLAG_AT
        return f

    # --- registration -----------------------------------------------------

    def make_credential(self, *, rp_id: str, challenge: bytes, origin: str) -> dict:
        """Fabricate a create() result. Returns the finish payload (base64url
        strings), matching hook.js's RegistrationResponseJSON.
        """
        priv = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(32)
        self._creds[rp_id] = Credential(rp_id, priv, cred_id)

        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        flags = bytes([self._flags(attested=True)])
        sign_count = struct.pack(">I", 0)
        cred_id_len = struct.pack(">H", len(cred_id))
        cose = _cose_key_es256(priv.public_key())
        auth_data = rp_id_hash + flags + sign_count + AAGUID + cred_id_len + cred_id + cose

        attestation_object = cbor_encode({
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data,
        })
        client_data = json.dumps({
            "type": "webauthn.create",
            "challenge": b64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        }, separators=(",", ":")).encode()

        return {
            "id": b64url(cred_id),
            "rawId": b64url(cred_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation_object),
                "transports": ["internal"],
                "authenticatorData": b64url(auth_data),
                "publicKey": b64url(_spki(priv.public_key())),
                "publicKeyAlgorithm": COSE_ES256,
            },
            "clientExtensionResults": {},
        }

    # --- authentication ---------------------------------------------------

    def get_assertion(self, *, rp_id: str, challenge: bytes, origin: str,
                      allow_credentials: list[bytes] | None = None) -> dict | None:
        """Fabricate a get() assertion, signing with the stored credential.

        Returns None if we hold no credential for this RP, or ours is not in a
        non-empty allowCredentials (mirrors hook.js).
        """
        entry = self._creds.get(rp_id)
        if entry is None:
            return None
        if allow_credentials:
            if entry.cred_id not in allow_credentials:
                return None

        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        flags = bytes([self._flags(attested=False)])
        entry.sign_count += 1
        sign_count = struct.pack(">I", entry.sign_count)
        authenticator_data = rp_id_hash + flags + sign_count

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": b64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        }, separators=(",", ":")).encode()
        client_data_hash = hashlib.sha256(client_data).digest()

        # ECDSA over authenticatorData || SHA256(clientDataJSON); cryptography
        # returns DER (SEQUENCE of two INTEGERs), exactly what WebAuthn wants.
        signature = entry.private_key.sign(
            authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

        return {
            "id": b64url(entry.cred_id),
            "rawId": b64url(entry.cred_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "authenticatorData": b64url(authenticator_data),
                "clientDataJSON": b64url(client_data),
                "signature": b64url(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
