"""
Smoke tests for orp-verifier.

These tests use synthetic fixtures generated on the fly: a fake meta-key, a
fake root, a fake registry, and a tiny bundle with a single record. The goal
is to exercise the verification code paths end-to-end without depending on
the Originum backend.

Run from the repository root:

    python -m pytest tests/ -v

Or directly:

    python -m unittest tests.test_smoke
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from originum_verify import (
    sha256,
    normalize_registry_id,
    verify_cose_sign1,
    load_p256_public_key,
    run_verification,
)


# =============================================================================
# Helpers to build synthetic fixtures
# =============================================================================

def gen_keypair():
    """Generate a P-256 keypair."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub


def pub_raw_xy(pub):
    """Serialize a public key to raw X || Y (64 bytes)."""
    nums = pub.public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def sign_cose_sign1(priv, payload: bytes) -> bytes:
    """Build a COSE_Sign1 message (tag 18) over `payload` with ES256."""
    # Protected header: {1: -7} (alg = ES256), serialized as canonical CBOR.
    protected_bstr = cbor2.dumps({1: -7}, canonical=True)
    sig_structure = ["Signature1", protected_bstr, b"", payload]
    to_be_signed = cbor2.dumps(sig_structure, canonical=True)

    der_sig = priv.sign(to_be_signed, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    msg = [protected_bstr, {}, payload, raw_sig]
    return cbor2.dumps(cbor2.CBORTag(18, msg), canonical=True)


def build_trust_bundle(meta_priv, root_priv, registry_priv, registry_id):
    """Build a complete trust_bundle (CBOR) given the three keypairs."""
    root_pub_raw = pub_raw_xy(root_priv.public_key())
    registry_pub_raw = pub_raw_xy(registry_priv.public_key())

    # Trust anchor payload (CBOR with integer keys).
    trust_anchor_payload = cbor2.dumps({
        1: 1,                              # version
        2: "test-authority",               # authority_id
        3: "ES256",                        # algorithm
        4: 1,                              # meta_key_version
        5: 1715000000,                     # created_at
        6: [                               # roots
            {
                1: 1,
                2: "test-root",
                3: root_pub_raw,
                4: 1715000000 - 86400,
                5: 0,
                6: 1,
            }
        ],
    }, canonical=True)
    trust_anchor_cose = sign_cose_sign1(meta_priv, trust_anchor_payload)

    # Registry payload (CBOR with integer keys), signed by root.
    registry_payload = cbor2.dumps({
        1: 1,
        2: registry_id,
        3: registry_pub_raw,
        4: 1715000000 - 86400,
        5: 0,
        6: 1,
        7: "ES256",
    }, canonical=True)
    registry_cose = sign_cose_sign1(root_priv, registry_payload)

    bundle_cbor = cbor2.dumps({
        "trust_anchor": trust_anchor_cose,
        "issuers": [],
        "registry": registry_cose,
    }, canonical=True)
    return base64.b64encode(bundle_cbor).decode("ascii")


def build_receipt(registry_priv, registry_id, file_hash, timestamp):
    """Build a receipt COSE for a single file."""
    receipt_payload = cbor2.dumps({
        "content_hash": file_hash,
        "registry_id":  registry_id,
        "timestamp":    timestamp,
        "publisher_id": "test-publisher",
    }, canonical=True)
    return base64.b64encode(sign_cose_sign1(registry_priv, receipt_payload)).decode("ascii")


def build_leaf(registry_id, file_hash, created_at, record_seq):
    """Per ORP-001 §6."""
    return sha256(
        normalize_registry_id(registry_id).encode("utf-8")
        + file_hash
        + created_at.to_bytes(8, "big")
        + record_seq.to_bytes(8, "big")
    )


def build_complete_bundle(file_bytes: bytes) -> tuple[dict, ec.EllipticCurvePublicKey]:
    """Build a complete, valid bundle and return (bundle_dict, meta_pubkey)."""
    file_hash = hashlib.sha256(file_bytes).digest()
    registry_id = "test-registry"
    timestamp = 1715000123
    record_seq = 1

    meta_priv, meta_pub = gen_keypair()
    root_priv, _ = gen_keypair()
    registry_priv, _ = gen_keypair()

    trust_bundle_b64 = build_trust_bundle(meta_priv, root_priv, registry_priv, registry_id)
    receipt_b64 = build_receipt(registry_priv, registry_id, file_hash, timestamp)

    # Build a tiny Merkle tree with the leaf + one sibling.
    leaf = build_leaf(registry_id, file_hash, timestamp, record_seq)
    sibling = sha256(b"sibling-data")
    # Tree of depth 1: root = SHA256(leaf || sibling) because leaf is on the left.
    merkle_root = sha256(leaf + sibling)

    # batch_hash = SHA256(registry_id || merkle_root || previous_hash || timestamp_be8)
    previous_hash = sha256(b"ORP_GENESIS_V1")
    batch_timestamp = timestamp + 100
    batch_hash = sha256(
        normalize_registry_id(registry_id).encode("utf-8")
        + merkle_root
        + previous_hash
        + batch_timestamp.to_bytes(8, "big")
    )
    signed_batch_hash_b64 = base64.b64encode(
        sign_cose_sign1(registry_priv, batch_hash)
    ).decode("ascii")

    bundle = {
        "job_id": "test-job",
        "status": "complete",
        "file_hash": file_hash.hex(),
        "file_name": "test-file.bin",
        "registered_at": timestamp,
        "completed_at": batch_timestamp,
        "receipt": receipt_b64,
        "proof": {
            "merkle_root":      merkle_root.hex(),
            "batch_id":         42,
            "batch_hash":       batch_hash.hex(),
            "signed_batch_hash": signed_batch_hash_b64,
            "registry_id":      registry_id,
            "content_hash":     file_hash.hex(),
            "created_at":       timestamp,
            "batch_date":       batch_timestamp,
            "record_sequence":  record_seq,
            "proof": [
                {"hash": sibling.hex(), "position": 1},
            ],
        },
        "trust_bundle": trust_bundle_b64,
        "trust_bundle_id": f"{registry_id}@test",
    }

    return bundle, meta_pub


# =============================================================================
# Tests
# =============================================================================

class TestCoseSign1(unittest.TestCase):
    """Unit test for the COSE_Sign1 verifier helper."""

    def test_sign_and_verify_roundtrip(self):
        priv, pub = gen_keypair()
        payload = b"hello world"
        cose = sign_cose_sign1(priv, payload)
        result = verify_cose_sign1(cose, pub)
        self.assertEqual(result, payload)

    def test_wrong_key_fails(self):
        priv, _ = gen_keypair()
        _, wrong_pub = gen_keypair()
        cose = sign_cose_sign1(priv, b"hello")
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises((InvalidSignature, ValueError)):
            verify_cose_sign1(cose, wrong_pub)


class TestFullBundle(unittest.TestCase):
    """End-to-end test with a complete synthetic bundle."""

    def setUp(self):
        # Create a temporary file with known content.
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)
        self.file_path = self.tmppath / "test-file.bin"
        self.file_bytes = b"this is the content of the test file\n"
        self.file_path.write_bytes(self.file_bytes)

        # Build a complete bundle.
        bundle, meta_pub = build_complete_bundle(self.file_bytes)
        self.bundle = bundle
        self.meta_pub = meta_pub

        # Write the bundle to disk.
        self.bundle_path = self.tmppath / "bundle.json"
        self.bundle_path.write_text(json.dumps(bundle, indent=2))

        # Write the meta-key to disk in hex form.
        self.meta_key_path = self.tmppath / "meta-key.pub"
        self.meta_key_path.write_text(pub_raw_xy(meta_pub).hex())

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_verified_with_custom_meta_key(self):
        report = run_verification(
            file_path=self.file_path,
            bundle_path=self.bundle_path,
            ots_path=None,
            meta_key_path=self.meta_key_path,
            strict_bitcoin=False,
        )
        # Mandatory checks must all pass.
        self.assertTrue(report.checks["trust_anchor"].is_pass(),
                        msg=report.checks["trust_anchor"].detail)
        self.assertTrue(report.checks["registry_chain"].is_pass(),
                        msg=report.checks["registry_chain"].detail)
        self.assertTrue(report.checks["receipt"].is_pass(),
                        msg=report.checks["receipt"].detail)
        self.assertTrue(report.checks["merkle_proof"].is_pass(),
                        msg=report.checks["merkle_proof"].detail)
        self.assertTrue(report.checks["batch_signature"].is_pass(),
                        msg=report.checks["batch_signature"].detail)

        # Check 6 is not_applicable because no .ots was provided.
        self.assertTrue(report.checks["bitcoin_anchor"].is_na())

        # Overall is PARTIALLY_VERIFIED because of check 6.
        self.assertEqual(report.overall, "PARTIALLY_VERIFIED")

    def test_tampered_file_fails(self):
        # Tamper with the file: change one byte.
        tampered = self.tmppath / "tampered.bin"
        tampered.write_bytes(self.file_bytes + b"X")

        report = run_verification(
            file_path=tampered,
            bundle_path=self.bundle_path,
            ots_path=None,
            meta_key_path=self.meta_key_path,
            strict_bitcoin=False,
        )
        # Checks 1 and 2 still pass (they don't involve the file),
        # but check 3 (receipt) must fail because content_hash mismatches.
        self.assertTrue(report.checks["trust_anchor"].is_pass())
        self.assertTrue(report.checks["registry_chain"].is_pass())
        self.assertTrue(report.checks["receipt"].is_fail())
        self.assertEqual(report.overall, "INVALID")

    def test_wrong_meta_key_fails_check_1(self):
        # Use a completely different meta-key.
        wrong_priv, wrong_pub = gen_keypair()
        wrong_key_path = self.tmppath / "wrong-meta.pub"
        wrong_key_path.write_text(pub_raw_xy(wrong_pub).hex())

        report = run_verification(
            file_path=self.file_path,
            bundle_path=self.bundle_path,
            ots_path=None,
            meta_key_path=wrong_key_path,
            strict_bitcoin=False,
        )
        self.assertTrue(report.checks["trust_anchor"].is_fail())
        self.assertEqual(report.overall, "INVALID")


if __name__ == "__main__":
    unittest.main()
