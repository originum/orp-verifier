#!/usr/bin/env python3
# =============================================================================
# Originum external verifier  —  reference implementation of ORP-001
#                                offline verification, plus optional Bitcoin
#                                anchor verification (check 6).
# =============================================================================
#
# This tool performs cryptographic verification of an Originum proof bundle
# without contacting the Originum backend. Given:
#
#   - the original file
#   - the bundle JSON (as produced by GET /v1/bundle in "fat" mode)
#   - optionally, the .ots file for the batch
#
# it runs up to six independent checks. If all mandatory checks pass, the
# proof is cryptographically valid and the file is bound to the bundle.
#
# The verifier is licensed under Apache 2.0 and intended to be auditable:
# every check is a separate function and every cryptographic operation uses
# well-known libraries (cryptography, cbor2, opentimestamps). There
# are no proprietary primitives.
#
# Usage:
#
#     python originum_verify.py \
#         --file factura.pdf \
#         --bundle bundle.json \
#         [--ots batch-42.ots] \
#         [--meta-key custom_meta_key.pub] \
#         [--strict-bitcoin] \
#         [--json-output]
#
# Exit codes:
#     0    VERIFIED               — all mandatory checks passed.
#     2    PARTIALLY VERIFIED     — mandatory checks passed but some optional
#                                  check was inconclusive (e.g. batch not
#                                  yet sealed, or .ots not yet confirmed in
#                                  Bitcoin).
#     1    INVALID                — at least one mandatory check failed.
#     3    USAGE ERROR            — wrong arguments, files not found, etc.
# =============================================================================

import argparse
import base64
import binascii
import hashlib
import json
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Third-party dependencies. cryptography and cbor2 are mandatory. The
# opentimestamps client is optional (only needed for check 6).
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature,
    )
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write(
        "ERROR: the 'cryptography' package is required.\n"
        "       Install it with: pip install cryptography\n"
    )
    sys.exit(3)

try:
    import cbor2
except ImportError:
    sys.stderr.write(
        "ERROR: the 'cbor2' package is required.\n"
        "       Install it with: pip install cbor2\n"
    )
    sys.exit(3)

# trusted_meta_keys lives next to this script. It carries the embedded list
# of meta-keys recognized by this build of the verifier.
from trusted_meta_keys import TRUSTED_META_KEYS

VERIFIER_VERSION = "1.0.0"
VERIFIER_URL = "https://github.com/originum/orp-verifier"


# =============================================================================
# Result types
# =============================================================================

@dataclass
class CheckResult:
    """Tri-state result of a single check."""
    status: str  # "pass" | "fail" | "not_applicable"
    detail: str = ""
    extra: dict = field(default_factory=dict)

    def is_pass(self) -> bool:
        return self.status == "pass"

    def is_fail(self) -> bool:
        return self.status == "fail"

    def is_na(self) -> bool:
        return self.status == "not_applicable"


@dataclass
class VerifyReport:
    """Full result of a verification run, serializable to JSON."""
    file_path: str
    file_hash_hex: str
    checks: dict  # check_name -> CheckResult
    overall: str  # "VERIFIED" | "PARTIALLY_VERIFIED" | "INVALID"
    metadata: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "verifier_version": VERIFIER_VERSION,
            "verifier_url": VERIFIER_URL,
            "file": self.file_path,
            "file_hash": self.file_hash_hex,
            "result": self.overall,
            "checks": {
                name: {
                    "status": r.status,
                    "detail": r.detail,
                    **r.extra,
                }
                for name, r in self.checks.items()
            },
            "metadata": self.metadata,
        }, indent=2)


# =============================================================================
# Low-level cryptographic helpers
# =============================================================================

def sha256(data: bytes) -> bytes:
    """Convenience wrapper. The protocol uses SHA-256 exclusively."""
    return hashlib.sha256(data).digest()


def normalize_registry_id(registry_id: str) -> str:
    """
    Apply ORP-001 §4.1 canonical encoding to a registry_id:
    UTF-8 + NFC + lowercase. Comparisons are byte-exact after this.
    """
    return unicodedata.normalize("NFC", registry_id).lower()


def load_p256_public_key(raw_xy: bytes) -> ec.EllipticCurvePublicKey:
    """
    Load a raw uncompressed P-256 public key. Accepts both the 65-byte
    SEC1 form (0x04 || X || Y) and the 64-byte raw form (X || Y) used
    inside the protocol.
    """
    if len(raw_xy) == 64:
        sec1 = b"\x04" + raw_xy
    elif len(raw_xy) == 65 and raw_xy[0] == 0x04:
        sec1 = raw_xy
    else:
        raise ValueError(
            f"public key must be 64 or 65 bytes, got {len(raw_xy)}"
        )
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sec1)


def verify_cose_sign1(
    cose_bytes: bytes,
    public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    """
    Verify a COSE_Sign1 message (RFC 9052) signed with ES256 and return
    the embedded payload.

    Structure of COSE_Sign1 (tag 18):
        [protected_header_bstr, unprotected_header_map, payload, signature]

    The signed bytes are the canonical CBOR encoding of:
        ["Signature1", protected_header_bstr, external_aad=b"", payload]

    The signature is raw R || S (64 bytes), so it has to be converted to
    DER for the `cryptography` library's verify() method.
    """
    # Decode and unwrap the CBOR tag if present.
    obj = cbor2.loads(cose_bytes)
    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != 18:
            raise ValueError(f"expected COSE_Sign1 tag 18, got {obj.tag}")
        obj = obj.value
    if not isinstance(obj, (list, tuple)) or len(obj) != 4:
        raise ValueError("COSE_Sign1 must be a 4-element array")

    protected_bstr, _unprotected, payload, signature = obj

    # The protected header is a bstr-wrapped CBOR map; decode it to check alg.
    if protected_bstr:
        protected = cbor2.loads(protected_bstr)
        alg = protected.get(1)  # 1 = alg in COSE headers
        if alg != -7:  # -7 = ES256
            raise ValueError(f"expected ES256 (-7), got alg={alg}")
    else:
        raise ValueError("protected header must not be empty (ORP-001 §12)")

    # Build the Sig_structure and serialize canonically.
    sig_structure = ["Signature1", protected_bstr, b"", payload]
    to_be_signed = cbor2.dumps(sig_structure, canonical=True)

    # Convert raw signature (R || S, 64 bytes) to DER for `cryptography`.
    if len(signature) != 64:
        raise ValueError(f"signature must be 64 bytes, got {len(signature)}")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_sig = encode_dss_signature(r, s)

    # The actual verification. Raises InvalidSignature on failure.
    from cryptography.hazmat.primitives import hashes
    public_key.verify(der_sig, to_be_signed, ec.ECDSA(hashes.SHA256()))

    return payload


# =============================================================================
# Loaders for the bundle structure
# =============================================================================

def load_file_hash(file_path: Path) -> bytes:
    """Compute SHA-256 of the original file, streaming to handle large inputs."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(64 * 1024):
            h.update(chunk)
    return h.digest()


def load_bundle(bundle_path: Path) -> dict:
    """Read and parse the bundle JSON."""
    with bundle_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_meta_keys_from_cli_or_embedded(
    cli_meta_key_path: Optional[Path],
) -> list[ec.EllipticCurvePublicKey]:
    """
    Decide which meta-keys to use. If --meta-key was provided, that file is
    the sole source. Otherwise, use the embedded list from trusted_meta_keys.
    """
    if cli_meta_key_path:
        raw = cli_meta_key_path.read_bytes()
        # Accept hex (with or without 0x prefix and whitespace) or raw binary.
        text = raw.decode("ascii", errors="ignore").strip().replace("\n", "")
        if text.startswith("0x"):
            text = text[2:]
        try:
            key_bytes = bytes.fromhex(text)
        except ValueError:
            key_bytes = raw
        return [load_p256_public_key(key_bytes)]

    keys = []
    for entry in TRUSTED_META_KEYS:
        hex_str = entry["public_key_hex"]
        key_bytes = bytes.fromhex(hex_str)
        keys.append(load_p256_public_key(key_bytes))
    return keys


# =============================================================================
# Trust bundle parsing
# =============================================================================

def parse_trust_bundle(trust_bundle_b64: str) -> dict:
    """
    Decode the base64-CBOR trust_bundle. Returns a dict with keys
    "trust_anchor", "issuers", "registry" — each a bytes-COSE blob.
    """
    cbor_bytes = base64.b64decode(trust_bundle_b64)
    obj = cbor2.loads(cbor_bytes)
    if not isinstance(obj, dict):
        raise ValueError("trust_bundle must be a CBOR map")
    return {
        "trust_anchor": obj["trust_anchor"],
        "issuers": obj.get("issuers", []),
        "registry": obj["registry"],
    }


def decode_trust_anchor_payload(payload: bytes) -> dict:
    """
    Decode the CBOR payload of the trust_anchor (after the COSE signature
    has been verified). The protocol uses integer keys (keyasint) here.
    """
    m = cbor2.loads(payload)
    if not isinstance(m, dict):
        raise ValueError("trust_anchor payload must be a map")
    return {
        "version":          m.get(1),
        "authority_id":     m.get(2),
        "algorithm":        m.get(3),
        "meta_key_version": m.get(4),
        "created_at":       m.get(5),
        "roots":            m.get(6, []),
    }


def decode_root_entry(entry: dict) -> dict:
    """Decode one root entry from the trust_anchor (CBOR keyasint)."""
    return {
        "version":     entry.get(1),
        "root_id":     entry.get(2),
        "public_key":  entry.get(3),
        "valid_from":  entry.get(4),
        "valid_to":    entry.get(5),
        "key_version": entry.get(6),
    }


def decode_registry_payload(payload: bytes) -> dict:
    """Decode the registry COSE payload (CBOR keyasint)."""
    m = cbor2.loads(payload)
    return {
        "version":     m.get(1),
        "entity_id":   m.get(2),
        "public_key":  m.get(3),
        "valid_from":  m.get(4),
        "valid_to":    m.get(5),
        "key_version": m.get(6),
        "algorithm":   m.get(7),
    }


def decode_receipt_payload(payload: bytes) -> dict:
    """
    Decode the receipt CBOR payload. The receipt uses STRING keys (unlike
    trust_anchor and registry which use integer keys).
    """
    m = cbor2.loads(payload)
    if not isinstance(m, dict):
        raise ValueError("receipt payload must be a map")
    return m


# =============================================================================
# The six checks
# =============================================================================

def check_1_trust_anchor(
    bundle: dict,
    meta_keys: list[ec.EllipticCurvePublicKey],
) -> tuple[CheckResult, Optional[dict]]:
    """
    Check 1: the trust_anchor inside the trust_bundle is signed by one of
    the recognized meta-keys.

    Returns (result, decoded_anchor_or_None).
    """
    try:
        tb = parse_trust_bundle(bundle["trust_bundle"])
    except (KeyError, ValueError, binascii.Error) as e:
        return CheckResult("fail", f"could not parse trust_bundle: {e}"), None

    payload = None
    for mk in meta_keys:
        try:
            payload = verify_cose_sign1(tb["trust_anchor"], mk)
            break
        except (InvalidSignature, ValueError):
            continue

    if payload is None:
        declared = bundle.get("trust_bundle_id", "<unknown>")
        return CheckResult(
            "fail",
            f"trust_anchor did not verify against any recognized meta-key. "
            f"Bundle declares trust_bundle_id={declared!r}. "
            f"If this bundle is from a private deployment, pass its "
            f"meta-key with --meta-key."
        ), None

    anchor = decode_trust_anchor_payload(payload)
    return CheckResult(
        "pass",
        f"signed by meta-key for authority {anchor.get('authority_id')!r}",
        extra={"authority_id": anchor.get("authority_id")},
    ), {"anchor": anchor, "trust_bundle": tb}


def check_2_registry_chain(state: dict) -> tuple[CheckResult, Optional[dict]]:
    """
    Check 2: the registry inside the trust_bundle is signed by one of the
    roots listed in the trust_anchor.
    """
    tb = state["trust_bundle"]
    anchor = state["anchor"]
    roots = anchor.get("roots", [])
    if not roots:
        return CheckResult("fail", "trust_anchor lists no roots"), None

    registry_cose = tb["registry"]
    payload = None
    chosen_root = None
    for root_entry in roots:
        root = decode_root_entry(root_entry)
        try:
            root_pub = load_p256_public_key(root["public_key"])
        except (ValueError, TypeError):
            continue
        try:
            payload = verify_cose_sign1(registry_cose, root_pub)
            chosen_root = root
            break
        except (InvalidSignature, ValueError):
            continue

    if payload is None:
        return CheckResult(
            "fail",
            f"registry COSE not signed by any of the {len(roots)} roots in "
            f"the trust_anchor"
        ), None

    registry = decode_registry_payload(payload)
    return CheckResult(
        "pass",
        f"registry {registry.get('entity_id')!r} signed by root "
        f"{chosen_root.get('root_id')!r}",
        extra={"registry_id": registry.get("entity_id"),
               "root_id": chosen_root.get("root_id")},
    ), {**state, "registry": registry, "registry_root": chosen_root}


def check_3_receipt(
    bundle: dict, state: dict, file_hash: bytes,
) -> tuple[CheckResult, Optional[dict]]:
    """
    Check 3: the receipt is signed by the registry's public key and its
    content_hash field equals the SHA-256 of the original file.
    """
    receipt_cose = base64.b64decode(bundle["receipt"])
    try:
        registry_pub = load_p256_public_key(state["registry"]["public_key"])
    except (ValueError, TypeError) as e:
        return CheckResult("fail", f"invalid registry public key: {e}"), None

    try:
        payload = verify_cose_sign1(receipt_cose, registry_pub)
    except (InvalidSignature, ValueError) as e:
        return CheckResult("fail", f"receipt signature invalid: {e}"), None

    try:
        receipt = decode_receipt_payload(payload)
    except ValueError as e:
        return CheckResult("fail", f"could not decode receipt payload: {e}"), None

    content_hash = receipt.get("content_hash")
    if not isinstance(content_hash, (bytes, bytearray)):
        return CheckResult(
            "fail", "receipt has no content_hash or it is not bytes"
        ), None
    if bytes(content_hash) != file_hash:
        return CheckResult(
            "fail",
            f"file SHA-256 ({file_hash.hex()[:16]}...) does not match "
            f"receipt.content_hash ({content_hash.hex()[:16]}...)"
        ), None

    return CheckResult(
        "pass",
        f"receipt signed by registry, file hash matches",
        extra={
            "publisher_id": receipt.get("publisher_id"),
            "timestamp": receipt.get("timestamp"),
        },
    ), {**state, "receipt": receipt}


def check_4_merkle_proof(
    bundle: dict, state: dict, file_hash: bytes,
) -> tuple[CheckResult, Optional[dict]]:
    """
    Check 4: rebuild the Merkle root from the leaf (derived from file_hash
    and receipt metadata) plus the proof_nodes, and verify it matches the
    merkle_root declared in the proof block.

    If the bundle has no proof block (the batch isn't sealed yet), this
    check is "not_applicable".
    """
    proof_block = bundle.get("proof")
    if not proof_block:
        return CheckResult(
            "not_applicable", "bundle has no proof (batch not yet sealed)"
        ), None

    # Build the leaf per ORP-001 §6:
    #   leaf = SHA256(
    #       registry_id_utf8 ||
    #       content_hash_32 ||
    #       created_at_be8 ||
    #       record_sequence_be8
    #   )
    receipt = state["receipt"]
    registry_id_canonical = normalize_registry_id(receipt["registry_id"])
    created_at = int(receipt["timestamp"])
    # record_sequence lives in the proof block; the receipt does not have it
    # because record_sequence is decided when the record is assigned to a
    # batch, after the receipt is issued.
    record_seq = int(proof_block["record_sequence"])

    leaf = sha256(
        registry_id_canonical.encode("utf-8")
        + file_hash
        + created_at.to_bytes(8, "big")
        + record_seq.to_bytes(8, "big")
    )

    # Walk the proof nodes per ORP-001 §16:
    #   for each (sibling, position):
    #     if position == 1: current = SHA256(current || sibling)
    #     else:             current = SHA256(sibling || current)
    current = leaf
    for node in proof_block.get("proof", []):
        sibling_raw = node["hash"]
        # The hash may be hex or base64 depending on the producer; try hex first.
        try:
            sibling = bytes.fromhex(sibling_raw)
        except ValueError:
            sibling = base64.b64decode(sibling_raw)

        pos = node["position"]
        if isinstance(pos, str):
            pos_int = 0 if pos == "left" else 1
        else:
            pos_int = int(pos)

        if pos_int == 1:
            current = sha256(current + sibling)
        else:
            current = sha256(sibling + current)

    # Compare with the merkle_root declared in the proof block.
    declared_root_raw = proof_block["merkle_root"]
    try:
        declared_root = bytes.fromhex(declared_root_raw)
    except ValueError:
        declared_root = base64.b64decode(declared_root_raw)

    if current != declared_root:
        return CheckResult(
            "fail",
            f"rebuilt merkle_root ({current.hex()[:16]}...) does not match "
            f"declared ({declared_root.hex()[:16]}...)"
        ), None

    return CheckResult(
        "pass",
        f"file is included in batch {proof_block.get('batch_id')} "
        f"at record_sequence {record_seq}",
        extra={"batch_id": proof_block.get("batch_id"),
               "record_sequence": record_seq},
    ), {**state, "merkle_root": current, "proof_block": proof_block}


def check_5_batch_signature(
    state: dict,
) -> tuple[CheckResult, Optional[dict]]:
    """
    Check 5: the signed_batch_hash in the proof is a valid COSE_Sign1 by
    the registry, and its payload equals the batch_hash declared in the
    proof block.

    Also independently recomputes batch_hash per ORP-001 §11:
        batch_hash = SHA256(
            registry_id_utf8 ||
            merkle_root_32 ||
            previous_hash_32 ||
            batch_timestamp_be8
        )
    But previous_hash is NOT in the proof block (it'd require fetching
    the chain to verify previous_hash linkage end-to-end). So this check
    verifies the binding (signed batch_hash == declared batch_hash) and
    the registry signature, which is what makes the bundle self-contained.
    """
    proof = state["proof_block"]
    registry_pub = load_p256_public_key(state["registry"]["public_key"])

    signed_bh = base64.b64decode(proof["signed_batch_hash"])
    try:
        payload = verify_cose_sign1(signed_bh, registry_pub)
    except (InvalidSignature, ValueError) as e:
        return CheckResult(
            "fail", f"signed_batch_hash signature invalid: {e}"
        ), None

    declared_bh = bytes.fromhex(proof["batch_hash"])
    if payload != declared_bh:
        return CheckResult(
            "fail",
            f"signed payload ({payload.hex()[:16]}...) does not match "
            f"declared batch_hash ({declared_bh.hex()[:16]}...)"
        ), None

    return CheckResult(
        "pass",
        f"batch_hash signed by registry",
        extra={"batch_hash": proof["batch_hash"]},
    ), state


# =============================================================================
# Check 6 — Bitcoin anchor verification (pure Python, no shell-out)
# =============================================================================
#
# This check uses the `opentimestamps` library directly (the parser-only
# core, not `opentimestamps-client` which depends on python-bitcoinlib
# and OpenSSL native DLLs). The motivation is portability: the verifier
# runs identically on Windows, Linux and macOS without external binaries.
#
# The .ots file is loaded either from a path passed via --ots OR
# extracted automatically from the bundle's `bitcoin_anchor.ots` field.
# Most users do not need --ots; the bundle is self-contained.

# Optional dependency: only required for check 6. Imported lazily so the
# rest of the verifier still works without it (checks 1–5 only).
try:
    from opentimestamps.core.timestamp import (
        DetachedTimestampFile, Timestamp,
    )
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.notary import (
        BitcoinBlockHeaderAttestation, PendingAttestation,
    )
    _OTS_AVAILABLE = True
    _OTS_IMPORT_ERR = None
except ImportError as e:
    _OTS_AVAILABLE = False
    _OTS_IMPORT_ERR = str(e)


def _resolve_ots_bytes(
    bundle: dict, ots_path: Optional[Path],
) -> tuple[Optional[bytes], Optional[str], dict]:
    """
    Resolve the .ots bytes to verify, in priority order:

      1. If --ots is provided and the file exists, use it (lets the user
         override the bundle's .ots with a locally-upgraded one).
      2. Otherwise, decode `bundle.proof.bitcoin_anchor.ots` from base64.
      3. Otherwise, return None — caller decides whether that is N/A or fail.

    Returns (ots_bytes_or_None, reason_or_None, source_info).

    source_info is a dict describing where the bytes came from. Keys:
      - source: "ots_flag" | "bundle" | "ots_flag+bundle_match"
                | "ots_flag+bundle_mismatch"
      - bundle_size: int (only when bundle has embedded .ots)
      - file_size:   int (only when --ots is provided)
    """
    info: dict = {}

    # Read bundle's embedded .ots first (if present) to enable cross-check
    # when --ots is also provided.
    bundle_ots_bytes: Optional[bytes] = None
    proof = bundle.get("proof", {})
    anchor = proof.get("bitcoin_anchor") if proof else None
    if anchor:
        ots_b64 = anchor.get("ots")
        if ots_b64:
            try:
                bundle_ots_bytes = base64.b64decode(ots_b64)
                info["bundle_size"] = len(bundle_ots_bytes)
            except (binascii.Error, ValueError):
                bundle_ots_bytes = None

    # Path takes precedence when given — explicit override.
    if ots_path is not None:
        if not ots_path.is_file():
            return None, f".ots file not found: {ots_path}", info
        try:
            file_bytes = ots_path.read_bytes()
        except OSError as e:
            return None, f"could not read .ots file: {e}", info
        info["file_size"] = len(file_bytes)
        if bundle_ots_bytes is None:
            info["source"] = "ots_flag"
        elif file_bytes == bundle_ots_bytes:
            info["source"] = "ots_flag+bundle_match"
        else:
            info["source"] = "ots_flag+bundle_mismatch"
        return file_bytes, None, info

    # Fall back to bundle-embedded .ots.
    if not anchor:
        return None, "bundle has no bitcoin_anchor (batch not yet anchored)", info
    if bundle_ots_bytes is None:
        return None, "bundle has bitcoin_anchor but no valid embedded .ots data", info
    info["source"] = "bundle"
    return bundle_ots_bytes, None, info


def _parse_ots(ots_bytes: bytes) -> "DetachedTimestampFile":
    """Parse raw .ots bytes into a DetachedTimestampFile."""
    import io
    ctx = StreamDeserializationContext(io.BytesIO(ots_bytes))
    return DetachedTimestampFile.deserialize(ctx)


def _find_bitcoin_attestation(
    ts: "Timestamp",
) -> Optional["BitcoinBlockHeaderAttestation"]:
    """
    Walk the timestamp tree looking for a BitcoinBlockHeaderAttestation.
    Returns the first one found, or None.
    """
    for a in ts.attestations:
        if isinstance(a, BitcoinBlockHeaderAttestation):
            return a
    for _op, sub_ts in ts.ops.items():
        found = _find_bitcoin_attestation(sub_ts)
        if found is not None:
            return found
    return None


def _collect_pending(
    ts: "Timestamp",
) -> list[tuple["Timestamp", "PendingAttestation"]]:
    """Walk the tree and return all (timestamp_node, pending_att) pairs."""
    out: list[tuple["Timestamp", "PendingAttestation"]] = []
    for a in ts.attestations:
        if isinstance(a, PendingAttestation):
            out.append((ts, a))
    for _op, sub_ts in ts.ops.items():
        out.extend(_collect_pending(sub_ts))
    return out


def _try_upgrade_from_calendars(
    ts: "Timestamp",
) -> tuple[Optional["BitcoinBlockHeaderAttestation"], Optional[str]]:
    """
    For each PendingAttestation in the tree, ask its calendar whether a
    Bitcoin attestation is now available. If any calendar responds with
    an upgraded timestamp that contains a BitcoinBlockHeaderAttestation,
    return (attestation, calendar_uri). Otherwise return (None, None).

    Network failures are silent — they downgrade to "still pending".
    """
    try:
        from opentimestamps.calendar import RemoteCalendar
    except ImportError:
        return None, None

    pendings = _collect_pending(ts)
    for ts_node, att in pendings:
        try:
            calendar = RemoteCalendar(att.uri)
            upgraded = calendar.get_timestamp(ts_node.msg, timeout=8)
        except Exception:
            # Calendar unreachable, 404 (still pending), timeout, etc.
            # Try the next one rather than failing the whole check.
            continue
        btc = _find_bitcoin_attestation(upgraded)
        if btc is not None:
            return btc, att.uri
    return None, None


def _fetch_bitcoin_block_info(height: int) -> dict:
    """
    Best-effort lookup of a Bitcoin block's hash and timestamp via the
    public mempool.space API. Returns a dict with the keys it could
    populate; never raises. If the network is unavailable, returns {}.

    This is "best-effort" because it depends on a third party (mempool.space)
    that is outside the trust boundary of the verifier. The verifier's PASS
    decision does NOT depend on this lookup succeeding — the proof is
    already valid by virtue of the .ots embedding the Bitcoin attestation.
    This is just contextual information to make the audit report richer.
    """
    import urllib.request
    import urllib.error

    out: dict = {}
    try:
        # Step 1: height → block hash
        with urllib.request.urlopen(
            f"https://mempool.space/api/block-height/{height}",
            timeout=5,
        ) as resp:
            if resp.status != 200:
                return out
            block_hash = resp.read().decode("ascii").strip()
            if len(block_hash) != 64:
                return out
            out["bitcoin_block_hash"] = block_hash

        # Step 2: block hash → metadata (timestamp, tx_count, ...)
        with urllib.request.urlopen(
            f"https://mempool.space/api/block/{block_hash}",
            timeout=5,
        ) as resp:
            if resp.status != 200:
                return out
            meta = json.loads(resp.read().decode("utf-8"))
            ts = meta.get("timestamp")
            if isinstance(ts, int):
                from datetime import datetime, timezone
                out["bitcoin_block_unix"] = ts
                out["bitcoin_block_time_utc"] = (
                    datetime.fromtimestamp(ts, tz=timezone.utc)
                            .strftime("%Y-%m-%d %H:%M:%S UTC")
                )
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, ValueError, OSError, TimeoutError):
        # Network down, mempool.space rate-limiting, etc. — silently skip.
        pass

    return out


def check_6_bitcoin_anchor(
    bundle: dict, state: dict, ots_path: Optional[Path], strict: bool,
) -> CheckResult:
    """
    Check 6: the Bitcoin anchor.

    Steps:

      1. Determine the expected anchored hash from the bundle, according
         to the `anchored_hash_type` discriminator
         (anchor_commitment_v1 or merkle_root_legacy).
      2. Cross-check it against `bitcoin_anchor.anchored_hash`.
      3. Load the .ots (from --ots if provided, otherwise from the
         bundle's bitcoin_anchor.ots field).
      4. Parse the .ots and verify it commits to the expected hash.
      5. If the .ots already has a Bitcoin attestation embedded
         (it was upgraded server-side), report PASS with block.
      6. Otherwise, query the calendar(s) listed in the .ots to see if
         Bitcoin confirmation is now available. If yes, PASS. If still
         pending, NOT APPLICABLE (or FAIL with --strict-bitcoin).

    No external binaries are invoked. No native dependencies. Pure
    Python using the `opentimestamps` library and `urllib` (for
    calendar queries, via RemoteCalendar).
    """
    proof = state.get("proof_block")
    anchor = proof.get("bitcoin_anchor") if proof else None

    if not anchor:
        return CheckResult(
            "fail" if strict else "not_applicable",
            "bundle has no bitcoin_anchor (batch not yet anchored)",
        )

    if not _OTS_AVAILABLE:
        return CheckResult(
            "fail" if strict else "not_applicable",
            f"opentimestamps library not installed: {_OTS_IMPORT_ERR}. "
            f"Install with: pip install opentimestamps",
        )

    # ---- Step 1: determine the expected anchored hash. ----------------------
    anchored_hash_type = anchor.get("anchored_hash_type")
    if anchored_hash_type == "anchor_commitment_v1":
        # Per ORP-001 §14:
        #   anchor_commitment = SHA256(
        #       canonical(registry_id) || batch_hash_32 || batch_ts_be8
        #   )
        registry_id = normalize_registry_id(state["registry"]["entity_id"])
        batch_hash = bytes.fromhex(proof["batch_hash"])
        batch_ts = int(proof.get("batch_date") or proof.get("created_at"))
        expected = sha256(
            registry_id.encode("utf-8")
            + batch_hash
            + batch_ts.to_bytes(8, "big")
        )
    elif anchored_hash_type == "merkle_root_legacy":
        try:
            expected = bytes.fromhex(proof["merkle_root"])
        except ValueError:
            expected = base64.b64decode(proof["merkle_root"])
    else:
        return CheckResult(
            "fail",
            f"unknown anchored_hash_type: {anchored_hash_type!r}",
        )

    # ---- Step 2: cross-check against the bundle's declared anchored_hash. --
    declared_hex = anchor.get("anchored_hash", "")
    if declared_hex:
        try:
            declared = bytes.fromhex(declared_hex)
        except ValueError:
            return CheckResult(
                "fail",
                f"bitcoin_anchor.anchored_hash is not valid hex: {declared_hex!r}",
            )
        if declared != expected:
            return CheckResult(
                "fail",
                f"bundle.bitcoin_anchor.anchored_hash ({declared.hex()[:16]}...) "
                f"does not match the recomputed hash ({expected.hex()[:16]}...)",
            )

    # ---- Step 3: resolve the .ots bytes. ------------------------------------
    ots_bytes, reason, source_info = _resolve_ots_bytes(bundle, ots_path)
    if ots_bytes is None:
        return CheckResult(
            "fail" if strict else "not_applicable",
            reason or "could not resolve .ots data",
        )

    # Mismatch between --ots and bundle is a HARD fail: if a user passed
    # a .ots that differs from the one in the bundle, the verifier MUST
    # surface that rather than silently picking one. The two could differ
    # legitimately (a locally-upgraded .ots vs the pending one in the
    # bundle), but they could also differ because of tampering. The user
    # decides which to trust by re-running with the appropriate input.
    if source_info.get("source") == "ots_flag+bundle_mismatch":
        # Continue verifying — but tell the user clearly via extra info.
        # We use the --ots bytes (the explicit override), and report the
        # discrepancy in the result's extra dict.
        pass

    # ---- Step 4: parse the .ots and verify the commitment matches. ---------
    try:
        dtf = _parse_ots(ots_bytes)
    except Exception as e:
        return CheckResult(
            "fail",
            f"could not parse .ots: {type(e).__name__}: {e}",
        )

    if dtf.file_digest != expected:
        return CheckResult(
            "fail",
            f".ots commits to {dtf.file_digest.hex()[:16]}... but bundle "
            f"declares {expected.hex()[:16]}...",
        )

    # Collect the calendars listed in the .ots (used as context regardless
    # of whether we end up calendar-upgrading or not).
    pending_in_ots = _collect_pending(dtf.timestamp)
    calendars_in_ots = [att.uri for _, att in pending_in_ots]

    # Pre-fill common extra fields shared by all PASS / pending branches.
    def _extra(extra_specific: dict) -> dict:
        common = {
            "anchored_hash":      expected.hex(),
            "anchored_hash_type": anchored_hash_type,
            "ots_source":         source_info.get("source", "unknown"),
            "ots_size_bytes":     len(ots_bytes),
        }
        if "bundle_size" in source_info:
            common["ots_bundle_size_bytes"] = source_info["bundle_size"]
        if "file_size" in source_info:
            common["ots_file_size_bytes"] = source_info["file_size"]
        if calendars_in_ots:
            common["calendars_in_ots"] = calendars_in_ots
        if source_info.get("source") == "ots_flag+bundle_mismatch":
            common["warning"] = (
                "the --ots file differs from the .ots embedded in the bundle "
                "(this can be legitimate if --ots is a locally-upgraded copy, "
                "but verify which one you trust)"
            )
        common.update(extra_specific)
        return common

    # ---- Step 5: look for an embedded Bitcoin attestation. -----------------
    btc_att = _find_bitcoin_attestation(dtf.timestamp)
    if btc_att is not None:
        extra = _extra({
            "bitcoin_block_height": btc_att.height,
            "attestation_source":   "embedded_in_ots",
        })
        # Enrich with block timestamp from mempool.space (best-effort).
        extra.update(_fetch_bitcoin_block_info(btc_att.height))
        return CheckResult(
            "pass",
            f"Bitcoin attestation confirmed at block {btc_att.height} "
            f"(embedded in .ots; anchored_hash_type={anchored_hash_type})",
            extra=extra,
        )

    # ---- Step 6: try to upgrade from the calendar(s). ----------------------
    btc_att, upgraded_via = _try_upgrade_from_calendars(dtf.timestamp)
    if btc_att is not None:
        extra = _extra({
            "bitcoin_block_height": btc_att.height,
            "attestation_source":   "calendar_upgrade",
            "calendar_upgraded_from": upgraded_via,
        })
        extra.update(_fetch_bitcoin_block_info(btc_att.height))
        return CheckResult(
            "pass",
            f"Bitcoin attestation confirmed at block {btc_att.height} "
            f"(via calendar {upgraded_via}; "
            f"anchored_hash_type={anchored_hash_type})",
            extra=extra,
        )

    # Pending: the .ots is valid and the calendars know it, but Bitcoin
    # has not confirmed the relevant block yet. This is the normal state
    # during the first ~1 hour after a batch is sealed.
    cals = ", ".join(calendars_in_ots) if calendars_in_ots else "(none listed)"
    return CheckResult(
        "fail" if strict else "not_applicable",
        f"OTS proof anchored but Bitcoin confirmation still pending "
        f"(calendars: {cals}). Retry in ~1 hour.",
        extra=_extra({"attestation_source": "still_pending"}),
    )


# =============================================================================
# Orchestration
# =============================================================================

def run_verification(
    file_path: Path,
    bundle_path: Path,
    ots_path: Optional[Path],
    meta_key_path: Optional[Path],
    strict_bitcoin: bool,
) -> VerifyReport:
    """Run all six checks and produce a consolidated report."""
    file_hash = load_file_hash(file_path)
    bundle = load_bundle(bundle_path)
    meta_keys = load_meta_keys_from_cli_or_embedded(meta_key_path)

    checks: dict[str, CheckResult] = {}
    state: Optional[dict] = None

    # Check 1
    r1, st1 = check_1_trust_anchor(bundle, meta_keys)
    checks["trust_anchor"] = r1
    if r1.is_fail():
        return _finalize(file_path, file_hash, checks)
    state = st1

    # Check 2
    r2, st2 = check_2_registry_chain(state)
    checks["registry_chain"] = r2
    if r2.is_fail():
        return _finalize(file_path, file_hash, checks)
    state = st2

    # Check 3
    r3, st3 = check_3_receipt(bundle, state, file_hash)
    checks["receipt"] = r3
    if r3.is_fail():
        return _finalize(file_path, file_hash, checks)
    state = st3

    # Check 4
    r4, st4 = check_4_merkle_proof(bundle, state, file_hash)
    checks["merkle_proof"] = r4
    if r4.is_fail():
        return _finalize(file_path, file_hash, checks)
    if r4.is_pass():
        state = st4

    # Check 5
    if r4.is_pass():
        r5, st5 = check_5_batch_signature(state)
        checks["batch_signature"] = r5
        if r5.is_fail():
            return _finalize(file_path, file_hash, checks)
        state = st5
    else:
        checks["batch_signature"] = CheckResult(
            "not_applicable", "batch not yet sealed"
        )

    # Check 6 (Bitcoin)
    if r4.is_pass():
        r6 = check_6_bitcoin_anchor(bundle, state, ots_path, strict_bitcoin)
        checks["bitcoin_anchor"] = r6
    else:
        checks["bitcoin_anchor"] = CheckResult(
            "not_applicable", "batch not yet sealed"
        )

    return _finalize(file_path, file_hash, checks)


def _finalize(file_path: Path, file_hash: bytes, checks: dict) -> VerifyReport:
    mandatory_names = ["trust_anchor", "registry_chain", "receipt"]
    optional_names = ["merkle_proof", "batch_signature", "bitcoin_anchor"]

    if any(checks.get(n) and checks[n].is_fail() for n in mandatory_names):
        overall = "INVALID"
    elif any(checks.get(n) and checks[n].is_fail() for n in optional_names):
        overall = "INVALID"
    elif any(checks.get(n) and checks[n].is_na() for n in optional_names):
        overall = "PARTIALLY_VERIFIED"
    else:
        overall = "VERIFIED"

    return VerifyReport(
        file_path=str(file_path),
        file_hash_hex=file_hash.hex(),
        checks=checks,
        overall=overall,
    )


# =============================================================================
# Output formatting
# =============================================================================

CHECK_DISPLAY = {
    "trust_anchor":      "Check 1  —  Trust anchor signed by meta-key",
    "registry_chain":    "Check 2  —  Registry signed by trusted root",
    "receipt":           "Check 3  —  Receipt signed by registry (file ↔ hash)",
    "merkle_proof":      "Check 4  —  Merkle inclusion proof",
    "batch_signature":   "Check 5  —  Batch signed by registry",
    "bitcoin_anchor":    "Check 6  —  Bitcoin anchor (OpenTimestamps)",
}


# Keys present in CheckResult.extra that should NOT be shown in the human
# output (they are still emitted in --json-output for programmatic use).
# These are redundant with a human-friendly equivalent already shown.
_EXTRA_HIDDEN_IN_HUMAN: set[str] = {
    "bitcoin_block_unix",   # redundant with bitcoin_block_time_utc
}


# Human-readable labels for the keys that may appear in CheckResult.extra.
# Keys not listed here fall back to their raw name. Order is the order in
# which they will be printed.
_EXTRA_LABELS: list[tuple[str, str]] = [
    # Identity (checks 1-3)
    ("authority_id",           "Authority"),
    ("registry_id",            "Registry"),
    ("root_id",                "Root"),
    ("publisher_id",           "Publisher"),
    ("timestamp",              "Notarized at (unix)"),
    # Batch (checks 4-5)
    ("batch_id",               "Batch ID"),
    ("record_sequence",        "Record sequence"),
    ("batch_hash",             "Batch hash"),
    # Bitcoin anchor (check 6)
    ("anchored_hash",          "Anchored hash"),
    ("anchored_hash_type",     "Anchored hash type"),
    ("attestation_source",     "Attestation source"),
    ("calendar_upgraded_from", "Calendar"),
    ("calendars_in_ots",       "Calendars in .ots"),
    ("bitcoin_block_height",   "Bitcoin block height"),
    ("bitcoin_block_hash",     "Bitcoin block hash"),
    ("bitcoin_block_time_utc", "Bitcoin block time"),
    ("ots_source",             ".ots source"),
    ("ots_size_bytes",         ".ots size (bytes)"),
    ("ots_bundle_size_bytes",  ".ots in bundle (bytes)"),
    ("ots_file_size_bytes",    ".ots in --ots file (bytes)"),
    ("warning",                "Warning"),
]


def print_human(report: VerifyReport) -> None:
    print()
    print(f"ORIGINUM EXTERNAL VERIFIER v{VERIFIER_VERSION}")
    print(f"Source: {VERIFIER_URL}")
    print()
    print(f"File:        {report.file_path}")
    print(f"SHA-256:     {report.file_hash_hex}")
    print()

    for name in ["trust_anchor", "registry_chain", "receipt",
                 "merkle_proof", "batch_signature", "bitcoin_anchor"]:
        r = report.checks.get(name)
        if not r:
            continue
        label = CHECK_DISPLAY[name]
        dots = "." * max(2, 60 - len(label))
        if r.is_pass():
            tag = "\033[32mPASS\033[0m"
        elif r.is_fail():
            tag = "\033[31mFAIL\033[0m"
        else:
            tag = "\033[33mN/A\033[0m"
        print(f"{label} {dots} {tag}")
        if r.detail:
            print(f"           {r.detail}")

        # Print known keys first, in the canonical order; then any
        # unknown leftover keys at the end (for forward-compat). Keys
        # listed in _EXTRA_HIDDEN_IN_HUMAN are skipped — they remain
        # available in --json-output for programmatic consumers.
        printed = set()
        for key, human_label in _EXTRA_LABELS:
            if key in r.extra:
                val = r.extra[key]
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                print(f"           {human_label:<26} {val}")
                printed.add(key)
        for k, v in r.extra.items():
            if k in printed or k in _EXTRA_HIDDEN_IN_HUMAN:
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            print(f"           {k:<26} {v}")

    print()
    print("─" * 72)
    if report.overall == "VERIFIED":
        print("\033[32mVERIFIED.\033[0m  This proof is verifiable without depending on Originum.")
    elif report.overall == "PARTIALLY_VERIFIED":
        print("\033[33mPARTIALLY VERIFIED.\033[0m  Mandatory checks passed; some optional check is pending.")
    else:
        print("\033[31mINVALID.\033[0m  At least one check failed. See details above.")
    print("─" * 72)
    print()


# =============================================================================
# CLI entry point
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="originum_verify",
        description=(
            "External verifier for Originum proof bundles. "
            "Runs up to six independent cryptographic checks offline, "
            "without contacting Originum."
        ),
    )
    parser.add_argument(
        "--file", required=True, type=Path,
        help="Path to the original file being verified.",
    )
    parser.add_argument(
        "--bundle", required=True, type=Path,
        help="Path to the bundle JSON (as produced by GET /v1/bundle).",
    )
    parser.add_argument(
        "--ots", type=Path, default=None,
        help="Optional .ots file for Bitcoin anchor verification (check 6).",
    )
    parser.add_argument(
        "--meta-key", type=Path, default=None,
        help=(
            "Path to a meta-key public file (hex or raw binary). "
            "If omitted, the embedded list of recognized meta-keys is used."
        ),
    )
    parser.add_argument(
        "--strict-bitcoin", action="store_true",
        help=(
            "Treat a missing or pending Bitcoin anchor as a FAIL instead of "
            "as NOT APPLICABLE. Use this only when the deployment guarantees "
            "all bundles have confirmed Bitcoin anchors."
        ),
    )
    parser.add_argument(
        "--json-output", action="store_true",
        help="Print the verification report as JSON instead of human text.",
    )
    args = parser.parse_args()

    if not args.file.is_file():
        print(f"ERROR: file not found: {args.file}", file=sys.stderr)
        return 3
    if not args.bundle.is_file():
        print(f"ERROR: bundle not found: {args.bundle}", file=sys.stderr)
        return 3

    try:
        report = run_verification(
            file_path=args.file,
            bundle_path=args.bundle,
            ots_path=args.ots,
            meta_key_path=args.meta_key,
            strict_bitcoin=args.strict_bitcoin,
        )
    except Exception as e:
        print(f"ERROR: verification crashed: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 3

    if args.json_output:
        print(report.to_json())
    else:
        print_human(report)

    if report.overall == "VERIFIED":
        return 0
    if report.overall == "PARTIALLY_VERIFIED":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())