# =============================================================================
# Trusted meta-keys recognized by this verifier
# =============================================================================
#
# A "meta-key" is the public half of the offline authority keypair that signs
# the trust_anchor of an ORP-001 deployment. The trust_anchor lists the roots
# of that deployment, the roots sign registries and issuers, and so on down
# the chain.
#
# This file is the verifier's "root of trust": if the trust_anchor of an
# incoming bundle does not verify against any meta-key listed here, the
# verifier rejects the bundle (unless the caller passes --meta-key explicitly).
#
# Each entry is a public ECDSA P-256 key in raw uncompressed form
# (65 bytes: 0x04 || X(32) || Y(32)), encoded as hex.
#
# -----------------------------------------------------------------------------
# Adding a new entry
# -----------------------------------------------------------------------------
#
# To get a meta-key into this list, a deployment operator submits a pull
# request to the orp-verifier repository on GitHub including:
#
#   - The hex of the public key (65 bytes uncompressed).
#   - The authority_id declared in the deployment's trust_anchor.
#   - A description identifying the operator and a public URL where the
#     operator publishes its trust practices and contact information.
#
# The Originum team reviews the request, verifies the binding between the
# public key and the declared identity, and merges. The new meta-key takes
# effect in the next tagged release of this verifier.
#
# Operators who prefer not to appear in this public list have two
# alternatives:
#
#   1. Distribute their meta-key separately and have verifiers use --meta-key.
#   2. Fork this repository, embed their own meta-keys, build a private
#      binary, and distribute it internally.
#
# Both paths are first-class and documented in the README.
#
# -----------------------------------------------------------------------------
# Rotation
# -----------------------------------------------------------------------------
#
# When an operator rotates its meta-key, both the old and the new entries
# coexist in this list during the overlap window (typically 6-12 months).
# Bundles signed by either are accepted. After the overlap closes, the old
# entry is removed in a tagged release.

TRUSTED_META_KEYS = [
    # -------------------------------------------------------------------------
    # Originum SaaS — public production deployment at originum.io
    # -------------------------------------------------------------------------
    # Meta-key v1, generated in the offline CA ceremony and embedded in the
    # production SDK. The same public key is used to sign the trust_anchor
    # of the originum-main registry.
    {
        "authority_id": "originum-authority",
        "description":  "Originum SaaS production (originum.io)",
        "key_version":  1,
        "added":        "2026-05-30",
        "public_key_hex": (
            "04"
            # X coordinate (32 bytes)
            "1d0a2fd50a9ce859e28777081cd7c333908e560007c6cc920bdd1271816e910b"
            # Y coordinate (32 bytes)
            "522bf18d8019efd72408caf8bad2992dde179f866d7b86f8ce14e0d1172dfeaa"
        ),
    },
    # Future deployments - submit a PR to add yours. Examples:
    #
    # {
    #     "authority_id": "acme-corp-authority",
    #     "description":  "Acme Corp on-premise deployment",
    #     "key_version":  1,
    #     "added":        "2026-XX-XX",
    #     "public_key_hex": "04...",
    # },
]
