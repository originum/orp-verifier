# Changelog

All notable changes to this project will be documented here.

This project adheres to [Semantic Versioning](https://semver.org/).
Format inspired by [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-06-01

Initial public release.

### Verification

- Implements the five mandatory ORP-001 verification checks:
  `trust_anchor`, `registry_chain`, `receipt` (with file ↔ hash
  binding), `merkle_proof`, and `batch_signature`.
- Adds an optional sixth check that verifies the Bitcoin anchor of the
  batch via OpenTimestamps. The verifier handles both the
  `anchor_commitment_v1` format (ORP-001 §14 conformant) and the
  `merkle_root_legacy` format (batches sealed before
  FIX [ANCHOR-1] in the backend).

### Implementation

- Pure Python; no native dependencies. Uses `cryptography`, `cbor2`,
  and `opentimestamps` (the format parser, not the
  `opentimestamps-client` package — which is broken on
  Windows + Python 3.13).
- Ships with the Originum SaaS meta-key embedded by default; supports
  arbitrary meta-keys via `--meta-key` for private deployments, and
  source-level customization via `trusted_meta_keys.py` for forks.
- `.ots` file is auto-extracted from the bundle's
  `proof.bitcoin_anchor.ots` field when the bundle is from a backend
  version that includes it; `--ots` is still supported as override.
- Best-effort enrichment of the Bitcoin anchor report with block hash
  and block timestamp via `mempool.space` public API (best-effort —
  failure to reach mempool.space does not affect the PASS decision).

### Output

- Human-readable output by default, with one line per check and
  labelled fields per check result.
- `--json-output` emits a machine-readable report suitable for CI
  pipelines or downstream tooling.
- `--strict-bitcoin` makes a missing or still-pending Bitcoin anchor
  a hard FAIL instead of `not_applicable`.

### Tests

- Five smoke tests in `tests/test_smoke.py` covering: COSE_Sign1
  round-trip, COSE verification against the wrong key, full bundle
  verification with a custom meta-key, detection of file tampering,
  and rejection of an incorrect meta-key.

### Licensing

- Licensed under Apache 2.0.
