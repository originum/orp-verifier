# orp-verifier

**External verifier for Originum proof bundles.**
Cryptographic verification of ORP-001 proofs, plus optional Bitcoin anchor
verification, running entirely offline.

License: Apache 2.0
Reference protocol: [ORP-001 v1.0 (Frozen)](https://originum.io)

> **In a hurry?** Skip to [Try it now — public sample](#try-it-now-public-sample)
> to verify a real Originum proof against the Bitcoin blockchain in 30 seconds.

---

## What this is

This tool verifies that a file was notarized by an Originum deployment, by
running independent cryptographic checks against the proof bundle. It does
**not** contact the Originum backend — every check is local, deterministic,
and based on well-known cryptographic primitives.

It implements the five checks defined by ORP-001 v1.0 (trust anchor, registry
chain, receipt, Merkle inclusion, batch signature) plus one extra check that
the Originum-internal verifier does not perform: verification of the .ots
file against the Bitcoin blockchain.

If all checks pass, the file is bound to the deployment that issued the
proof, and the proof remains verifiable even if Originum the company ceases
to exist.

---

## Quick start

### For Originum SaaS bundles (originum.io)

The verifier ships with the meta-key of Originum SaaS embedded by default.

```bash
pip install -r requirements.txt

python originum_verify.py \
    --file factura.pdf \
    --bundle factura-bundle.json
```

Note: the `.ots` file is auto-extracted from the bundle, so you don't need
to pass it separately. If you have a locally-upgraded `.ots` and want to
use it instead of the one embedded in the bundle, pass it with `--ots`.

Expected output on success:

```
ORIGINUM EXTERNAL VERIFIER v1.0.0
Source: https://github.com/originum/orp-verifier

File:        factura.pdf
SHA-256:     a3f29c1e...

Check 1  —  Trust anchor signed by meta-key ........................ PASS
Check 2  —  Registry signed by trusted root ........................ PASS
Check 3  —  Receipt signed by registry (file ↔ hash) ............... PASS
Check 4  —  Merkle inclusion proof ................................. PASS
Check 5  —  Batch signed by registry ............................... PASS
Check 6  —  Bitcoin anchor (OpenTimestamps) ........................ PASS

────────────────────────────────────────────────────────────────────────
VERIFIED.  This proof is verifiable without depending on Originum.
────────────────────────────────────────────────────────────────────────
```

---

## Try it now — public sample

The `samples/` folder contains a real Originum proof you can verify on
your own machine right now. It's a small text file
([`originum-sample-document.txt`](./samples/originum-sample-document.txt))
notarized in the public Originum SaaS registry (`originum-main`), with
its proof bundle
([`originum-sample-document-bundle.json`](./samples/originum-sample-document-bundle.json))
sitting next to it.

From the root of the repository:

```bash
pip install -r requirements.txt

python originum_verify.py \
    --file   samples/originum-sample-document.txt \
    --bundle samples/originum-sample-document-bundle.json
```

You should see all five mandatory ORP-001 checks pass:

```
Check 1  —  Trust anchor signed by meta-key ........................ PASS
Check 2  —  Registry signed by trusted root ........................ PASS
Check 3  —  Receipt signed by registry (file ↔ hash) ............... PASS
Check 4  —  Merkle inclusion proof ................................. PASS
Check 5  —  Batch signed by registry ............................... PASS
Check 6  —  Bitcoin anchor (OpenTimestamps) ........................ PASS or N/A
```

Check 6 may show `PASS` or `N/A` depending on when you run it:

- If you run it more than ~1 hour after the sample was notarized, the
  Bitcoin block that confirms the anchor has been mined and you'll see
  `PASS` with the block height, hash and UTC time.
- If you run it within the first hour, you'll see `N/A` with the message
  *"OTS proof anchored but Bitcoin confirmation still pending."* This is
  the normal transient state and is exactly what the protocol predicts.
  Re-run later, the same bundle will then verify completely. No data
  needs to change — Bitcoin mines a new block on average every ten
  minutes, and the OpenTimestamps calendars pick it up automatically.

### What you've just demonstrated

If the run reports `VERIFIED` (or `PARTIALLY VERIFIED` with check 6
pending), then a piece of code you can read and audit — running on your
own machine, with no network connection to Originum — has independently
confirmed every link of the cryptographic chain:

  1. The trust anchor was signed by Originum's offline authority key.
  2. The registry `originum-main` was endorsed by a trusted root.
  3. The receipt for this file was signed by that registry.
  4. The file was included in a Merkle batch.
  5. That batch was signed by the registry.
  6. The batch's anchor commitment was timestamped in a Bitcoin block
     (or is on its way to being timestamped).

The proof remains valid forever, because the Bitcoin blockchain is not
under Originum's control. Even if Originum the company ceased to exist
tomorrow, this `samples/` folder, this verifier, and the Bitcoin
blockchain would still be enough to prove the file existed and was
notarized at a specific moment in time.

That is the promise of ORP-001. This folder is a working proof of it.

---

## For private / on-premise deployments

If you receive a bundle from an organization running its own Originum
deployment with its own meta-key, pass that meta-key explicitly:

```bash
python originum_verify.py \
    --file factura.pdf \
    --bundle factura-bundle.json \
    --ots factura-batch.ots \
    --meta-key acme-meta-key.pub
```

The meta-key file can be either:

- A hex-encoded public key (with or without `0x` prefix, whitespace OK).
- Raw binary in SEC1 uncompressed form (65 bytes starting with `0x04`)
  or in raw `X || Y` form (64 bytes).

The meta-key is public by definition — only the private half is secret.
Deployment operators typically publish their meta-key on their website
under a `.well-known/` path or include it alongside each bundle.

---

## How it works

The verifier walks the cryptographic chain defined by ORP-001:

```
authority (meta-key, embedded)
   │  signs
   ▼
trust_anchor              ◄── Check 1
   │  lists
   ▼
roots
   │  one of them signs
   ▼
registry                  ◄── Check 2
   │  signs
   ▼
receipt   ─── content_hash == SHA-256(file) ◄── Check 3
   │
   │  leaf is included via Merkle proof
   ▼
merkle_root               ◄── Check 4
   │
   │  is part of batch_hash
   ▼
batch_hash                ◄── Check 5
   │  signed by registry
   │
   │  anchored in Bitcoin via OpenTimestamps
   ▼
Bitcoin block             ◄── Check 6 (optional)
```

Each check is implemented as a separate, auditable function in
[`originum_verify.py`](./originum_verify.py). No proprietary crypto.

### What each check proves

| # | Check | What it proves |
|---|---|---|
| 1 | Trust anchor | The list of roots was published by a recognized authority. |
| 2 | Registry chain | The registry is endorsed by one of those roots. |
| 3 | Receipt | The file (by SHA-256) was registered, and the registry signed an attestation of that. |
| 4 | Merkle inclusion | The file is included in a specific batch. |
| 5 | Batch signature | The batch is endorsed by the registry (and thus cannot be silently rewritten). |
| 6 | Bitcoin anchor | The batch existed before a specific Bitcoin block was mined. |

Checks 1–3 are **mandatory** — they prove that the file is bound to the
deployment. Checks 4–6 are **optional** — they may show as "not applicable"
when the batch has not yet been sealed or the .ots has not yet been
confirmed in a Bitcoin block (this is a transient state, typically
under one hour).

---

## How meta-keys are recognized

This verifier embeds a list of meta-keys it recognizes by default — see
[`trusted_meta_keys.py`](./trusted_meta_keys.py). The Originum SaaS meta-key
is in that list.

There are three first-class ways to verify bundles from deployments that
are NOT in the embedded list:

### Option 1 — Use `--meta-key` per-invocation

The simplest path. The deployment operator distributes its meta-key
publicly (it's a public key, not a secret). Auditors and end-users pass
it on the command line.

### Option 2 — Fork the repository and rebuild

Clone this repository, edit `trusted_meta_keys.py` to add the meta-keys
relevant to your organization, and distribute the resulting verifier
internally. This is the recommended path for organizations that prefer
controlling the verifier binary used inside their perimeter.

### Option 3 — Request inclusion in the public list

Submit a pull request to this repository adding your deployment to
`trusted_meta_keys.py`. The Originum team reviews the request, verifies
the binding between the public key and the declared identity, and merges.
Your meta-key takes effect in the next tagged release of this verifier.

All three paths are equally legitimate. The choice depends on whether the
deployment wants public visibility, internal control, or maximum
distribution simplicity.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | VERIFIED. All mandatory checks passed. |
| `2` | PARTIALLY VERIFIED. Mandatory checks passed; some optional check is "not applicable" (e.g. batch not yet sealed). |
| `1` | INVALID. At least one check failed. |
| `3` | Usage error (file not found, malformed arguments). |

These exit codes are stable. Scripts can rely on them.

---

## JSON output

Pass `--json-output` to get a machine-readable report. Useful for CI,
batch verification, or integration with audit tooling.

```bash
python originum_verify.py \
    --file factura.pdf \
    --bundle factura-bundle.json \
    --ots factura-batch.ots \
    --json-output
```

```json
{
  "verifier_version": "1.0.0",
  "verifier_url": "https://github.com/originum/orp-verifier",
  "file": "factura.pdf",
  "file_hash": "a3f29c1e...",
  "result": "VERIFIED",
  "checks": {
    "trust_anchor":     {"status": "pass", "detail": "...", "authority_id": "originum-authority"},
    "registry_chain":   {"status": "pass", "detail": "...", "registry_id": "originum-main"},
    "receipt":          {"status": "pass", "detail": "...", "publisher_id": "..."},
    "merkle_proof":     {"status": "pass", "detail": "...", "batch_id": 42},
    "batch_signature":  {"status": "pass", "detail": "..."},
    "bitcoin_anchor":   {"status": "pass", "detail": "...", "bitcoin_attestation": "Bitcoin block ..."}
  }
}
```

---

## Strict mode for the Bitcoin anchor

By default, if the .ots file is missing or the anchor is still pending
Bitcoin confirmation, check 6 reports `not_applicable` and the overall
result is `PARTIALLY_VERIFIED` (exit code 2). This is the right behaviour
for general use: a freshly notarized file is typically `PARTIALLY_VERIFIED`
for up to one hour while it waits for Bitcoin confirmation, then becomes
`VERIFIED` automatically once the .ots is upgraded.

For workflows that require a confirmed Bitcoin anchor unconditionally
(typically archival pipelines that re-verify older bundles), pass
`--strict-bitcoin`. Missing or pending anchors then cause `INVALID`.

---

## Dependencies

Three Python packages. All mature, all pure Python (no native dependencies):

- **`cryptography`** — ECDSA P-256, SHA-256.
- **`cbor2`** — Deterministic CBOR decoding.
- **`opentimestamps`** — Pure-Python parser for the `.ots` format and
  HTTP client for OpenTimestamps calendars. Only needed for check 6.

Install everything with:

```bash
pip install -r requirements.txt
```

The verifier deliberately avoids `opentimestamps-client`, which pulls in
`python-bitcoinlib` and requires OpenSSL native DLLs — that combination
is broken on Windows + Python 3.13. By using only the pure-Python format
parser and the calendar HTTP client, this verifier runs identically on
Windows, Linux and macOS with no native dependencies.

---

## Building a standalone binary

To produce a single-file binary for distribution (e.g. for non-Python
environments), use PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --name orp-verify originum_verify.py
```

This produces `dist/orp-verify` (or `orp-verify.exe` on Windows). The
binary embeds all dependencies and the recognized meta-keys.

---

## Status and stability

This verifier targets **ORP-001 v1.0 (Frozen)**, which is a stable
specification by design (no breaking changes within v1.x). The verifier
itself follows semantic versioning. Backward-compatible additions to the
bundle format (such as `bitcoin_anchor`) are supported transparently.

---

## Contributing

Issues and pull requests welcome at
[github.com/originum/orp-verifier](https://github.com/originum/orp-verifier).

For security issues, see [SECURITY.md](./SECURITY.md).

---

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
