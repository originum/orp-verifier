# Building a custom verifier for an on-premise deployment

If your organization runs its own Originum deployment with its own
meta-key, and you want users to verify bundles without passing
`--meta-key` every time, you can build a custom version of this
verifier with your meta-key embedded.

This is the same path that Originum follows for the SaaS verifier:
the SaaS meta-key is just an entry in `trusted_meta_keys.py`.

## Steps

### 1. Clone the repository

```bash
git clone https://github.com/originum/orp-verifier.git acme-verifier
cd acme-verifier
```

### 2. Edit `trusted_meta_keys.py`

Add your deployment's meta-key to the `TRUSTED_META_KEYS` list. The
public key must be in raw uncompressed P-256 form (65 bytes:
`0x04 || X || Y`), encoded as hex.

```python
TRUSTED_META_KEYS = [
    # Optionally keep the Originum SaaS entry if you want your binary
    # to verify SaaS bundles too. Otherwise remove it.
    # {
    #     "authority_id": "originum-authority",
    #     ...
    # },

    {
        "authority_id": "acme-corp-authority",
        "description":  "Acme Corp on-premise deployment",
        "added":        "2026-XX-XX",
        "public_key_hex": (
            "04"
            "abc123..."  # your X coordinate, 32 bytes hex
            "def456..."  # your Y coordinate, 32 bytes hex
        ),
    },
]
```

### 3. Adjust branding (optional)

If you want your binary to identify itself as "Acme Verifier" instead
of "Originum External Verifier", edit the constants at the top of
`originum_verify.py`:

```python
VERIFIER_VERSION = "1.0.0"
VERIFIER_URL = "https://internal.acme.com/orp-verifier"
```

### 4. Build a standalone binary

```bash
pip install -r requirements.txt
pip install pyinstaller

pyinstaller \
    --onefile \
    --name acme-verifier \
    --add-data "trusted_meta_keys.py:." \
    originum_verify.py
```

The result is `dist/acme-verifier` (or `acme-verifier.exe` on Windows),
a single self-contained executable with your meta-keys embedded.

### 5. Distribute internally

Sign and distribute the binary via your usual software distribution
channels. Verify the signature on the binary the same way you would
for any other internally-trusted tool.

Internal users now run:

```bash
acme-verifier --file factura.pdf --bundle factura-bundle.json --ots factura-batch.ots
```

No `--meta-key` argument needed.

## Compliance with the Apache 2.0 license

You can rebrand, modify, and redistribute the verifier under the terms
of Apache 2.0. The license requires that:

- You preserve the copyright notices and the LICENSE file in your
  source distribution.
- If you modify the code, you mark the modified files as such.
- You do not use the "Originum" trademark in a way that suggests
  endorsement by Originum (you can describe yourself as compatible
  with ORP-001 v1.0).

You do not have to publish your modifications. The custom binary
with your meta-keys is yours to distribute as you see fit.

## Alternative: in-place meta-key list

If you prefer not to build a standalone binary, you can simply maintain
a fork (or branch) of this repository with your `trusted_meta_keys.py`
modified, and have your users `git clone` and run the Python script
directly. The downside is that your users need a working Python
environment; the upside is zero build infrastructure.
