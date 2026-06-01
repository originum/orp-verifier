#!/usr/bin/env bash
# =============================================================================
# Example: verify an Originum SaaS bundle.
#
# The Originum SaaS meta-key is already embedded in the verifier, so no
# --meta-key argument is needed. The .ots file is auto-extracted from
# the bundle's bitcoin_anchor field, so --ots is also not needed in the
# common case.
# =============================================================================

set -euo pipefail

FILE="${1:-factura.pdf}"
BUNDLE="${2:-factura-bundle.json}"

if [ ! -f "$FILE" ] || [ ! -f "$BUNDLE" ]; then
    cat <<USAGE
Usage: $0 <file> <bundle.json>

The bundle JSON is what GET /v1/bundle returns when status == "complete".
The .ots is embedded inside the bundle in modern Originum versions; if
your bundle is older and doesn't carry it, pass the .ots file as a third
argument.

Example:
    $0 factura.pdf factura-bundle.json
USAGE
    exit 3
fi

python3 ../originum_verify.py \
    --file    "$FILE" \
    --bundle  "$BUNDLE"
