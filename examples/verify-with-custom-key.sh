#!/usr/bin/env bash
# =============================================================================
# Example: verify a bundle from a private deployment with its own meta-key.
#
# This is the path for on-premise / enterprise deployments that operate
# their own ORP-001 instance with a meta-key distinct from the Originum
# SaaS one.
#
# The deployment operator distributes its meta-key publicly (it's a
# public key — only the private half is secret). Typical distribution
# channels:
#
#   - The operator's website under .well-known/originum-meta-key.pub
#   - The operator's signed software release notes
#   - Inside the operator's security policy document
#
# Either way, the auditor places the meta-key file alongside the bundle
# and passes it explicitly to the verifier.
# =============================================================================

set -euo pipefail

FILE="${1:-document.pdf}"
BUNDLE="${2:-document-bundle.json}"
META_KEY="${3:-acme-meta-key.pub}"
OTS="${4:-}"

if [ ! -f "$FILE" ] || [ ! -f "$BUNDLE" ] || [ ! -f "$META_KEY" ]; then
    cat <<EOF
Usage: $0 <file> <bundle.json> <meta-key.pub> [batch.ots]

Example:
    $0 contrato.pdf contrato-bundle.json acme-meta-key.pub contrato-batch.ots
EOF
    exit 3
fi

python3 ../originum_verify.py \
    --file     "$FILE" \
    --bundle   "$BUNDLE" \
    --meta-key "$META_KEY" \
    ${OTS:+--ots "$OTS"}
