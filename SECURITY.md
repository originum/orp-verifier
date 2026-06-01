# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in this verifier — for example, a
case where the verifier reports `VERIFIED` for a bundle that should be
rejected, or `INVALID` for a bundle that should pass — please do **not**
open a public issue.

Instead, send a private report to:

- **security@originum.io**

We aim to acknowledge reports within 2 business days and to release a fix
within 30 days for confirmed vulnerabilities. Coordinated disclosure is
preferred; we credit reporters in release notes unless they ask to remain
anonymous.

## Scope

This policy covers:

- Cryptographic correctness of the six checks.
- Handling of malformed input (the verifier should never crash; it should
  return INVALID with a clear explanation).
- The embedded list of recognized meta-keys.

Out of scope (please report to upstream instead):

- Vulnerabilities in `cryptography`, `cbor2`, or `opentimestamps-client`.
- Vulnerabilities in the Originum backend (report to security@originum.io
  with a separate subject).

## Independent review

This verifier is open source under Apache 2.0 specifically so it can be
audited independently. We welcome and encourage independent security
reviews. If you publish a review, we are happy to link to it from the
project documentation.
