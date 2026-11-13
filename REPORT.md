# MOLT ledger verifier — Camp 1 compatibility

The verifier now checks the MOLT-CORE Camp 1 hash and signature rules: hash the 64-character `prev_hash` text plus the canonical five-field body (`seq`, `ts`, `type`, `payload`, `actor`), then verify Ed25519 over the 32 raw hash bytes.

## Verification

- `npm test`: 17 passed, 0 failed.
- The shared `molt-verify` L1 `sample-good` ledger is accepted.
- Tampering, broken links, wrong sequences, malformed fields, bad signatures, invalid JSON/UTF-8, and unreadable paths remain covered.
- End-to-end test path passed: `molt-event` → this verifier → `molt-verify` L1 package verifier → `molt-anchor`.

Cross-implementation interoperability is confirmed for ASCII event content. MOLT-CORE leaves non-ASCII canonicalization open; this update does not change the shared RFC 8785 canonicalizer.

The verifier is read-only. Tests use temporary keys and ledgers; no real ledger or key was accessed.
