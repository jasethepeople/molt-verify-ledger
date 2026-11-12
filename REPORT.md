Verdict: YES — the verifier checks MOLT ledger canonicalization, field formats, chain links, SHA-256 hashes, and Ed25519 signatures.
Tests: 15 passed, 0 failed (`npm test`, Node v22.23.4).

## Files

- `molt-verify-ledger.mjs` — read-only ledger verifier CLI.
- `molt-canonical.mjs` — supplied canonicalizer, copied unchanged (SHA-256: `5e4c0503fbefa64503616551bc56e743e4681e40a009590f9eaf315a9c8dcff3`).
- `tests/verify-ledger.test.mjs` — built-in Node test runner tests with fresh ephemeral Ed25519 keypairs.
- `package.json` — `npm test` runs `node --test`; no dependencies.
- `README.md` — usage, checks, output, exit codes, and pairing with `molt-event`.
- `REPORT.md` — this verification report.

## Test results

Command: `npm test`

Result: 15 tests passed, 0 failed. The 12 requested cases all pass, along with additional coverage for invalid JSON, invalid UTF-8, and an unreadable ledger path. Tests ran with Node v22.23.4.

## Checks implemented

The verifier performs the eight requested checks in order for every non-empty event line: valid JSON; canonical line; exact field set; field formats; sequence order; previous-hash chain link; recomputed SHA-256 hash; and Ed25519 signature verification using the event's raw public key. Subsequent links use the prior event's recomputed hash, not its stored hash.

## Open items

Node 24 was not installed in the available environment, so the suite could not be run under Node 24. The implementation uses Node built-ins available in Node 22 and 24. No product decisions remain.

## What was NOT done

- No network access, repository push, or deployment.
- No ledger was modified; the CLI only reads its input.
- No real key or manifest signer key was accessed. Tests generate temporary keypairs in memory; no test key is committed.
