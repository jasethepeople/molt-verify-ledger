# molt-verify-ledger

A standalone, read-only Node.js CLI that verifies every event in a MOLT `events.jsonl` ledger. It uses only Node.js built-ins and the included, unchanged `molt-canonical.mjs`; there are no dependencies, install steps, build steps, keys, or network access.

## Run it

Node.js 22 or 24 is supported. From this directory:

```sh
node molt-verify-ledger.mjs --ledger /path/to/events.jsonl
```

Run the test suite with:

```sh
npm test
```

The verifier reads the ledger only. It does not append to or modify it and does not need a key file.

## Checks

For each non-empty line, in ledger order, the verifier checks:

1. The line is valid JSON.
2. The line exactly matches `canonicalizeJsonText` output.
3. The event has exactly these fields: `seq`, `ts`, `type`, `actor`, `payload`, `prev_hash`, `pub`, `sig`, and `hash`.
4. Field formats: non-negative safe integer `seq` and `ts`; string `type` and `actor`; 64 lowercase hexadecimal characters for `prev_hash`, `pub`, and `hash`; 128 lowercase hexadecimal characters for `sig`.
5. `seq` matches the event's zero-based position.
6. The chain link is correct: the first event points to 64 zeroes; each later event points to the prior event's recomputed hash.
7. The SHA-256 hash recomputes from the 64-character `prev_hash` text followed by the canonical Camp 1 five-field body: `seq`, `ts`, `type`, `payload`, `actor`.
8. The Ed25519 signature verifies over the 32 raw bytes of the recomputed hash using the raw public key recorded in `pub`.

This matches the Camp 1 scheme used by `molt-verify`, `molt-event`, and the MOLT audit writer for ASCII event content. MOLT-CORE leaves non-ASCII canonicalization open; cross-implementation agreement for non-ASCII content is not yet guaranteed.

Each event is reported as `seq N: PASS` or `seq N: FAIL (reason1, reason2)`. `N` is its zero-based position in the ledger. The final line is `VALID: M events` if every event passes, or `INVALID: M events, F failed` if any event fails. An empty ledger is valid and prints `VALID: 0 events`.

Exit codes: `0` for a valid ledger, `1` for a ledger with failed events, and `2` for an unreadable/missing ledger, invalid UTF-8, or invalid command-line usage. Operational errors go to stderr and do not print a report.

## Pairing with molt-event

`molt-event` appends signed events to an `events.jsonl` ledger using the same canonical body, SHA-256 chain, and Ed25519 signature scheme. Run this verifier afterward to independently check the entire ledger, using only each event's recorded public key; it does not require the writer's identity file or private key.
