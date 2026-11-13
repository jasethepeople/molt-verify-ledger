#!/usr/bin/env node
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { TextDecoder } from 'node:util';
import { pathToFileURL } from 'node:url';
import { canonicalizeJsonText } from './molt-canonical.mjs';

const FIELD_NAMES = ['seq', 'ts', 'type', 'actor', 'payload', 'prev_hash', 'pub', 'sig', 'hash'];
const ZERO_HASH = '0'.repeat(64);
const HASH_FORMAT = /^[0-9a-f]{64}$/;
const SIGNATURE_FORMAT = /^[0-9a-f]{128}$/;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function checkEvent(line, index, previousRecomputedHash) {
  const failures = [];
  let parsed;

  try {
    parsed = JSON.parse(line);
  } catch {
    return { failures: ['invalid JSON'], recomputedHash: null };
  }

  let canonicalLine;
  try {
    canonicalLine = canonicalizeJsonText(line);
  } catch {
    failures.push('not canonical');
  }
  if (canonicalLine !== undefined && canonicalLine !== line) failures.push('not canonical');

  const event = parsed !== null && typeof parsed === 'object' ? parsed : {};
  const keys = Object.keys(event);
  const fieldsAreExact = !Array.isArray(event)
    && keys.length === FIELD_NAMES.length
    && FIELD_NAMES.every(field => Object.hasOwn(event, field));
  if (!fieldsAreExact) failures.push('wrong fields');

  const formatsAreValid = Number.isSafeInteger(event.seq) && event.seq >= 0
    && Number.isSafeInteger(event.ts) && event.ts >= 0
    && typeof event.type === 'string'
    && typeof event.actor === 'string'
    && typeof event.prev_hash === 'string' && HASH_FORMAT.test(event.prev_hash)
    && typeof event.pub === 'string' && HASH_FORMAT.test(event.pub)
    && typeof event.sig === 'string' && SIGNATURE_FORMAT.test(event.sig)
    && typeof event.hash === 'string' && HASH_FORMAT.test(event.hash);
  if (!formatsAreValid) failures.push('bad field format');

  if (event.seq !== index) failures.push('seq out of order');

  if (event.seq === 0) {
    if (event.prev_hash !== ZERO_HASH) failures.push('chain broken');
  } else if (Number.isSafeInteger(event.seq) && event.seq > 0) {
    if (previousRecomputedHash === null || event.prev_hash !== previousRecomputedHash) {
      failures.push('chain broken');
    }
  } else {
    failures.push('chain broken');
  }

  let canonicalBody;
  if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const signedBody = {
      seq: event.seq,
      ts: event.ts,
      type: event.type,
      payload: event.payload,
      actor: event.actor,
    };
    try {
      canonicalBody = canonicalizeJsonText(JSON.stringify(signedBody));
    } catch {
      canonicalBody = undefined;
    }
  }
  let recomputedHash = null;
  if (canonicalBody !== undefined && typeof event.prev_hash === 'string') {
    recomputedHash = createHash('sha256')
      .update(event.prev_hash + canonicalBody, 'utf8')
      .digest('hex');
  }
  if (recomputedHash === null || event.hash !== recomputedHash) failures.push('hash mismatch');

  let signatureIsValid = false;
  if (recomputedHash !== null && typeof event.pub === 'string' && HASH_FORMAT.test(event.pub)
      && typeof event.sig === 'string' && SIGNATURE_FORMAT.test(event.sig)) {
    try {
      const publicKey = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(event.pub, 'hex')]),
        format: 'der',
        type: 'spki',
      });
      signatureIsValid = verifySignature(
        null,
        Buffer.from(recomputedHash, 'hex'),
        publicKey,
        Buffer.from(event.sig, 'hex'),
      );
    } catch {
      signatureIsValid = false;
    }
  }
  if (!signatureIsValid) failures.push('bad signature');

  return { failures, recomputedHash };
}

function decodeUtf8(bytes) {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--ledger' || args[1].length === 0) {
    throw new Error('usage: node molt-verify-ledger.mjs --ledger LEDGER');
  }

  let bytes;
  try {
    bytes = await readFile(args[1]);
  } catch (error) {
    throw new Error(`cannot read ledger "${args[1]}": ${error.message}`);
  }

  let text;
  try {
    text = decodeUtf8(bytes);
  } catch {
    throw new Error('ledger is not valid UTF-8');
  }

  const report = [];
  let previousRecomputedHash = null;
  let eventIndex = 0;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    if (line.length === 0) continue;

    const result = checkEvent(line, eventIndex, previousRecomputedHash);
    if (result.failures.length === 0) {
      report.push(`seq ${eventIndex}: PASS`);
    } else {
      report.push(`seq ${eventIndex}: FAIL (${result.failures.join(', ')})`);
    }
    previousRecomputedHash = result.recomputedHash;
    eventIndex++;
  }

  const failedCount = report.reduce((count, line) => count + Number(line.includes(': FAIL ')), 0);
  report.push(failedCount === 0
    ? `VALID: ${eventIndex} events`
    : `INVALID: ${eventIndex} events, ${failedCount} failed`);
  process.stdout.write(`${report.join('\n')}\n`);
  process.exitCode = failedCount === 0 ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    process.stderr.write(`molt-verify-ledger: ${error.message}\n`);
    process.exitCode = 2;
  });
}
