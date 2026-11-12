import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonicalizeJsonText } from '../molt-canonical.mjs';

const verifierPath = new URL('../molt-verify-ledger.mjs', import.meta.url);
const zeroHash = '0'.repeat(64);

function makeKeypair() {
  const pair = generateKeyPairSync('ed25519');
  const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' });
  return { privateKey: pair.privateKey, publicKeyHex: publicDer.subarray(-32).toString('hex') };
}

function makeEvent({ seq, prevHash, signer, publicKeyHex = signer.publicKeyHex }) {
  const body = {
    seq,
    ts: 1700000000 + seq,
    type: 'record.created',
    actor: 'test-suite',
    payload: { entry: `event-${seq}`, values: [seq, true] },
    prev_hash: prevHash,
    pub: publicKeyHex,
  };
  const canonicalBody = canonicalizeJsonText(JSON.stringify(body));
  const hash = createHash('sha256').update(prevHash + canonicalBody, 'utf8').digest('hex');
  const sig = sign(null, Buffer.from(canonicalBody, 'utf8'), signer.privateKey).toString('hex');
  return { ...body, sig, hash };
}

function makeLedger(count = 3) {
  const signer = makeKeypair();
  const events = [];
  let previousHash = zeroHash;
  for (let seq = 0; seq < count; seq++) {
    const event = makeEvent({ seq, prevHash: previousHash, signer });
    events.push(canonicalizeJsonText(JSON.stringify(event)));
    previousHash = event.hash;
  }
  return events;
}

function mutateLine(lines, index, mutate) {
  const event = JSON.parse(lines[index]);
  mutate(event);
  lines[index] = canonicalizeJsonText(JSON.stringify(event));
  return lines.join('\n');
}

async function runLedger(t, contents) {
  const dir = await mkdtemp(join(tmpdir(), 'molt-verify-ledger-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const ledgerPath = join(dir, 'events.jsonl');
  await writeFile(ledgerPath, contents);
  return spawnSync(process.execPath, [verifierPath.pathname, '--ledger', ledgerPath], { encoding: 'utf8' });
}

function assertFail(result, seq, reasons) {
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stdout, new RegExp(`^seq ${seq}: FAIL \\(`, 'm'));
  for (const reason of reasons) assert.match(result.stdout, new RegExp(reason));
  assert.match(result.stdout, /INVALID: /);
}

test('valid three-event ledger passes every event', async t => {
  const result = await runLedger(t, `${makeLedger().join('\n')}\n`);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.stdout.trim().split('\n'), [
    'seq 0: PASS',
    'seq 1: PASS',
    'seq 2: PASS',
    'VALID: 3 events',
  ]);
});

test('tampered payload fails its hash and signature and breaks the next link', async t => {
  const lines = makeLedger();
  const contents = mutateLine(lines, 1, event => { event.payload.entry = 'event-1!'; });
  const result = await runLedger(t, contents);
  assertFail(result, 1, ['hash mismatch', 'bad signature']);
  assert.match(result.stdout, /^seq 0: PASS$/m);
  assert.match(result.stdout, /^seq 2: FAIL \(chain broken/m);
});

test('broken previous hash is reported', async t => {
  const lines = makeLedger();
  const contents = mutateLine(lines, 1, event => { event.prev_hash = zeroHash; });
  const result = await runLedger(t, contents);
  assertFail(result, 1, ['chain broken']);
});

test('wrong sequence is reported', async t => {
  const lines = makeLedger();
  const contents = mutateLine(lines, 1, event => { event.seq = 5; });
  const result = await runLedger(t, contents);
  assertFail(result, 1, ['seq out of order']);
});

test('non-canonical event line is reported', async t => {
  const lines = makeLedger();
  lines[0] = lines[0].replace('{', '{ ');
  const result = await runLedger(t, lines.join('\n'));
  assertFail(result, 0, ['not canonical']);
});

test('bad signature is reported while the hash still passes', async t => {
  const lines = makeLedger();
  const contents = mutateLine(lines, 0, event => {
    event.sig = `${event.sig[0] === '0' ? '1' : '0'}${event.sig.slice(1)}`;
  });
  const result = await runLedger(t, contents);
  assertFail(result, 0, ['bad signature']);
  assert.doesNotMatch(result.stdout, /hash mismatch/);
});

test('missing field is reported', async t => {
  const lines = makeLedger();
  const contents = mutateLine(lines, 0, event => { delete event.pub; });
  const result = await runLedger(t, contents);
  assertFail(result, 0, ['wrong fields']);
});

test('empty ledger is valid', async t => {
  const result = await runLedger(t, '');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'VALID: 0 events\n');
});

test('missing ledger exits with code 2 and no report', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'molt-verify-ledger-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const missingPath = join(dir, 'missing.jsonl');
  const result = spawnSync(process.execPath, [verifierPath.pathname, '--ledger', missingPath], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /cannot read ledger/);
});

test('event signed by another key fails against its recorded public key', async t => {
  const signer = makeKeypair();
  const recordedKey = makeKeypair();
  const event = makeEvent({ seq: 0, prevHash: zeroHash, signer, publicKeyHex: recordedKey.publicKeyHex });
  const result = await runLedger(t, canonicalizeJsonText(JSON.stringify(event)));
  assertFail(result, 0, ['bad signature']);
});

test('bad hash format is reported', async t => {
  const lines = makeLedger();
  const contents = mutateLine(lines, 0, event => { event.hash = event.hash.slice(1); });
  const result = await runLedger(t, contents);
  assertFail(result, 0, ['bad field format', 'hash mismatch']);
});

test('extra field is reported', async t => {
  const lines = makeLedger();
  const contents = mutateLine(lines, 0, event => { event.extra = 'not allowed'; });
  const result = await runLedger(t, contents);
  assertFail(result, 0, ['wrong fields']);
});

test('invalid JSON is reported as an invalid event', async t => {
  const result = await runLedger(t, '{not json');
  assert.equal(result.status, 1);
  assert.equal(result.stdout, 'seq 0: FAIL (invalid JSON)\nINVALID: 1 events, 1 failed\n');
});

test('invalid UTF-8 exits with code 2 and no report', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'molt-verify-ledger-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const ledgerPath = join(dir, 'events.jsonl');
  await writeFile(ledgerPath, Buffer.from([0xc3, 0x28]));
  const result = spawnSync(process.execPath, [verifierPath.pathname, '--ledger', ledgerPath], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /not valid UTF-8/);
});

test('unreadable ledger path exits with code 2 and no report', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'molt-verify-ledger-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const directoryPath = join(dir, 'directory');
  await mkdir(directoryPath);
  const result = spawnSync(process.execPath, [verifierPath.pathname, '--ledger', directoryPath], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /cannot read ledger/);
});
