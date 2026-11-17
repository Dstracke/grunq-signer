#!/usr/bin/env node
// Verify and apply NIP-05 claims for grunq.com.
//
// A user prepares a claim in the extension (profile → "Claim name@grunq.com")
// and sends it by e-mail. The operator runs this tool against the claim and the
// live nostr.json:
//
//   node tools/nip05-claim.mjs verify --name luku --npub npub1… \
//     --issued 2026-11-17T11:00:00.000Z --signature <128-hex>
//
//   node tools/nip05-claim.mjs apply --file ../grunq/deploy/landing/.well-known/nostr.json \
//     --name luku --npub npub1… --issued 2026-11-17T11:00:00.000Z --signature <128-hex>
//
// `apply` verifies first, refuses names owned by another key and writes the
// file atomically (sorted names/relays). Deploy afterwards (rsync), see
// deploy/README.md in the Grunq repository.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { npubToHex, verifyClaim } from '../src/signer/claim.js';
import { normalizeDoc, serializeDoc, upsertName } from '../src/signer/nip05store.js';

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const args = {};
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i];
    const value = rest[i + 1];
    if (!key?.startsWith('--') || value === undefined) {
      throw new Error(`unexpected argument: ${key}`);
    }
    args[key.slice(2)] = value;
  }
  return { command, args };
}

function fail(message, code = 1) {
  console.error(`error: ${message}`);
  process.exit(code);
}

function requireArgs(args, names) {
  for (const name of names) {
    if (!args[name]) fail(`missing --${name}`);
  }
}

function describe() {
  return `name=${args.name} pubkey=${pubkey} issued=${args.issued}`;
}

let command;
let args;
let pubkey;

try {
  ({ command, args } = parseArgs(process.argv.slice(2)));
} catch (e) {
  fail(e.message);
}

if (command !== 'verify' && command !== 'apply') {
  fail('usage: nip05-claim.mjs verify|apply --name … --npub … --issued … --signature … [--file …]');
}
requireArgs(args, ['name', 'npub', 'issued', 'signature']);

try {
  pubkey = npubToHex(args.npub);
} catch {
  fail('invalid --npub');
}

const check = verifyClaim({
  pubkey,
  name: args.name,
  issuedAt: args.issued,
  signature: args.signature,
});
if (!check.ok) {
  fail(`claim rejected: ${check.code}`);
}

if (command === 'verify') {
  console.log(`ok: claim valid for ${args.name}@grunq.com (${describe()})`);
  process.exit(0);
}

requireArgs(args, ['file']);
let current;
try {
  current = JSON.parse(readFileSync(args.file, 'utf8'));
} catch (e) {
  fail(`cannot read ${args.file}: ${e.message}`);
}

let result;
try {
  result = upsertName(current, { name: args.name, pubkey });
} catch (e) {
  fail(e.code === 'name_taken' ? `name ${args.name} already belongs to another key` : e.message);
}

const next = serializeDoc(result.doc);
const tmp = `${args.file}.tmp-${process.pid}`;
writeFileSync(tmp, next, { mode: 0o644 });
renameSync(tmp, args.file);
console.log(
  `${result.created ? 'added' : 'updated'}: ${args.name}@grunq.com -> ${pubkey}\n` +
    `wrote ${args.file} (names: ${Object.keys(normalizeDoc(result.doc).names).length})`,
);
