#!/usr/bin/env node
// Cross-language byte-identity verifier for the Zimam receipt vectors —
// JavaScript, Node standard library only. Companion to verify_vectors.py
// (Python stdlib) and the Rust signer's test suite, which re-derive the
// same corpus independently.
//
// Beyond the Python verifier, this one also VERIFIES the vectors' Ed25519
// signatures against the published test public key (node:crypto can;
// Python's stdlib cannot).
//
// Run:  node vectors/verify_vectors.mjs        (exit 0 = every byte identical)
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GENESIS, guardViolations, jcs, keyIdOf, payloadDigest, sha256Wire, verifyChain, verifySignature } from '../lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8'));

let failures = 0;
const check = (name, ok, detail = '') => {
  if (!ok) {
    failures += 1;
    console.log(`  ✗ FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  } else {
    console.log(`  ✓ ${name}`);
  }
};

console.log(`${vectors.spec} v${vectors.version}`);

console.log('canonicalization');
for (const c of vectors.canonicalization) {
  const got = jcs(c.input);
  check(`${c.name}: canonical bytes`, got === c.jcs, got !== c.jcs ? `got ${got.slice(0, 80)}` : '');
  check(`${c.name}: digest`, sha256Wire(got) === c.sha256);
}

console.log('receipts');
check('test key id matches its material', keyIdOf(vectors.test_key.public_pem) === vectors.test_key.kid);
const payloads = [];
for (const r of vectors.receipts) {
  payloads.push(r.payload);
  const got = jcs(r.payload);
  check(`${r.name}: canonical bytes`, got === r.jcs);
  check(`${r.name}: payload digest`, payloadDigest(r.payload) === r.sha256);
  check(`${r.name}: Ed25519 signature verifies`, verifySignature(r.payload, r.signature, vectors.test_key.public_pem));
  check(`${r.name}: guards pass`, guardViolations(r.payload, r.payload.seq === 0 ? null : r.payload.seq - 1).length === 0);
}
const chain = verifyChain(payloads);
check('the receipt chain links gap-free from genesis', chain.valid === true);
check('genesis constant is the all-zero digest', payloads[0].previous_receipt_hash === GENESIS);

console.log('guards');
for (const g of vectors.guards) {
  const got = guardViolations(g.payload, g.last_seq).sort();
  const want = [...g.expected_violations].sort();
  check(
    `${g.name}: refused for exactly [${want.join(', ')}]`,
    got.length === want.length && got.every((v, i) => v === want[i]),
    `got [${got.join(', ')}]`,
  );
}

console.log(failures === 0 ? '\nAll checks passed — byte-identical with the committed corpus.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
