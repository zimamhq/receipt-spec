#!/usr/bin/env node
// Verify Zimam's published signed receipts — Node standard library only.
// Two chains, two custodies:
//   self-hosted (this directory): signed by a separated signer daemon on a
//     developer machine, the kernel's answer to "who connected" inside the
//     signed bytes; anchored to the repo commit that built that signer.
//   cloud (cloud/): the same stream continuing across custodies — receipt
//     #0 by the same daemon, receipt #1 by an AWS KMS P-256 key that has
//     never existed outside its HSM; anchored to the commit that added the
//     KMS adapter.
//
// Run:  node receipts/verify.mjs        (exit 0 = everything verifies)
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GENESIS, guardViolations, jcs, keyIdOf, payloadDigest, sha256Wire, verifyChain, verifySignature } from '../lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const read = (name) => JSON.parse(readFileSync(join(here, name), 'utf8'));
const pem = (name) => readFileSync(join(here, name), 'utf8');

let failures = 0;
const check = (name, ok) => {
  console.log(`  ${ok ? '✓' : '✗ FAIL'} ${name}`);
  if (!ok) failures += 1;
};

// A miniature registry: keys resolved BY KID, the way an evidence store
// resolves them — never by trusting a file layout.
const registry = new Map(
  ['signer.pub', 'kms-signer.pub'].map((f) => [keyIdOf(pem(f)), pem(f)]),
);
const verify = (r) => {
  const key = registry.get(r.signature.kid);
  return key !== undefined && verifySignature(r.payload, r.signature, key);
};
// The published tool results behind each anchor (see the README): reading
// .git/refs/heads/main returns the HEAD commit — recompute the digests.
const anchorDigest = (head) =>
  sha256Wire(jcs({
    content: [{ type: 'text', text: `${head}\n` }],
    structuredContent: { content: `${head}\n` },
  }));

console.log('the self-hosted chain');
const s0 = read('00000000.json');
const s1 = read('00000001.json');
check('receipt #0 signature (Ed25519, kernel-attested signer)', verify(s0));
check('receipt #1 signature', verify(s1));
check('#0 guards', guardViolations(s0.payload, null).length === 0);
check('#1 guards', guardViolations(s1.payload, 0).length === 0);
check('genesis is the all-zero value', s0.payload.previous_receipt_hash === GENESIS);
check('#1 links to #0 by payload digest', s1.payload.previous_receipt_hash === payloadDigest(s0.payload));
check('chain verifies gap-free', verifyChain([s0.payload, s1.payload]).valid);
check('#1 commit-anchors HEAD 53fc09a', anchorDigest('53fc09abe216d43498b32cdd31740fcbe13df8b3') === s1.payload.result_digest);
check('kernel attestation present (peer_uid/peer_gid)', Number.isInteger(s0.payload.signer?.peer_uid));

console.log('the cloud chain — one stream, two custodies');
const c0 = read('cloud/00000000.json');
const c1 = read('cloud/00000001.json');
check('cloud #0 signature (Rust signer, EdDSA)', verify(c0));
check('cloud #1 signature (AWS KMS, ES256)', verify(c1));
check('cloud #1 really is ES256', c1.signature.alg === 'ES256');
check('the two receipts carry DIFFERENT key ids', c0.signature.kid !== c1.signature.kid);
check('cloud guards pass across both custodies', guardViolations(c0.payload, null).length === 0 && guardViolations(c1.payload, 0).length === 0);
check('cloud genesis is the all-zero value', c0.payload.previous_receipt_hash === GENESIS);
check('cloud #1 links to cloud #0 by payload digest', c1.payload.previous_receipt_hash === payloadDigest(c0.payload));
check('the mixed-algorithm chain verifies gap-free', verifyChain([c0.payload, c1.payload]).valid);
check('cloud #1 commit-anchors HEAD 75841dc (the KMS adapter commit)', anchorDigest('75841dc7fe2db707df12806ab9e747775fcafccd') === c1.payload.result_digest);
check('every approval names distinct initiator and approver', [s0, s1, c0, c1].every((r) => !r.payload.approval || r.payload.approval.initiator_id !== r.payload.approval.approver_id));

console.log(
  failures === 0
    ? '\nAll checks passed. Two chains, two custodies — a kernel-attested local signer and a Frankfurt HSM — every signature verifiable from this directory alone.'
    : `\n${failures} check(s) FAILED.`,
);
process.exit(failures === 0 ? 0 : 1);
