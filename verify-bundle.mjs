#!/usr/bin/env node
// Verify a Zimam evidence bundle — the portable export an operator downloads
// from a console or a control plane. Node standard library only.
//
//   node verify-bundle.mjs <bundle.json>
//
// The bundle's metadata is DESCRIPTIVE; its authority is the signatures
// inside it. Accordingly, nothing stated is trusted: every key id and
// algorithm is recomputed from the key material, every signature is checked
// over recomputed canonical bytes, every chain link is re-derived, and the
// five signing guards are re-run. Exit 0 means everything held.
import { readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { GENESIS, guardViolations, keyIdOf, payloadDigest, verifyChain, verifySignature } from './lib.mjs';

const file = process.argv[2];
if (!file) {
  console.error('usage: node verify-bundle.mjs <bundle.json>');
  process.exit(2);
}
const bundle = JSON.parse(readFileSync(file, 'utf8'));

let failures = 0;
const check = (name, ok) => {
  console.log(`  ${ok ? '✓' : '✗ FAIL'} ${name}`);
  if (!ok) failures += 1;
};

console.log(`${bundle.bundle ?? '(unlabelled)'} v${bundle.bundle_version ?? '?'} — agent ${bundle.agent_id}, tenant ${bundle.tenant_id}`);
console.log(`exported ${bundle.exported_at}, ${bundle.receipts?.length ?? 0} receipt(s), ${bundle.keys?.length ?? 0} key(s)\n`);

console.log('the keys — nothing stated is trusted');
const registry = new Map();
for (const k of bundle.keys ?? []) {
  let derivedKid = null;
  let derivedAlg = null;
  try {
    const key = createPublicKey(k.public_key_pem);
    derivedKid = keyIdOf(k.public_key_pem);
    derivedAlg =
      key.asymmetricKeyType === 'ed25519'
        ? 'EdDSA'
        : key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
          ? 'ES256'
          : null;
  } catch {
    /* not key material */
  }
  check(`key ${String(k.kid).slice(0, 20)}…: stated kid matches its material`, derivedKid === k.kid);
  check(`key ${String(k.kid).slice(0, 20)}…: stated alg matches its material (${derivedAlg})`, derivedAlg === k.alg);
  if (derivedKid !== null) registry.set(derivedKid, k.public_key_pem);
  if (k.revoked_at) console.log(`    note: revoked ${k.revoked_at} — history stays verifiable; new receipts must not use it`);
}

console.log('the receipts');
const payloads = [];
let lastSeq = null;
for (const r of bundle.receipts ?? []) {
  payloads.push(r.payload);
  const label = `#${r.payload.seq} ${r.signature.alg} ${r.payload.verdict} ${r.payload.action?.tool ?? ''}`;
  const pem = registry.get(r.signature.kid);
  check(`${label}: signature verifies against a bundled key`, pem !== undefined && verifySignature(r.payload, r.signature, pem));
  check(`${label}: the five guards pass`, guardViolations(r.payload, lastSeq).length === 0);
  lastSeq = r.payload.seq;
}

console.log('the chain');
const chain = verifyChain(payloads);
check('gap-free, linked payload-digest to payload-digest', chain.valid === true);
if (payloads[0]?.seq === 0) check('anchored at the all-zero genesis', payloads[0].previous_receipt_hash === GENESIS);
check('receipt_count matches what arrived', bundle.receipt_count === payloads.length);

const approvals = payloads.filter((p) => p.approval);
if (approvals.length > 0) {
  console.log('human oversight');
  check(
    `every approval names distinct initiator and approver (${approvals.length} approval(s))`,
    approvals.every((p) => p.approval.initiator_id !== p.approval.approver_id),
  );
}

console.log(
  failures === 0
    ? `\nAll checks passed. ${payloads.length} receipt(s), ${registry.size} key(s), one verifiable stream — and nothing in it taken on trust.`
    : `\n${failures} check(s) FAILED.`,
);
process.exit(failures === 0 ? 0 : 1);
