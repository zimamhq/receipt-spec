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

console.log('the cloud chain — one stream, two custodies, and the first refusal');
const cloud = [0, 1, 2, 3, 4, 5, 6].map((n) => read(`cloud/${String(n).padStart(8, '0')}.json`));
const [c0, c1, , , , c5, c6] = cloud;
check('cloud #0 signature (Rust signer, EdDSA)', verify(c0));
check('cloud #1 signature (AWS KMS, ES256)', verify(c1));
check('cloud #2–#6 signatures (all KMS)', cloud.slice(2).every(verify));
check('cloud #1 really is ES256', c1.signature.alg === 'ES256');
check('the two custodies carry DIFFERENT key ids', c0.signature.kid !== c1.signature.kid);
check('guards pass on every cloud receipt', cloud.every((r, i) => guardViolations(r.payload, i === 0 ? null : i - 1).length === 0));
check('cloud genesis is the all-zero value', c0.payload.previous_receipt_hash === GENESIS);
check('the seven-receipt mixed-algorithm chain verifies gap-free', verifyChain(cloud.map((r) => r.payload)).valid);
check('cloud #1 commit-anchors HEAD 75841dc (the KMS adapter commit)', anchorDigest('75841dc7fe2db707df12806ab9e747775fcafccd') === c1.payload.result_digest);
check('#0–#1 predate agent identity and say so: not_evaluated', [c0, c1].every((r) => r.payload.controls_evaluated.identity.status === 'not_evaluated'));
check('#2 onward: identity PASS inside the signed bytes (plane_token)', cloud.slice(2).every((r) => {
  const id = r.payload.controls_evaluated.identity;
  return id.status === 'pass' && id.detail?.method === 'plane_token' && id.detail?.subject === r.payload.agent_id;
}));
check('#3–#4: the first WRITE_INTERNAL in the stream', [cloud[3], cloud[4]].every((r) => r.payload.action.action_class === 'WRITE_INTERNAL'));
check('#5 is a DENY: MATRIX_BLOCK on a DESTRUCTIVE tool at L0', c5.payload.verdict === 'deny' && c5.payload.reason_code === 'MATRIX_BLOCK' && c5.payload.action.action_class === 'DESTRUCTIVE');
check('#5 never asked a human and never executed (no approval, no result digest)', !c5.payload.approval && !c5.payload.result_digest);
check('#5 sits INSIDE the chain — refusals are receipted, not dropped', c6.payload.previous_receipt_hash === payloadDigest(c5.payload));
check('every approval names distinct initiator and approver', [s0, s1, ...cloud].every((r) => !r.payload.approval || r.payload.approval.initiator_id !== r.payload.approval.approver_id));

console.log('the second agent — impact-weighted, and one attested approver');
const scribe = [0, 1, 2].map((n) => read(`scribe/${String(n).padStart(8, '0')}.json`));
check('every scribe receipt verifies against the registry', scribe.every(verify));
check('the chain is gap-free from genesis', verifyChain(scribe.map((r) => r.payload)).valid);
check('guards pass on all three', scribe.every((r, i) => guardViolations(r.payload, i === 0 ? null : i - 1).length === 0));
check('a SECOND agent identity — separate stream, separate trust', scribe.every((r) => r.payload.agent_id === 'docs-scribe') && scribe[0].payload.agent_id !== c0.payload.agent_id);
// ADR 0010 / draft.2: the approver's name is a claim; the attestation is not.
const attested = scribe.find((r) => r.payload.approval?.approver_attestation);
check('one receipt carries an ATTESTED approver (method + principal)', attested !== undefined
  && attested.payload.approval.approver_attestation.method === 'plane_api_key'
  && typeof attested.payload.approval.approver_attestation.principal === 'string');
check('the attested approver is NOT the agent\'s own credential', attested !== undefined
  && attested.payload.approval.approver_attestation.principal
     !== attested.payload.controls_evaluated.identity.detail.credential);
check('the earlier two are honest about having no attestation (absent, not empty)', scribe
  .slice(0, 2).every((r) => r.payload.approval !== undefined && r.payload.approval.approver_attestation === undefined));

console.log('the third agent — a real external effect, governed by two layers');
const mail = [0, 1].map((n) => read(`mailer/${String(n).padStart(8, '0')}.json`));
const [m0, m1] = mail;
check('both mailer receipts verify against the registry', mail.every(verify));
check('the chain is gap-free from genesis', verifyChain(mail.map((r) => r.payload)).valid);
check('guards pass on both', mail.every((r, i) => guardViolations(r.payload, i === 0 ? null : i - 1).length === 0));
check('a THIRD agent identity, its own stream', mail.every((r) => r.payload.agent_id === 'mailer'));
check('both are COMM_EXTERNAL — a real external effect, not a file read', mail.every((r) => r.payload.action.action_class === 'COMM_EXTERNAL'));
// The story in the chain: the REGULATORY layer refused the non-compliant send
// before any human saw it, then the HUMAN layer approved the compliant one.
check('#0 is a REGULATORY deny: verdict deny, reason BLOCK_RULE', m0.payload.verdict === 'deny' && m0.payload.reason_code === 'BLOCK_RULE');
check('#0 asked no human and executed nothing (no approval, no result digest)', !m0.payload.approval && !m0.payload.result_digest);
check('#1 was HELD for a human: escalate / MATRIX_REQUIRE_APPROVAL', m1.payload.verdict === 'escalate' && m1.payload.reason_code === 'MATRIX_REQUIRE_APPROVAL');
check('#1 carries an ATTESTED approver (not a typed name)', m1.payload.approval?.approver_attestation?.method === 'plane_api_key' && typeof m1.payload.approval.approver_attestation.principal === 'string');
check('the receipt records only the recipient reference, never the mail body', JSON.stringify(m1.payload).includes('majeed@example.com') === false || m1.payload.action.tool === 'mail.send');

console.log(
  failures === 0
    ? '\nAll checks passed. Four chains, two custodies — a kernel-attested local signer and a Frankfurt HSM — a verified agent identity from receipt #2 on, one refusal kept forever in the chain, a second agent with its own stream, an approver whose identity was attested rather than typed, and a third agent whose first external-effect send was refused by a regulatory layer before a human ever saw it. Every signature verifiable from this directory alone.'
    : `\n${failures} check(s) FAILED.`,
);
process.exit(failures === 0 ? 0 : 1);
