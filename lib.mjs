// Standalone verification primitives for the Zimam receipt formats.
// Node standard library ONLY — no packages, no build step, nothing to trust
// but this file, which the conformance vectors pin byte-for-byte.
//
// The JCS here is a deliberate SUBSET of RFC 8785: Zimam signed payloads
// carry integers only (the float_in_signed_field guard enforces it), so
// ECMAScript number serialisation reduces to plain integer printing. The
// remaining sharp edge is object key ordering — UTF-16 code units — which
// is exactly what JavaScript's native string comparison does.
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

export function jcs(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error(`float in signed field: ${value} — the format forbids it`);
    }
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort(); // native sort = UTF-16 code units, per RFC 8785
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(',')}}`;
  }
  throw new Error(`not JSON: ${typeof value}`);
}

export function sha256Wire(text) {
  return `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;
}

export const GENESIS = `sha256:${'0'.repeat(64)}`;

export function payloadDigest(payload) {
  return sha256Wire(jcs(payload));
}

/** kid = sha256: of the public key's SPKI DER — recomputed, never trusted. */
export function keyIdOf(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return `sha256:${createHash('sha256').update(der).digest('hex')}`;
}

/**
 * Verify a { payload, signature } record against public key material.
 * The algorithm is derived from the KEY, never from the claim: an Ed25519
 * key verifies EdDSA over the raw JCS bytes; a P-256 key verifies ES256
 * (SHA-256 + ECDSA, JOSE r||s form). Anything inconsistent is false.
 */
export function verifySignature(payload, signature, publicKeyPem) {
  try {
    const key = createPublicKey(publicKeyPem);
    const keyAlg =
      key.asymmetricKeyType === 'ed25519'
        ? 'EdDSA'
        : key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
          ? 'ES256'
          : null;
    if (keyAlg === null || keyAlg !== signature.alg) return false;
    if (keyIdOf(publicKeyPem) !== signature.kid) return false;
    const bytes = Buffer.from(jcs(payload), 'utf8');
    const sig = Buffer.from(signature.signature, 'base64url');
    return signature.alg === 'EdDSA'
      ? cryptoVerify(null, bytes, key, sig)
      : cryptoVerify('sha256', bytes, { key, dsaEncoding: 'ieee-p1363' }, sig);
  } catch {
    return false;
  }
}

const DIGEST_KEY = /(_hash|_digest|_identity)$/;
const SHA256_WIRE = /^sha256:[0-9a-f]{64}$/;
const CONTROL_LAYERS = ['identity', 'capability', 'policy', 'trust_gate', 'ceilings', 'post_eval'];
const CONTROL_STATUSES = ['pass', 'deny', 'escalate', 'transform', 'warn', 'not_evaluated'];

/** The five signing-time guards (SIGNED.md §9), re-checkable by any verifier. */
export function guardViolations(payload, lastSeq) {
  const violations = [];
  if (payload.approval && payload.approval.initiator_id === payload.approval.approver_id) {
    violations.push('self_approval_guard');
  }
  const controls = payload.controls_evaluated;
  const controlsOk =
    controls !== null &&
    typeof controls === 'object' &&
    Object.keys(controls).every((k) => CONTROL_LAYERS.includes(k)) &&
    CONTROL_LAYERS.every((layer) => {
      const entry = controls[layer];
      if (typeof entry !== 'object' || entry === null) return false;
      if (!CONTROL_STATUSES.includes(entry.status)) return false;
      if (layer === 'policy') {
        if (entry.status !== 'not_evaluated') {
          return Number.isInteger(entry.matched_count) && entry.matched_count >= 0;
        }
        return entry.matched_count === undefined;
      }
      return entry.matched_count === undefined;
    });
  if (!controlsOk) violations.push('false_control_attestation_guard');

  const walk = (value, key) => {
    if (key !== null && DIGEST_KEY.test(key)) {
      if (typeof value !== 'string' || !SHA256_WIRE.test(value)) {
        violations.push('digest_not_sha256_wire_form');
      }
    }
    if (typeof value === 'number' && !Number.isInteger(value)) {
      violations.push('float_in_signed_field');
    }
    if (Array.isArray(value)) value.forEach((v) => walk(v, null));
    else if (typeof value === 'object' && value !== null) {
      for (const [k, v] of Object.entries(value)) walk(v, k);
    }
  };
  walk(payload, null);

  const expected = lastSeq === null ? 0 : lastSeq + 1;
  if (payload.seq !== expected) violations.push('sequence_gap_guard');
  return [...new Set(violations)];
}

/** Verify seq continuity and payload-digest links over one ordered stream slice. */
export function verifyChain(payloads) {
  for (let i = 0; i < payloads.length; i++) {
    const p = payloads[i];
    if (i === 0) {
      if (p.seq === 0 && p.previous_receipt_hash !== GENESIS) {
        return { valid: false, at: 0, reason: 'GENESIS_HASH_MISMATCH' };
      }
      continue;
    }
    if (p.seq !== payloads[i - 1].seq + 1) return { valid: false, at: i, reason: 'SEQUENCE_GAP' };
    if (p.previous_receipt_hash !== payloadDigest(payloads[i - 1])) {
      return { valid: false, at: i, reason: 'PREV_PAYLOAD_HASH_MISMATCH' };
    }
  }
  return { valid: true };
}
