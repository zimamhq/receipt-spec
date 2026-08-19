# Zimam Signed Receipt — Attestation Format (v1.0.0-draft.2)

**License:** Apache-2.0 (this format is intended to become an interoperability
standard for agent execution evidence; anyone may implement it, in anything,
for any purpose).
**Status:** **draft** — wire identifier `zimam.receipt`, version
`1.0.0-draft.2`. Field semantics below are stable in intent; the format
freezes to `1.0.0` per §11. Reference implementations: the TypeScript
library, Rust signer, and control plane live in the main Zimam repository
(opening with the product launch); this repository carries two standalone
stdlib-only verifiers — [`vectors/verify_vectors.py`](./vectors/verify_vectors.py)
and [`vectors/verify_vectors.mjs`](./vectors/verify_vectors.mjs) — that
re-derive every committed byte independently.

This document specifies the **signed receipt**: one cryptographically signed
statement per *terminal* governance decision. It complements
[`SPEC.md`](./SPEC.md) (the hash-chained event log of a whole run): the event
chain is the *diary*, the signed receipt is the *sworn statement*.

## 1. Purpose

Every terminal outcome of a governed action — allowed and executed, denied,
failed, or resolved by a human — leaves exactly one signed payload in a
gap-free per-agent stream. A verifier holding only the public key material
can prove, offline: what was decided, which control layers said what, who
approved, what the action and its result were (by digest), and that nothing
in the stream was altered, dropped, reordered, or inserted since signing.

## 2. The payload

A `SignedReceiptPayload` is a JSON object:

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `spec` | string | REQUIRED | Always `"zimam.receipt"`. |
| `spec_version` | string | REQUIRED | SemVer of this document, e.g. `"1.0.0-draft.2"`. |
| `seq` | integer | REQUIRED | Position in the per-(tenant × agent) stream, starting at 0, gap-free (§6). |
| `issued_at` | integer | REQUIRED | Epoch **milliseconds**. An integer — floats never appear in a signed field (§5). |
| `tenant_id` | string | REQUIRED | The tenant the stream belongs to. |
| `agent_id` | string | REQUIRED | The governed agent. |
| `run_id` | string | REQUIRED | Correlates with the run's event-chain receipt (`SPEC.md`). |
| `action.tool` | string | REQUIRED | Tool name as invoked. |
| `action.action_class` | string | REQUIRED | The governance class the call was classified into. |
| `action.input_identity` | digest | REQUIRED | Digest (§5) of the canonical form of the *requested* action. |
| `action.enforced_identity` | digest | REQUIRED | Digest of the *enforced* action — differs from `input_identity` exactly when a transform rewrote arguments. |
| `verdict` | string | REQUIRED | One of the five verdicts (§3). |
| `reason_code` | string | REQUIRED | Machine-readable reason for the verdict. |
| `controls_evaluated` | object | REQUIRED | The six-layer controls record (§4). |
| `previous_receipt_hash` | digest | REQUIRED | Chain link (§6). |
| `approval` | object | OPTIONAL | Present **only** when a human decided: `{ initiator_id, approver_id, approver_attestation?, decided_at }` (`decided_at` integer epoch ms). Omitted otherwise — never `null`. See §7.1 — `approver_id` is a **claim**, `approver_attestation` is what was **verified**. |
| `result_digest` | digest | OPTIONAL | Present **only** when an executed call produced a result; a deny or a failed execution has none. Absence is the honest record. |
| `signer` | object | OPTIONAL | Custody attestation injected by the signing boundary (§9): `{ peer_uid, peer_gid }` (integers). Absent when the custody provides attestation elsewhere (e.g. a KMS key policy). |

Unknown fields MUST NOT be added in v1. Optional fields are **omitted, never
null**: a verifier MUST treat absence as "not applicable", and MUST NOT infer
anything an absent field would have attested.

## 3. Verdicts

`verdict` is one of exactly five values, in decreasing severity:

`deny` > `escalate` > `transform` > `warn` > `allow`

- `allow` — permitted as requested.
- `warn` — permitted; a shadow-mode rule recorded what it *would* have done.
- `transform` — permitted with rewritten arguments; `enforced_identity`
  attests what actually ran, and the rewritten *values* are never recorded —
  only which rule, layer, and path rewrote.
- `escalate` — a human decision was required; when the payload also carries
  `approval`, the human resolved it and the action proceeded.
- `deny` — refused; nothing executed downstream.

## 4. The six-layer controls record

`controls_evaluated` has **exactly six keys**, always:
`identity`, `capability`, `policy`, `trust_gate`, `ceilings`, `post_eval`.

Each value is `{ status, matched_count?, detail? }` where `status` is one of
`pass`, `deny`, `escalate`, `transform`, `warn`, `not_evaluated`.

Rules a conformant producer MUST enforce (and a verifier MAY re-check):

- A layer that did not run is recorded as an explicit `not_evaluated`.
  **Omission over false attestation**: an absent or extra key makes the
  record invalid — a verifier must never infer that a missing layer ran.
- `matched_count` appears **only** on the `policy` layer, and is REQUIRED
  whenever policy's status is not `not_evaluated`. Zero matches is a
  legitimate, recordable answer; the invalid state is *evaluated without a
  count*, never the zero.
- `detail` carries small bounded facts. Receipts are references, not
  payloads: raw arguments, outputs, and rewritten values never appear.

## 5. Canonicalization, digests, and numbers

- **Canonical form: RFC 8785 (JCS).** Signatures and payload digests are
  computed over the payload's JCS bytes (UTF-8).
- **Digest wire form:** every digest-valued field matches
  `sha256:<64 lowercase hex>` — the regex `^sha256:[0-9a-f]{64}$`. Fields
  whose names end `_hash`, `_digest`, or `_identity` are digest-valued.
- **Integers only.** No IEEE-754 fractional value may appear anywhere in a
  signed payload. Timestamps are integer epoch milliseconds. (RFC 8785
  serialises numbers via ECMAScript rules; excluding fractions removes the
  entire cross-language float-formatting risk class.)

## 6. Streams and chaining

Receipts form one stream per **(tenant × agent)**:

- `seq` starts at 0 and increments by exactly 1 — gap-free.
- `previous_receipt_hash` is the digest (§5) of the **previous payload's JCS
  bytes** — the payload only, never the signature envelope, so re-encoding
  or re-verifying a signature can never break the chain.
- The first receipt of a stream links to the all-zero genesis value:
  `sha256:000…0` (64 zeros).

Chain verification over an ordered slice: for each receipt after the first,
`seq` must be the predecessor's plus one and `previous_receipt_hash` must
equal the predecessor's payload digest; a slice beginning at `seq` 0 must
link to genesis. Streams MAY mix signature algorithms (§7) — chain links are
digests over payloads and know nothing of the envelope.

## 7. The signature envelope

A signed receipt travels as `{ payload, signature }` where `signature` is:

| Field | Meaning |
|---|---|
| `alg` | `"EdDSA"` or `"ES256"`. |
| `kid` | `sha256:` digest (§5) of the signing key's **SPKI DER** encoding. |
| `signature` | base64url (unpadded) signature over the payload's JCS bytes. |

- **EdDSA** — Ed25519 over the raw JCS bytes; the 64-byte raw signature.
  Deterministic (RFC 8032): identical payload + key ⇒ identical bytes.
- **ES256** — ECDSA P-256 over SHA-256 of the JCS bytes; the signature is
  the JOSE raw form `r || s` (32 bytes each). Randomized: signatures do not
  reproduce byte-for-byte, so ES256 conformance is *functional* (§10).

**The algorithm is a property of the key material, never a claim.** An
Ed25519 key signs `EdDSA`; a P-256 key signs `ES256`; nothing else is valid
in v1. A verifier MUST derive the expected algorithm from the key it holds
and reject a mismatching `alg` before attempting verification.

## 8. Key identity and registries

- `kid` is **computed** from the public key's SPKI DER — a registry MUST
  recompute it and MUST NOT store a caller-claimed identifier.
- A registry stores `(kid, alg, public_key_pem)` per tenant, with `alg`
  derived from the material exactly as §7.
- **Revocation is containment, not erasure:** a revoked key stops *new*
  acceptance; stored history remains verifiable against the revoked key's
  material forever.

## 9. Custody and the five signing guards

Signing happens at a custody boundary the producer does not control from the
inside (a separated signer process, or a cloud KMS whose key never leaves
the HSM). Two custody attestations exist in v1:

- **Socket custody:** the signer daemon injects `signer: { peer_uid,
  peer_gid }` — the kernel's answer to *who connected* — into the payload
  **before** canonicalization, so the attested identity is covered by the
  signature and never asserted by the caller.
- **KMS custody:** no `signer` field; who may invoke the key is attested by
  the key's IAM policy, outside the payload.

### 9.1 The two halves of an approval

`approver_id` is a **display name the reviewer supplied**. Nothing in this
format verifies it, and a verifier MUST NOT read it as an identity: it exists
so a human reading the record sees a human's name.

`approver_attestation` is what the issuing system actually **verified** about
the approver, as `{ method, principal }`:

| field | meaning |
| --- | --- |
| `method` | how the approver was authenticated. `"plane_api_key"` is defined in this version; further methods (per-user sessions, OIDC subjects, client certificates) extend the enumeration without changing the shape. |
| `principal` | the identifier the authentication established — an opaque string, meaningful within the issuing system. |

The field is **omitted whenever nothing was verified**, and a verifier MUST
NOT read an absent attestation as a passed one. An implementation that cannot
attest its approvers is conformant; one that *invents* an attestation is not.

The field is deliberately **not** named `*_identity`: §5 reserves that suffix
for content digests, and guard 3 enforces it.

**The five guards** run at the custody boundary and MUST refuse to sign —
reject before signing, never annotate after:

1. `self_approval_guard` — `approval.initiator_id` equals
   `approval.approver_id`; **or**, when both are present, the approver's
   attested `principal` equals the agent's attested `credential` in
   `controls_evaluated.identity.detail`. The first comparison is over names
   anyone can type and is walked past by typing a different one; the second
   is over what was verified on each half, and is not.
2. `false_control_attestation_guard` — `controls_evaluated` violates §4.
3. `digest_not_sha256_wire_form` — any `_hash`/`_digest`/`_identity` field
   fails the §5 wire form.
4. `float_in_signed_field` — any non-integer number anywhere in the payload.
5. `sequence_gap_guard` — `seq` is not exactly last-known + 1 (or 0 for a
   new stream).

A guard refusal reports **all** violations, not just the first.

## 10. Verification algorithm and conformance

A conformant verifier, given `{ payload, signature }` and key material:

1. Recompute `kid` from the key's SPKI DER; reject on mismatch with
   `signature.kid`.
2. Derive the algorithm from the key material (§7); reject on mismatch with
   `signature.alg`.
3. Serialise `payload` with RFC 8785; verify the signature over those bytes
   (EdDSA: raw; ES256: SHA-256 then ECDSA, `r || s` form).
4. Validate §4 (controls) and §5 (wire forms, integers); a verifier SHOULD
   also re-run guards 1–4.
5. For a stream slice: verify §6 ordering and links.
6. Where `result_digest` is present and the result is available, recompute
   and compare.

**Conformance vectors** live at
[`vectors/vectors.json`](./vectors/vectors.json)
(wire id `zimam.receipt.vectors`, version 1): 6 canonicalization cases,
4 complete receipts with byte-exact Ed25519 signatures under a published
test key, and 5 guard-refusal cases. A conforming implementation reproduces
every canonical byte, digest, and EdDSA signature exactly, and refuses every
guard case. ES256 is deliberately absent from the byte-identity corpus
(randomized signatures); ES256 conformance is: signatures your
implementation produces verify under §10, and the vectors' payloads
re-canonicalise to the same bytes.

## 11. Versioning

`spec_version` is SemVer. `1.0.0-draft.N` may still change field semantics;
**freeze to `1.0.0`** happens when: the vector corpus is published at a
stable URL, at least two independent implementations reproduce it, and the
guard set survives external review. After freeze: MINOR adds optional
fields or registered values only (a 1.0 verifier remains correct on 1.x
payloads it accepts); MAJOR is reserved for changes that alter
canonicalization, chaining, or guard semantics.

## 12. Changelog

### 1.0.0-draft.2

- **Added** `approval.approver_attestation` (§9.1) — what the issuing system
  verified about the approver, beside the `approver_id` display name it
  never verified. Optional, and **omitted when nothing was verified**.
- **Strengthened** `self_approval_guard` (§9, guard 1): where both
  attestations are present, the approver's `principal` must not equal the
  agent's attested `credential`. The name comparison alone is walked past by
  typing a different name.
- Vector corpus regenerated — the version string is inside every canonical
  payload, so all vector signatures change with it.

Receipts issued under `1.0.0-draft.1` remain valid and verify unchanged;
the published chains in [`receipts/`](./receipts/) contain both versions.
One receipt carries `approver_attestation` while still declaring draft.1 —
issued in the hour between the field landing and this bump, and kept as
issued rather than reissued. The record is what happened.
