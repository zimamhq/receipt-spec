# Zimam Receipt Format — Specification (v1.1)

**License:** Apache-2.0 (deliberately permissive — this format is intended to
become an interoperability standard for agent execution evidence; anyone may
implement it, in anything, for any purpose).
**Status:** **frozen wire format; current version v1.1.** The wire format below
is stable: a receipt that verifies against this document will verify against
every future v1.x reader. v1.1 is a MINOR, additive change per §7 — it registers
the `PACK_EVALUATED` event type (policy-pack evaluation record) and nothing
else; v1.0 readers still verify v1.1 receipts. The reference implementation is
[`@zimam/receipts`](../../packages/receipts) (`RECEIPT_SPEC_VERSION = "1.1"`).

## 1. Purpose

A **receipt** is a tamper-evident record of one governed execution: what was
requested, what the policy decided, who approved, what ran, and what oversight
followed. A verifier that accepts a receipt guarantees it is bit-for-bit the
receipt that was written — edit, drop, reorder, or backdate one event and
verification fails at that exact link.

## 2. Structure

A receipt is a JSON object:

```json
{
  "spec_version": "1.1",
  "id": "<caller-supplied run identifier>",
  "events": [ <ReceiptEvent>, ... ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `spec_version` | string | `MAJOR.MINOR` of this format (§7). Receipt-level metadata — see §3, it is **not** part of the hash chain. OPTIONAL on the wire; a writer SHOULD emit it, a reader treats its absence as compatible. |
| `id` | string | Caller-supplied run identifier. Also receipt-level metadata, not chained. |
| `events` | array | The hash-chained event log below. |

Each `ReceiptEvent`:

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer | 0-based position in the chain |
| `at` | integer | Epoch milliseconds; MUST be ≥ the previous event's `at` |
| `type` | string | One of the registered event types (§4) |
| `payload` | JSON value | Event data; hashed as written |
| `prevHash` | string | Hash of the previous event; `"0" × 64` for `seq` 0 (genesis) |
| `hash` | string | SHA-256 (hex) over the canonical form of this event (§3) |

## 3. Canonicalization and hashing

`hash = sha256_hex( canonical_json( { seq, at, type, payload, prevHash } ) )`

The hash covers **only** those five per-event fields. Receipt-level metadata
(`spec_version`, `id`) is deliberately outside the chain: it selects *which
rules a verifier applies*, it is not evidence about the run. This is what makes
it safe — editing `spec_version` can never make a tampered chain verify (the
links are computed without it), and a verifier that doesn't recognise the
version refuses outright (§5, §7) rather than trusting it.

Canonical JSON rules:
- Object keys sorted lexicographically, recursively, at every depth.
- Arrays keep their order.
- Scalars serialize as standard JSON (`JSON.stringify` semantics); strings are
  UTF-8 encoded before hashing.
- No insignificant whitespace.

## 4. Registered event types

`RUN_REQUESTED` · `PACK_EVALUATED` *(v1.1)* · `POLICY_DECIDED` · `APPROVAL_REQUESTED` · `APPROVAL_GRANTED`
· `APPROVAL_REJECTED` · `APPROVAL_WITHDRAWN` · `EXECUTED` · `FAILED` ·
`QA_SAMPLED` · `EVAL_PASS` · `EVAL_FAIL` · `INCIDENT_RAISED` · `TRUST_TRANSITION`

Implementations MAY carry additional payload fields; verifiers MUST NOT reject
unknown payload content (it is hashed as written either way). New event types
are added under MINOR versions (§7) — a reader that meets an unrecognised
`type` still verifies the chain, since the type is just a hashed string.

## 5. Verification algorithm

**Version gate (first).** If `spec_version` is present and its MAJOR is either
unparseable or greater than the MAJOR the verifier implements → reject with
`UNSUPPORTED_SPEC_VERSION`. If it is absent, proceed (treat as compatible). This
happens before the walk: a chain declaring rules the verifier doesn't implement
must be refused, not verified under the wrong rules.

Then walk `events` in order, tracking `prevHash` (start: genesis) and `prevAt`
(start: −∞). For event `i`, reject with the given reason if:

1. `seq ≠ i` → `SEQ_MISMATCH`
2. `event.prevHash ≠ prevHash` → `PREV_HASH_MISMATCH`
3. `event.at < prevAt` → `TIME_REGRESSION`
4. recomputed hash ≠ `event.hash` → `HASH_MISMATCH`

Otherwise advance and continue. An empty receipt is valid.

The reference verifier reports the first broken link's index and reason; a
version rejection is receipt-level and reports index `-1`.

## 6. Conformance

An implementation conforms if: identical event histories produce identical
chains on any machine; every mutation of a stored receipt is detected by §5;
time never runs backwards within a chain; and it applies the §5 version gate.

## 7. Versioning

`spec_version` is `MAJOR.MINOR`. This document is **MAJOR 1, MINOR 1**.

- **MINOR** bumps are backward-compatible additions: new event types, new
  OPTIONAL fields, new payload conventions. A v1.0 reader MUST still verify a
  v1.9 receipt — everything it needs (§3 canonicalization, §5 walk) is
  unchanged, and it ignores what it doesn't recognise (§4).
- **MAJOR** bumps change canonicalization (§3) or the verification walk (§5) in
  a way that would make an older reader compute the wrong result. A reader MUST
  refuse a receipt whose MAJOR exceeds the one it implements (§5 version gate),
  rather than silently mis-verify it.
- **Absent** `spec_version` is read as compatible, for pre-versioning and
  minimal third-party writers. Writers SHOULD emit it.

Because the field is outside the hash chain (§3), it is a compatibility signal,
never an integrity claim: it cannot be used to smuggle a tampered chain past a
verifier.

## 8. Payload conventions (informative)

Nothing in this section changes the wire format or verification — payloads are
opaque JSON, hashed as written (§3, §4). It records the convention the
reference implementation follows, and that implementers handling personal data
are strongly encouraged to follow:

**A receipt proves what a governance decision was, not what the data said.**
Payloads carry references, not content: the action name, a `targetRef` (an
opaque identifier in the producer's own system), the action class, the policy
version, the trust level at decision time, the outcome, the reviewer, and
timing. Tool arguments and results stay in the producer's systems, referenced
by `targetRef` — they do not enter the chain. Note that a bare hash of content
is not an anonymous reference: hashing a low-entropy value (an email address)
is reversible by dictionary attack, and a hash of personal data remains
personal data under GDPR. Where a content fingerprint is genuinely needed, use
a keyed HMAC and treat the field as pseudonymous.
