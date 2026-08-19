# The published signed receipts — three chains, two custodies

On 12 August 2026, the coding agent building Zimam asked to read Zimam's own
`README.md`. It was not allowed to.

The agent (`claude-code`) sits at **L0_PROBATION** in the trust engine — new
agents earn autonomy the way new employees earn trust, and probation means a
human signs off on everything. So the call hung, held open by the gateway,
for **203 seconds**, until a human reviewer granted it. The decision then
left the governor as receipt `00000000.json` in this directory:

- verdict `escalate`, reason `MATRIX_REQUIRE_APPROVAL`;
- the approval pair — `initiator: claude-code`, `approver: majeed` — a pair
  the format's self-approval guard would have refused to sign had they been
  the same principal;
- all six control layers, recorded honestly: what did not run says
  `not_evaluated`, because a verifier must never infer that an absent
  control ran and passed;
- a digest of the result the tool returned;
- and `signer: { peer_uid, peer_gid }` — the operating-system kernel's own
  answer to *who connected to the signing socket*, injected by the separated
  signer **before** canonicalisation, so the caller's attested identity sits
  inside the signed bytes. The gateway that proxied the call never touched
  the signing key.

Receipt `00000001.json` came 420 held seconds later, the same night: a
governed read of `.git/refs/heads/main` — the file that names the
repository's HEAD commit. Its result digest therefore **cryptographically
commits this signed chain to the exact repository state that built the
signer that signed it**. Self-reference, closed with mathematics.

## The cloud chain (`cloud/`) — seven receipts, two custodies, one refusal

The same agent then ran governed against the **live cloud evidence store**
(the control plane on Railway, verified-ingest — the plane re-checks every
signature, guard, and chain link before a row exists). The stream now reads
like a diary of the product growing up:

- [`#0`](cloud/00000000.json) — 12 August, signed by the same separated
  **Rust signer** (EdDSA, kernel-attested caller), a governed read of this
  very directory's README, held until a human granted it.
- [`#1`](cloud/00000001.json) — 14 August, signed by an **AWS KMS key in
  Frankfurt that has never existed outside its HSM** (ES256 over the same
  RFC 8785 bytes). Approved from the Zimam console UI. Its result digest
  commit-anchors `.git/refs/heads/main` — the commit that added the KMS
  adapter itself.
- [`#2`](cloud/00000002.json) — 17 August, the first receipt whose
  `identity` layer reads **`pass`**: the agent booted with a plane-issued
  credential, the gateway verified it *before serving a single call*, and
  the verified `{method, subject, credential}` sits inside the signed
  bytes. The governed action, fittingly: reading ADR 0009 — the identity
  design itself.
- [`#3`–`#4`](cloud/00000003.json) — 17 August, the **first WRITE_INTERNAL
  in the stream's history**: the agent prepares a directory and writes a
  working note, each held for a human (39 s and 9 s).
- [`#5`](cloud/00000005.json) — 17 August, the **first refusal**. The
  agent's plan said "rename the note" — `move_file`, classified
  DESTRUCTIVE. The default policy matrix does not escalate DESTRUCTIVE at
  L0 probation; it refuses outright: verdict `deny`, reason `MATRIX_BLOCK`,
  decided in about a second. No human was asked. Nothing executed — the
  receipt carries **no approval and no result digest**, and the verifier
  checks both. Blocks are not punishments: the trust score was untouched.
- [`#6`](cloud/00000006.json) — 17 August, the agent **corrects its own
  note through governance**: the note had claimed the rename happened; the
  truthful rewrite was granted and executed. The plan said move; the policy
  said no; the record says both, forever — `#6` chains onto the refusal's
  own payload digest.

Same stream, same chain rules, different keys and different algorithms —
resolved by key id exactly the way the store's registry does. A demotion of
one custody never orphans the history of the other. And a refusal is a
first-class link: evidence stores that only remember successes are
scrapbooks, not records.

## The second agent (`scribe/`) — weighted work, and an attested approver

A workforce is more than one agent, so the store holds more than one chain.
`docs-scribe` is a second governed agent with its own credential, its own
trust ledger, and a deliberately narrower brief — its tool registry contains
no destructive tools at all.

- [`scribe/#0`](scribe/00000000.json), [`#1`](scribe/00000001.json) — 19
  August, a directory listing and a file read, each held for a human. Their
  governed calls carry **impact hints** (0.1 and 0.3): the two grants bought
  **0.4 weighted successes** toward a 20-success promotion gate, where
  counting calls would have bought 2. A success on a trivial action must not
  buy the trust a consequential one does, or an agent farms its way to
  autonomy through busywork.
- [`scribe/#2`](scribe/00000002.json) — the first receipt in this store
  whose **approver identity was attested rather than typed**. Every earlier
  approval records `approver_id`, a display name nothing verified; this one
  also carries `approver_attestation: { method: "plane_api_key", principal }`
  — the authenticated key that submitted the decision, recorded by the plane
  and not accepted from the request body. The verifier checks that this
  principal is **not** the agent's own credential: names can be typed, two
  verified principals cannot collide by accident.

The two earlier scribe receipts have no attestation at all, and say so by
**omission** — the field is absent, not empty. A verifier must never read an
absence as a passed check. (`#2` still declares `spec_version`
`1.0.0-draft.1` while carrying a draft.2 field: it was issued in the hour
between the field landing and the version bump, and is published as issued
rather than reissued. The record is what happened.)

## Verify everything yourself

From the repository root, with Node ≥ 22.18:

```bash
node receipts/verify.mjs
```

Thirty-three checks across all three chains: every signature against the published
public keys ([`signer.pub`](signer.pub), [`kms-signer.pub`](kms-signer.pub)),
the five signing-time guards on every payload, both gap-free chains from the
all-zero genesis — one of them seven receipts long and mixed-algorithm —
both commit anchors recomputed from first principles, the identity layer's
honesty in both directions (`not_evaluated` before ADR 0009, verified `pass`
after), and the refusal's anatomy (no approval, no result digest, still
chained). The same canonical bytes reproduce in TypeScript, Python, and
Rust — this repository's cross-language vectors live in
[`../vectors/`](../vectors/), with stdlib-only verifiers in both Python and
JavaScript.

## What the receipts do NOT contain

No file contents, no arguments, no paths. The action identities and the
result digest are **commitments**: the receipt holder can prove what any of
them was by revealing a preimage — as done above for the HEAD ref — and
reveal nothing otherwise. Receipts are references, never payloads.

## Honest limits

- These receipts govern the **MCP gateway path**. The coding agent's native
  tooling ran ungoverned alongside it — Zimam was not fully built under its
  own governance, and we will not claim otherwise until it is.
- An API key identifies a **key, not a person**: everyone sharing a console
  password shares its key, so `approver_attestation` proves which credential
  approved, not which human held it. Per-user sessions, OIDC subjects, and
  reviewer-signed approvals are the rungs above, and the `{method,
  principal}` envelope exists so they arrive without a format break.
- `identity` reads `not_evaluated` on the earliest receipts because the
  governor did not yet verify agent identity — and the records say so
  rather than pretend. From cloud receipt `#2` on, the layer reads `pass`:
  a plane-issued bearer credential (stored only as its sha256) verified at
  gateway boot, with the verified subject required to equal the configured
  agent or the gateway refuses to start. Bearer tokens are the first rung —
  mTLS/OIDC bindings remain future work, and the evidence store also
  re-checks `plane_token` claims against its own credential registry at
  ingest.
- Both processes ran as one OS user here (a laptop demo). The production
  posture — signer as its own user, key unreadable to the gateway — is
  enforced by the signer itself: it refuses keys readable beyond their
  owner, and the socket peer is attested by the kernel either way.
