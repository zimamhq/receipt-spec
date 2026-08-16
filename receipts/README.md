# The published signed receipts — two chains, two custodies

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

## The cloud chain (`cloud/`) — one stream, two signing custodies

Two nights later the same agent ran governed against the **live cloud
evidence store** (the control plane on Railway, verified-ingest — the plane
re-checks every signature, guard, and chain link before a row exists).

- [`cloud/00000000.json`](cloud/00000000.json) — 12 August, signed by the
  same separated **Rust signer** (EdDSA, kernel-attested caller), a governed
  read of this very directory's README, held until a human granted it.
- [`cloud/00000001.json`](cloud/00000001.json) — 14 August, signed by an
  **AWS KMS key in Frankfurt that has never existed outside its HSM**
  (ES256 over the same RFC 8785 bytes). Approved from the Zimam console UI.
  Its result digest commit-anchors `.git/refs/heads/main` again — this time
  to the commit that added the KMS adapter itself.

Same stream, same chain rules, different keys and different algorithms —
resolved by key id exactly the way the store's registry does. A demotion of
one custody never orphans the history of the other.

## Verify everything yourself

From the repository root, with Node ≥ 22.18:

```bash
node receipts/verify.mjs
```

Twenty checks across both chains: every signature against the published
public keys ([`signer.pub`](signer.pub), [`kms-signer.pub`](kms-signer.pub)),
the five signing-time guards on every payload, both gap-free chains from the
all-zero genesis — one of them mixed-algorithm — and both commit anchors
recomputed from first principles. The same canonical bytes reproduce in
TypeScript, Python, and Rust — this repository's cross-language vectors live
in [`../vectors/`](../vectors/), with stdlib-only verifiers in both Python
and JavaScript.

## What the receipts do NOT contain

No file contents, no arguments, no paths. The action identities and the
result digest are **commitments**: the receipt holder can prove what any of
them was by revealing a preimage — as done above for the HEAD ref — and
reveal nothing otherwise. Receipts are references, never payloads.

## Honest limits

- These receipts govern the **MCP gateway path**. The coding agent's native
  tooling ran ungoverned alongside it — Zimam was not fully built under its
  own governance, and we will not claim otherwise until it is.
- `identity` reads `not_evaluated` because the governor does not yet verify
  agent identity itself (the mTLS/OIDC binding is future work); what IS
  attested is the kernel-verified identity of the signer's caller.
- Both processes ran as one OS user here (a laptop demo). The production
  posture — signer as its own user, key unreadable to the gateway — is
  enforced by the signer itself: it refuses keys readable beyond their
  owner, and the socket peer is attested by the kernel either way.
