# The Zimam Receipt Formats

**Tamper-evident execution evidence for AI agents — specified, vectored, and
verifiable from this repository alone.** Apache-2.0, on purpose: this format
is meant to be implemented by anyone, in anything, for any reason.

A governed agent action leaves two artifacts. The **event chain** is the
diary: every step of one run, hash-linked so that editing, dropping,
reordering, or backdating any event breaks verification at that exact link.
The **signed receipt** is the sworn statement: one cryptographically signed
attestation per terminal decision — what was decided, which control layers
said what, who approved, and a digest of what ran — in a gap-free per-agent
stream that survives storage, export, and time.

## Verify everything, right now

Two commands, Node ≥ 18, no packages, no build:

```bash
node vectors/verify_vectors.mjs   # the conformance corpus, byte for byte
node receipts/verify.mjs          # real production receipts, two custodies
```

The second command verifies **actual receipts from the system governing its
own construction**: two chains — one signed by a separated signer daemon
with the OS kernel's caller attestation inside the signed bytes, one
continuing across custody into an AWS KMS key that has never existed outside
its HSM — each commit-anchored to the exact repository state that produced
it. The story is in [`receipts/README.md`](./receipts/README.md).

## The documents

| Document | Specifies | Status |
|---|---|---|
| [`SPEC.md`](./SPEC.md) | The event chain — structure, canonicalization, hashing, event registry, verification | **v1.1, frozen wire format** |
| [`SIGNED.md`](./SIGNED.md) | The signed receipt — payload, five verdicts, six-layer controls record, RFC 8785 canonicalization, chaining, EdDSA/ES256 envelopes, key identity, the five signing guards, verification algorithm | **v1.0.0-draft.1** |
| [`MAPPINGS.md`](./MAPPINGS.md) | Where the formats answer regulatory obligations (EU AI Act, ISO/IEC 42001, Colorado ADMTA) — and where they honestly do not | draft |

## Conformance

[`vectors/vectors.json`](./vectors/vectors.json) pins the byte-identity
surface: canonicalization cases (including the UTF-16 key-ordering edge that
breaks naive implementations), four complete receipts with deterministic
Ed25519 signatures under a published test key, and five guard-refusal cases.
Three independent verifiers reproduce it:

- [`vectors/verify_vectors.mjs`](./vectors/verify_vectors.mjs) — JavaScript, Node stdlib only (also verifies the signatures)
- [`vectors/verify_vectors.py`](./vectors/verify_vectors.py) — Python, stdlib only
- The reference implementation's TypeScript and Rust suites re-derive the
  same bytes (the main Zimam repository opens with the product launch)

An implementation conforms when it reproduces every canonical byte, digest,
and EdDSA signature, and refuses every guard case. ES256 conformance is
functional, not byte-pinned — ECDSA is randomized by design.

## Freezing to 1.0.0

Per [`SIGNED.md`](./SIGNED.md) §11: a stable public vector URL (this
repository), at least two independent implementations reproducing the
corpus, and external review of the guard set. Issues and implementation
reports are welcome.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE). Copyright 2026 Zimam.
