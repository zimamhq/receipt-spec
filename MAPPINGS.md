# Regulatory Mappings — Draft (as of 2026-08-14)

**Status:** draft, maintained alongside the formats. **This is not legal
advice**, and no mapping below claims that producing receipts makes anyone
compliant with anything. The claim is narrower and honest: *these formats
produce evidence that the listed obligations ask for*. Compliance is a
property of an organisation's whole process; receipts are the part of that
process a verifier can check cryptographically.

Terminology: **event chain** = [`SPEC.md`](./SPEC.md) (the per-run log);
**signed receipt** = [`SIGNED.md`](./SIGNED.md) (the per-decision
attestation); **evidence store** = any verified-ingest receipt store (one that
re-checks signatures, guards, and chain links before accepting a row).

## 0. What applies when

| Regime | Instrument | Key dates |
|---|---|---|
| EU AI Act — transparency (Art 50) + AI literacy | Reg. (EU) 2024/1689 | In force since **2 Aug 2026** |
| EU AI Act — high-risk (Annex III) obligations incl. logging | As amended by **Reg. (EU) 2026/1744** (Digital Omnibus, OJ 24 Jul 2026) | **2 Dec 2027** |
| EU AI Act — high-risk embedded in regulated products (Annex I) | Same | 2 Aug 2028 |
| Colorado ADMTA | SB 26-189 (2026; replaced the repealed SB 24-205) | **1 Jan 2027**, conditional on AG rulemaking |
| ISO/IEC 42001:2023 | Voluntary management-system standard | Certifiable now |

## 1. EU AI Act

| Obligation | What it asks for | Where the formats answer | Honest limits |
|---|---|---|---|
| **Art 12** — record-keeping: automatic recording of events over the system lifetime | Logs sufficient to identify risk situations and trace operation | The **event chain**: every governed run logs request → decision → approval → execution → oversight as ordered, hash-linked events with integer timestamps. The **signed receipt** adds a per-decision attestation (verdict, six-layer controls, identities-by-digest) whose integrity survives export. | Art 12(3)'s biometric-specific fields are content decisions for the deployment, not format fields. The formats guarantee the *integrity and structure* of what was logged, not that a given deployment logged everything an Annex III use requires. |
| **Art 14 / Art 26** — human oversight, exercised and demonstrable | Oversight measures and their actual use | The `escalate` verdict holds execution until a human decides; `approval { initiator_id, approver_id, decided_at }` is **inside the signed bytes**, and the `self_approval_guard` refuses a record where requester and approver are the same principal. Withdrawn and rejected approvals leave their own events. | The formats evidence oversight *events*, not the adequacy of an oversight *design* (Art 14 is also a design obligation on providers). |
| **Art 19 / Art 26(6)** — keep the logs (≥ 6 months) | Retention of Art 12 logs | Chained formats make retained logs **tamper-evident in storage and after export**; the evidence store verifies on ingest and serves them back verifiable. | Retention *duration* is deployment policy, not a wire-format property. |
| **Art 50** — transparency/disclosure to persons | Disclosures made where required | Runtime policy packs enforce disclosure behaviour (`transform`/`warn`/`deny`), and every pack evaluation lands in receipts (`PACK_EVALUATED`; `controls_evaluated.policy` with `matched_count`). A regulator sees *which rule fired on which call* — with rewritten values never recorded. | The formats evidence that disclosure controls executed; drafting the disclosures is the deployer's. |
| **Art 72** — post-market monitoring | Systematic collection and review of operation data | `QA_SAMPLED` + review events (deterministic sampling), eval pass/fail events, incident and trust-transition records — a monitoring trail that is itself evidence-grade. | — |
| **Art 86** — explanation of individual decision-making | The role of the AI system and the main elements of the decision | A signed receipt is a decision skeleton: `verdict`, `reason_code`, the six-layer controls record, input/enforced identities, approval if any. | An explanation for an affected person is prose the deployer writes; the receipt is its verifiable substrate. |

## 2. ISO/IEC 42001:2023

| Control / clause | What it asks for | Where the formats answer |
|---|---|---|
| **Annex A.6.2.8** — recording of event logs | Event logs across the AI lifecycle for traceability and accountability | Both formats, directly: the event chain per run, the signed stream per terminal decision — ordered, hash-linked, exportable, independently verifiable. |
| **Annex A.6.2.6** — AI system operation and monitoring | Ongoing operational monitoring | Trust scores and transitions, QA sampling and reviews, eval events, incidents — recorded as receipt events, not dashboard-only state. |
| **Clause 8.1** — operational planning and control | Controlled execution of AI processes | The governed path itself: classification → policy → trust gate → ceilings → execution, each recorded in `controls_evaluated` (all six layers, `not_evaluated` explicit). |
| **Clause 9.1** — monitoring, measurement, analysis, evaluation | Measured performance | Impact-weighted trust movement per (agent × action class); eval reports feed trust events that appear in receipts. |
| **Clause 10** — nonconformity and corrective action | Detected failures drive correction | Incident receipts and instant demotion transitions record both the nonconformity and the consequence, in the same tamper-evident trail. |

*Mapping to an ISO management system is inherently partial: 42001 governs an
organisation; these formats supply the operational-evidence layer an auditor
samples.*

## 3. Colorado ADMTA (SB 26-189)

The 2026 act replaced the repealed SB 24-205, dropping the duty-of-care and
impact-assessment apparatus and keeping disclosure-based duties.

| Duty | Where the formats answer | Honest limits |
|---|---|---|
| **Explanation** of a consequential automated decision | `verdict` + `reason_code` + the six-layer controls record identify what decided and why, per decision, signed. | Consumer-facing wording is the deployer's. |
| **Human review** opportunity | The escalate/approval machinery *is* a human-review record: named reviewer, timestamp, initiator ≠ approver enforced at signing time. | — |
| **Record retention (3 years)** | Chained, signed records survive storage and export without silent alteration — a 3-year-old receipt is as checkable as a fresh one. | The 3-year clock is deployment configuration. |
| **Notice** that an ADS is in use | Runtime packs can enforce notice behaviour the same way the Art-50 pack does, receipted per call. | Notice content and channel are the deployer's. |

## 4. What these formats deliberately do not claim

- They do not retain anything: retention windows are deployment policy.
- They do not make required *content* appear in logs; they make whatever was
  logged tamper-evident and attributable.
- They do not perform impact assessments, register systems, or notify
  authorities — process obligations outside a wire format.
- No mapping above is a conformity claim. The sellable sentence is exactly
  this: **"here is the evidence, and here is how to verify it yourself."**
