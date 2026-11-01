# Metadata trust model and root-cause work — 1 November 2026

## The decision being made

An MCP description is an untrusted statement about an interface. The security question is whether it asks the host to cross a data, authority, control, execution or evidence boundary. A suspicious word alone does not answer that question. Identical words can describe a prohibited action, a literal search operand, a fixed placeholder or an active instruction.

For screening, an actionable hostile candidate is an active request for an effect requiring authority the metadata cannot supply: release private material, manufacture consent, weaken a security control, promote retrieved content into policy, run unreviewed code or misrepresent results. A benign control preserves those boundaries or uses dangerous-looking text solely as data. Unknown language or missing user/permission context is unestablished, not proven benign. A description cannot attest its own authorization, destination ownership or runtime behavior.

The product fails when it misses a labelled boundary-crossing request, flags a genuine prohibition/data operand, applies different semantic rules to equivalent metadata fields, silently omits coverage, or implies safety from absence of matches. The first three occurred in the preserved 31 October audit. A reviewed-reference match establishes unchanged recognized metadata only; it does not establish safe initial approval.

## Top-down and bottom-up diagnosis

The top-down security invariants are confidentiality of private values, integrity of host authority and approvals, functioning controls, truthful evidence and explicit execution authority. The bottom-up trace starts at metadata enumeration, then context interpretation, action/value relations, individual rule paths, evidence/reporting and exit policy.

The current implementation loses essential distinctions at context interpretation and relation extraction. Clause-wide exemptions and independent literal/intent/effect/tool-specific paths can disagree about polarity, quoted operands and value identity. Fixed carrier nouns cannot follow an arbitrary named intermediate. Sensitive vocabulary in a field name is confused with the value of a fixed redacted constant. Selected disabling strings are mistaken for a model of control effectiveness. The evaluation process then tests the growing set of known examples and treats its success as stronger generalization evidence than it supplies.

## Implementation contract

1. Establish shared, span-preserving metadata context before every semantic security path. Scope negated actions, embedded clauses, quoted operands and constant redacted values locally; never exempt a later positive instruction because of an earlier defensive sentence. Preserve original byte-span evidence. Skill/source literal policies remain distinct from advertised-metadata context.
2. Trace values through acquisition, assignment, transformation, named intermediates and release. Encoding/compression preserve sensitivity. A new unrelated public value must not inherit a previous private value. A variable name containing `redacted` does not declassify an actual secret, while a fixed `[REDACTED]` constant is not a private value.
3. Evaluate control effects and authorization/evidence changes in the same active context. Include lost delivery/coverage, manufactured consent, insecure validation defaults and fabricated outcomes. Observing/reporting a bad state is different from causing it.
4. Route tool-specific exfiltration screening through the shared metadata analysis and enumerate supported fields consistently. Preserve existing public rule identifiers and review semantics; do not silently disable the old check or classify every mention of secrets as hostile.
5. Gate acceptance on unchanged historical corpora, the frozen 31 October failures, pre-implementation validation, field/runtime/live parity, compositional counterexamples and a fresh user evaluation after implementation. Preserve failed runs and original labels. Do not claim field accuracy or exhaustive future detection from authored examples.

## Research grounding

The [MCP local-server security guide](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/local-server-security.mdx) treats tool definitions as untrusted runtime input and recommends reviewing/pinning definitions. [OWASP's MCP security guidance](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) separates description integrity from least privilege, sensitive-action approval and runtime isolation. These support treating metadata as evidence rather than authority.

[CaMeL](https://arxiv.org/abs/2503.18813), revised June 2025, separates trusted control from untrusted data and enforces capability policies at tool calls. Its runtime architecture is not something a static lexical screen acquires by recognizing more text. The applicable principle here is explicit provenance and boundaries; runtime authorization remains a host responsibility. Research was checked on 1 November 2026. No third-party classifier, service dependency or user-metadata upload is introduced.

This document is an implementation/verification contract, not a completed-results claim or publication approval.
