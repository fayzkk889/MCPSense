# Detection root-cause investigation — 26 October 2026

## Reproduction and cause

Public 0.4.1 detected one of six newly labelled hostile texts; five were missed as both tool descriptions and server instructions, identically through npm and Go. Preserve that baseline in the [user-test record](user-test-2026-10-26.md) and its unchanged result JSON. Installation was not the cause.

The investigation found four contributing problems:

1. **Phrase-dependent relations.** Individual regex combinations required particular role nouns and verb ordering. The scanner already knew the origin was untrusted metadata, but rules still required the text to name that origin. Permission denial, identity replacement, contradictory results, evidence suppression and approval-policy edits were handled as unrelated phrases.
2. **Lost scope and roles.** Literal rules could borrow an action from one sentence and credentials from another. Whole-field feature bags could combine unrelated facts. A generic instruction-documentation request could be mistaken for extraction of the model's own instructions because ownership was optional.
3. **Evaluation feedback.** Passing examples used during development became regressions, which is useful but does not establish generalization. The newly preserved failure diagnostic was not required by existing CI. A green run could therefore coexist with known misses.
4. **Finding score versus security establishment.** Zero findings produced score100 and exit0. Terminal disclaimers existed, but JSON lacked a distinct assessment telling consumers that security and authorization had not been established.

The fundamental limit is broader: arbitrary natural-language intent cannot be made reliably decidable by maintaining a deny list. OWASP describes input screening as a review layer rather than a security boundary and recommends permissions at the tool boundary. MCP likewise puts invocation control in the client/host. This change does not claim to solve general prompt injection.

Sources: [OWASP prompt-injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), [MCP tools and invocation control](https://modelcontextprotocol.io/specification/2025-06-18/server/tools), [MCP security practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).

## Candidate changes

The unpublished version is 0.4.2. Public npm/GitHub 0.4.1 is unchanged until separate publication approval.

- A shared bounded event model captures actions, their local objects, negation, previews, identity substitution and contrary outcomes. Five invariants replace the corresponding phrase-specific families: untrusted-to-privileged authority promotion, replay after denial under another identity, false success, security-evidence suppression and weakened approval safeguards. Vocabulary remains explicit and limited; this is not a trained semantic classifier.
- Literal metadata rules are clause-local. Only explicitly temporal legacy relations may connect neighbouring clauses. Context windows are bounded, with linear chunking of long clauses. Skill/source scanning retains its separate literal policy. Model instruction extraction requires an ownership/privileged-context signal, rather than any request to show instructions.
- JSON includes `security_assessment`: `not_established` without findings or `review_required` with findings, always with `authorization_enforced:false`. SARIF carries the same object; CLI displays the state. Existing finding score and exit codes remain compatible. Report copies recompute this state rather than trusting an imported claim of safety.
- The original 12 texts and 40 additional cases frozen before implementation are mandatory native/npm product gates: 104 observations on two metadata surfaces. Detector tests additionally exercise case changes, ordinary prefixes, negation, unrelated actions and defensive-prefix escapes. Original labels and public failure results are not rewritten.
- A separate optional `--require-metadata-baseline` check rejects unrecognized changes independently of semantic screening. It requires an explicit pre-existing full snapshot, refuses first-use capture, refuses combined update/skip options, and does not let severity/rule filters suppress the comparison. The new full recognized-catalog digest includes server identity, schemas, annotations, resources, prompts and authentication declarations, with stable catalog ordering. Historical baselines remain usable for ordinary comparisons but cannot satisfy the new strict check without the digest.

## Deterministic metadata workflow

After inspecting the original target through a trusted workflow, capture a local reference explicitly:

```sh
mcpsense scan ./manifest.json --offline --baseline ./operator-baseline.json --update-baseline
```

Subsequent scans can require the captured metadata to match:

```sh
mcpsense scan ./manifest.json --offline --baseline ./operator-baseline.json --require-metadata-baseline
```

The gate exits2 on missing, incomplete or different metadata and never updates its reference. A baseline is a trusted local input, not a signature or proof a human reviewed it. Initial review, baseline access control and execution permissions remain external. Unknown manifest extensions, runtime responses, fetched contents and installed server behavior are not in this recognized-catalog gate. For local live discovery, `--allow-exec` still authorizes process startup; the metadata comparison is not a process sandbox or an invocation interceptor.

## Verification record

Before implementation, commit9f5ae12 froze the 40-case validation fixture, SHA256 `2027914f6a38e4c6349b793bcfbab1adc3c494c8bc505c18fdac62c945630683`. This is an authored development validation set, not independent field evaluation. Iterative failures and their corrections consumed it as development data; it is now regression evidence.

The full Linux Go1.22 native suite passed after the event-model/report changes. All 104 original/validation metadata observations passed through an actual installed candidate: original TP12/FN0/FP0/TN12, validation TP40/FN0/FP0/TN40. Twelve deterministic gate journeys passed, including opaque new text, removed tools, severity/rule-filter attempts, absent references and attempts to update/skip the gate. Normal anonymous Windows candidate installation and upgrade from public0.4.1 passed13 command/onboarding checks with Go/tar absent. JSON/SARIF assessment agreement passed in installed remediation/report workflows.

Broader CLI checks rejected intermediate refactors for two existing authority-comparison forms. Their labels were preserved and the comparative-authority relation restored. All seven datasets (232 texts), including the unchanged persona examples extracted into a shared JSON fixture, now run as fast detector tests with case and prefix transformations, instead of relying on later CLI tests to expose such regressions. No acceptance threshold was relaxed. The installed package and cross-platform results are recorded on [PR16](https://github.com/fayzkk889/MCPSense/pull/16); passing authored cases does not establish universal detection. A local unsigned Windows native build was blocked by Application Control during an extra check; that run was stopped and is not counted as a pass. Hosted native checks and actual installed npm checks are separate evidence. Runtime assets and raw local logs remain under ignored `bin/`; no credentials, Go installation requirement for npm or protection-setting changes are introduced. MIT remains unchanged.
