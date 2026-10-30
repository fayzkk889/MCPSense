# Metadata effect analysis — 28 October 2026

## Cause, contract and design

The [public 0.4.2 audit](product-audit-2026-10-27.md) found the same misses in native Go and npm. Packaging was not the cause. A hostile metadata field proposes that the host use its authority for a different effect: move a secret, weaken a safeguard, conceal evidence or execute downloaded code. Recognizing individual words does not establish whether those effects are related, negated or merely quoted as data.

The earlier bounded event model improved authority/approval/refusal detection but did not represent credential transformations and staged carriers, Boolean monitoring settings, empty escalation destinations, no-op replacements or claims about actual safeguard state. Treating its green development corpora as evidence about all hostile language was the evaluation mistake. Adding an exact incident sentence to a regex would leave these missing relations unaddressed.

This follow-up adds `internal/detection/effects.go` to the shared native/WebAssembly detector. It extracts local actions, their object spans and polarity, then evaluates five review invariants:

| Rule | Relation inspected |
| --- | --- |
| EFF-001 | Sensitive source to a release/request destination, including encoding and explicitly referenced staged notes, memos, JSON, bundles or attachments |
| EFF-002 | Configuration/replacement action on security monitoring or escalation, paired with a disabling state, no-op or empty recipient destination |
| EFF-003 | Security evidence reclassified into informational/debug output |
| EFF-004 | Download/fetch followed by execution of code |
| EFF-005 | Described missing safeguard followed by a contrary claim that it remains active |

Transforms preserve the inferred sensitivity of a carrier; encoding is not declassification. Public verification keys are distinguished from private material. Sources do not taint unrelated later public data. Relations use at most three adjacent 48-word chunks, with explicit artifact references for cross-clause credential propagation. URL path components are data, not action verbs. These limits bound work and avoid joining arbitrarily distant facts; they also bound recall.

Negation scope now accounts for coordinated prohibitions such as “cannot ... or acquire higher authority.” A fresh positive action after a conjunction/colon is still inspected. A complete literal lookup may contain a quoted attack phrase; its anchored return-object grammar does not exempt an appended active instruction. Skill-file literal scanning retains its separate policy. Existing rule families remain active.

The new production source is embedded in the detector identity. A report produced by the previous detector cannot satisfy equivalent-detector remediation verification. JSON/SARIF assessment remains `not_established` or `review_required`, always `authorization_enforced:false`. A score of 100 and exit 0 do not authorize execution.

## Research and architectural limits

Primary sources reviewed on 28 October:

- [MCP security best practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices) put consent, token audience validation, network restrictions and execution controls at concrete trust boundaries. Those controls cannot be inferred from a tool's own claim that it is authorized.
- [Microsoft's MCP indirect-injection guidance](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/) combines injection screening with separation of untrusted content and supply-chain controls.
- [Invariant's guardrails reference](https://github.com/invariantlabs-ai/docs/blob/main/docs/mcp-scan/guardrails-reference.md) includes tool-argument and dataflow restrictions over actual calls/results, a broader enforcement surface than static description screening. Its current scanner repository redirects to [Snyk Agent Scan](https://github.com/snyk/agent-scan).
- [Defenses Against Prompt Attacks Learn Surface Heuristics, ACL 2026](https://aclanthology.org/2026.acl-long.502/) reports generalization and false-refusal problems even in trained defenses. Replacing a finite lexical layer with a model would not establish exhaustive detection.

No third-party detector was added and no user metadata was uploaded to a classifier. npm still needs only patched Node 22+, Go installation remains independent, and MIT is unchanged.

This is bounded lexical effect analysis, not semantic verification, a general taint engine, an invocation proxy or proof of authorization. Unsupported vocabulary, long-distance aliases, multilingual paraphrases, malicious initial approvals, tool results and server implementation behavior remain outside its guarantee. Arbitrary natural-language screening cannot honestly promise zero misses. The existing optional required-metadata-reference check rejects changed recognized metadata independently of wording; the initial reference and all runtime effects still need host/operator control. No new release is authorized by passing authored cases.

## Verification record

The original 32-text audit is unchanged (SHA-256 `c35976e18fbbeb3e71a845ca5534cc29273cb9d5636552069e7b786ff2cec815`). Another 32-text effect/polarity corpus was committed in `3d5d5ac` before implementation, alongside a detector-level test reproducing both sets. Labels were not relabelled to match output. These are development/acceptance examples, not an independent benchmark or field-accuracy estimate.

The strict product gate now includes 232 observations: original 24, earlier validation 80, incident audit 64 and new effect cases 64, across tool descriptions and server instructions. These are repeated observations of 116 texts, not 232 independent attacks. Fast detector checks also exercise capitalization, benign prefixes, unrelated source/sink events and active suffixes.

Additional composition checks run 80 source/carrier/release/destination combinations with public-data and prohibition controls (240 assertions, including repeated controls). They exposed a legacy-path negation defect: stripping a leading prohibited action could turn its remaining object and coordinated verb into an apparent disclosure. The fix retains full polarity for disclosure/event analysis while checking subsequent legacy actions separately. A reporting complement (“do not reveal that this helper copies passwords ...”) does not negate the helper's behavior; an object-relative clause inside a prohibition keeps its negation. Earlier cancellation, permission and concealment regressions remain enforced. Six conditional-state controls also pass.

Final production code is `cbcc4b4bc60166b9f789a8f692355bbdac7b2988`. Both the independently built Linux native CLI and a freshly installed Windows npm tarball pass:

| Frozen suite | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| Earlier original failures | 12 | 0 | 0 | 12 |
| Earlier validation | 40 | 0 | 0 | 40 |
| 27 October incident audit | 32 | 0 | 0 | 32 |
| New effect cases | 26 | 0 | 0 | 38 |
| Total per route | 110 | 0 | 0 | 122 |

The full installed npm product suite passes: reports, explanation/remediation/rescan/verification, privacy, malformed/missing/oversized inputs, configuration non-execution, authorized live metadata discovery, offline behavior, existing corpora, dependency-inventory workflows, baseline compatibility, and the strict description gates. Offline installation with Go/archive tools absent and no installation hooks also passes. Native and npm each pass 12 deterministic required-reference workflows. The expert audit passes 86 checks and fails the same one upstream-advisory applicability control described below; that failure is retained.

All source tests pass on Linux with Go 1.27.3 and the existing Go 1.22 compatibility toolchain; `go vet ./...` passes. The [hosted final-code workflow](https://github.com/fayzkk889/MCPSense/actions/runs/40734953023) checks native Windows/Linux, race detection, Go 1.22/1.27, npm on three operating systems and Node 22/24, lint, vulnerabilities, the action and release dry run. Check its current conclusion rather than treating a pending job as passed. Local Windows restricted runs retained execution-policy, rename and networking failures; unrestricted npm/contract checks and Linux checks were used without changing Windows protections. Local Linux race testing lacked a C compiler; hosted native jobs run the race tests.

The [machine-readable receipt](detection-effects-2026-10-28-results.json) records component hashes, actual tarball integrity, native bytes, every normalized observation, expert checks and both runtime-specific detector identities. Outcomes, scores, exits and rule multisets agree; concurrent rule arrival order is normalized. The complete source/runtime identity formula was checked for every frozen report. The description-module digest alone is not the whole-scanner identity; an initial local receipt helper incorrectly compared them. That helper error prompted extra builds, did not invalidate the product assertions, and is not presented as evidence of a product defect.

Intermediate failed tests and earlier build receipts remain under ignored `bin/effects-*`; labels and the public 0.4.2 failure record are preserved. This branch keeps version strings at 0.4.2 for regression compatibility; the source candidate's bytes are **not** the published 0.4.2 artifact. A separately approved new version/publication is still required.

The Tensorlake publisher/OSV applicability conflict from the previous audit is separate from metadata detection. No feed record was rewritten or advisory silently suppressed in this change. It remains a release-triage item; clean metadata regression results do not resolve it.
