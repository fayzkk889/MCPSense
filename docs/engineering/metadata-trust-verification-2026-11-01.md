# Shared metadata trust analysis — candidate verification, 1 November 2026

This record concerns the **unpublished 0.4.4 candidate**. The public 0.4.3 release still has the [preserved fresh-audit failures](product-use-audit-2026-10-31.md). A branch push does not update an installed package or approve publication.

## What failed and what changed

The [first-principles contract](metadata-trust-model-2026-11-01.md) starts with effects and authority: an untrusted description cannot authorize disclosure of host secrets, manufacture consent, weaken controls, execute unreviewed instructions or fabricate evidence. A prohibition, observed predicate, quoted search operand or fixed placeholder can contain the same vocabulary without requesting that effect. Unknown context remains unestablished.

The implementation previously interpreted these distinctions independently in literal, intent, effect and tool-specific rules. Different paths disagreed about quoted/negated text and supported fields; finite carrier names lost a private value after renaming or transformation. A sensitive identifier name could also falsely taint a public value. Existing example collections then hid these gaps by becoming the only acceptance evidence.

The candidate resolves metadata context before the semantic checks, preserves original evidence positions through Unicode normalization, follows values through named bindings and transformations, and evaluates control/evidence changes in that same context. Tool-specific exfiltration uses the shared analysis across enumerated metadata fields. Public bindings feed the literal rules too; metadata-defined aliases cannot shadow host-owned credentials. Only an entire fixed replacement value declassifies a binding. Names such as `redacted_api_key` do not make actual secrets public.

Value tracing has a 256-binding capacity. Exceeding it produces an incomplete-analysis error and CLI exit 2, including when only SEC-001 or SEC-011 is selected. It does not accuse the text of being malicious or present a completed clean scan. The raw skill/source literal policies remain distinct from metadata interpretation. MIT, independent npm/Go routes, and the Node-based npm runtime are preserved. No external classifier or metadata upload is introduced.

## Evidence discipline

Labels were frozen in separate commits before their relevant executions:

| Collection | Descriptions / observations | Freeze |
| --- | --- | --- |
| Original public 0.4.3 audit | 48 / 144 | `b44c0f4` |
| Pre-implementation trust validation | 34 / 102 | `b325b38` |
| First post-implementation fresh set | 24 / 72 | `f7c9268` |
| Subsequent user scenarios | 16 / 48 | `a40602a` |
| Value-identity rename invariants | 40 / 120 | `d8b749a` |
| Four historical boundary collections | 116 / 232 | Existing unchanged release gates |

The first post-implementation fresh run **failed**: 21 detected hostile observations, 15 misses, six benign false alarms and 30 benign quiet observations. Its WASM SHA256 was `a83d08880ed3d59a94679ab91e77feb86d3d502368488479949a332fac9a7182`. The original local results remain in `bin/trust-044-initial-fresh/`; their counts, corpus digest and artifact identity are retained in the final machine record. The subsequent rename-invariance failure is preserved in `bin/trust-identifier-invariant-before.log`. Neither failed run was relabelled as success. Corrections were made to shared context/value handling, followed by new artifact builds and complete reruns.

Uppercase, ordinary-prefix, alias-renaming, value transformation, public/private substitution, host-ownership and observed-predicate/active-continuation checks supplement the labelled examples. All nine corpora and the live metadata check are mandatory acceptance gates in native CI and the npm product suite. A mismatch returns a failing process status. The larger suite has a larger outer timeout; assertions and failure exits remain enforced.

## Final candidate product results

Source: `b0e231b219ec8d35d3a2a6f77f693d6b8cdf3d1a`. The subsequent documentation/receipt commit does not change executable source. WASM SHA256: `7350a814975c9af86c8d1dc6ce99fd068188230b9f668bbab11419ea9b091ddd`; Linux native SHA256: `bb9e240487c5c8c6bdb904dd21c9ed08fadff30dcbe8ce8ca39ec37181b5b3ae`. Both identify themselves as 0.4.4.

| User-visible requirement | Final actual-CLI result |
| --- | --- |
| Nine unchanged boundary collections | **PASS on each route:** 353 hostile observations detected, zero missed, zero benign security false alarms, 365 benign observations quiet; 718 total per route |
| Native/npm consistency | **PASS:** every observation agrees on outcome, exit, score and multiset of rule IDs |
| Fresh representative live metadata | **PASS:** six hostile detections, six benign quiet observations, no advertised tools called |
| Required reviewed metadata reference | **PASS:** all 12 journeys, including refusal of missing/changed reference; baseline match does not imply initial safety |
| Beginner and experienced-user workflows | **PASS:** full npm product suite, including terminal explanations, remediation/rescan, JSON/SARIF, report comparison, private/offline permissions and mixed project inspection |
| Core privacy, actionable failures and existing examples | **PASS:** 24 grouped assertions and 197 CLI invocations; malformed/empty/oversized inputs do not become completed clean inspections |
| Existing live protocol discovery | **PASS:** all 15 transport/discovery checks, preserving explicit authentication and response-limit errors |
| Saved baselines, source/skill inspection, inventory and pinning | **PASS:** unchanged baseline, threat-review and dependency product suites |
| Expert coverage and advisory behavior | **PASS:** 87 checks, including online OSV queries for synthetic package declarations and explicit unresolved/source-conflict handling |
| Analysis capacity | **PASS:** six CLI journeys across npm/native and default/SEC-001-only/SEC-011-only selection return exit 2 with manual-review error, without a malicious-content allegation or clean report |

Full Go tests and `go vet ./...` pass on the final source. The Action/package checks pass all 15 tests. A final 10-second evidence fuzz run completed 7,774 generated executions without a crash or invalid evidence. Local race testing lacks a C compiler; the four hosted Linux/Windows Go 1.22/1.27 native jobs passed their race checks on this source in [run 41292279445](https://github.com/fayzkk889/MCPSense/actions/runs/41292279445). Hosted npm platform jobs and release dry-run are checked separately at the final PR head; do not infer their completion from local results.

To repeat the user acceptance locally, build with `node scripts/build-npm-runtime.cjs`, then run `node scripts/npm-product-suite.cjs`. For a native build, set `MCPSENSE_TEST_BINARY` to that CLI and run `node scripts/boundary-acceptance.cjs`. The expert walkthrough is `node scripts/incident-product-audit.mjs`, with `MCPSENSE_INCIDENT_ONLINE=1` for public advisory queries. These tests inspect synthetic declarations; they do not execute hostile fixture instructions or install the named vulnerable packages.

## Verification scope and limits

The final machine-readable receipt is [metadata-trust-verification-2026-11-01-results.json](metadata-trust-verification-2026-11-01-results.json). It records source/artifact identity, unchanged corpus digests, every boundary outcome, native/npm parity, live results and capacity checks. Detailed local command output is retained under `bin/trust-044-root-final-*`. Hosted checks are associated with the exact PR head in [PR #21](https://github.com/fayzkk889/MCPSense/pull/21).

These are authored, targeted examples repeated across fields and routes. They are regression evidence, not 718 independent attacks, independent field accuracy or proof of future zero misses. Once an example informs a correction, its later success is regression evidence. The scanner still uses bounded lexical and relational analysis; it does not understand arbitrary language, verify a server's actual behavior or enforce runtime authorization. A clean report remains `not_established`. Reviewed metadata baselines detect subsequent recognized changes; they do not establish initial safety.

Local product runs reuse the built CLI entrypoints and skip installation/onboarding. Hosted CI retains its existing package smoke checks alongside the product gates. No npm login, merge, release tag, package publication or website deployment is part of this verification. Release approval and verification of published bytes remain separate steps.
