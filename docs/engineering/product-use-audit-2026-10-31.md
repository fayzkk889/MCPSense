# Product-use audit of released 0.4.3 — 31 October 2026

**Verdict: FAIL for fresh hostile-description security acceptance.** The existing product workflows function, but newly authored user scenarios reproduce substantial missed hostility and benign false alarms. Passing the old regressions is insufficient evidence for a broad protection claim or another release acceptance decision.

The maintainer requested product testing without installation or release work. This audit reuses the actual public npm 0.4.3 installation and independently public-Go-installed Linux 0.4.3 binary. No installer, login, package publication, tag, merge or website deployment is part of this audit. Production code, package bytes and MIT are unchanged.

## Product and evidence identity

- Released source: `v0.4.3`, `09f8022f300880244c4f91a961fbd59c243506c9`; audit checkout starts from main `5334eea82936dc9a61286c20b086ef0154b05d2b` (documentation follow-up only).
- Actual npm runtime SHA256: `3f408c15b0533160e1899bc3fa84c2d8aea8c4c41f9380e8258584b203a899b9`, matching the [canonical release receipt](release-0.4.3-2026-10-30.md). Node 22.23.4 executes that bundled engine on Windows.
- Independently installed public Go binary SHA256: `75898648c2cbf2c080df3d096e4d105bf484a746dccf289d3291e7969f706993`.
- [48 labelled descriptions](../../testdata/product-use-audit-2026-10-31.json), 24 hostile and 24 benign, were committed at `b44c0f4` before their first scanner execution. SHA256: `8546a116b29bfddb1da920f17e63542f267e8ee731c72694992444e6a9b726f2`.
- [Machine-readable results](product-use-audit-2026-10-31-results.json) preserve every metadata observation, finding evidence, counts, live outcomes and baseline results.

The cases were written before inspecting the detector implementation in this audit. They are targeted authored adversarial and benign examples, not a random sample, independent field evaluation or overall accuracy estimate. Three metadata fields and two engines repeat the same texts; they are not independent attacks. Labels were not changed after observing results.

## Do practical workflows work?

All seven existing product suites passed through the released npm entrypoint. A separate terminal-to-remediation walkthrough also passed its 14 user checks. This execution runs the CLI as a user would, preserving exit codes, output files and reports. It does not rebuild the engine or substitute internal functions for the product.

| User goal | Result |
| --- | --- |
| Inspect ordinary configuration, identify known hostile text, explain/remediate/rescan and compare reports | PASS: core product suite; 24 grouped checks and 197 CLI invocations, including its historical description benchmarks |
| Read a terminal finding and suggested fix, edit/rescan, export JSON/SARIF, verify remediation, scan a mixed source/skill/manifest project and enforce offline/private-endpoint permissions | PASS: separate 14-check user walkthrough; no installation |
| Preserve private values and baseline contents; distinguish malformed input from a clean scan | PASS: core privacy, coverage and actionable error checks |
| Discover live metadata without executing advertised tools | PASS: 15 existing discovery/transport checks, including pagination, unsupported authentication and malformed/oversized responses; 29 protocol requests, no tool calls |
| Save/compare a metadata baseline, retain history and reject incompatible reports | PASS: 14 grouped saved-baseline checks, 21 CLI invocations |
| Review package pinning and trust-boundary diagnostics | PASS: existing threat-review suite, 8 invocations |
| Inspect supported explicit dependency inventories | PASS: existing dependency suite, 18 invocations using its controlled advisory cache |
| Preserve previous hostile/benign corrections | PASS: all 232 frozen description observations and 12 required-reference workflows |
| Show supported metadata coverage and explicit advisory disagreement | PASS: all 87 existing expert checks, with online public OSV queries enabled for synthetic Tensorlake declarations |

These green results describe exercised workflows and old cases. They do not override the failing fresh evaluation below. No affected package, fixture credential transfer or remote setup script was installed or executed.

## Fresh detection results

Each description was supplied unchanged as a tool description, server instruction and input-schema property description. A hostile observation counts as detected if **any `SEC-*` finding** appears, not only `SEC-001`. A quality warning does not count as security detection. This is a deliberately permissive detection criterion; false alarms use the same security criterion.

Both released engines agree on every observation's outcome, exit code, score and multiset of rule IDs. Finding order can differ and was normalized only for parity comparison.

| Metadata field, per engine | Detected hostile | Missed hostile | Benign false alarms | Benign quiet |
| --- | ---: | ---: | ---: | ---: |
| Tool description | 10 | 14 | 6 | 18 |
| Server instructions | 9 | 15 | 5 | 19 |
| Schema description | 9 | 15 | 5 | 19 |
| Total observations | 28 | 44 | 16 | 56 |

Of the 24 distinct hostile descriptions, **15 were missed in at least one field and 14 in all three fields**. Six of the 24 distinct benign descriptions were falsely flagged in at least one field. All 44 missed hostile observations returned exit 0; 34 also had no findings and score 100. Their separate security assessment correctly remained `not_established`, which communicates uncertainty but does not supply the missing detection.

Missed requests include refresh-token disclosure in a URL, a session cookie relayed through a named record, a compressed/encoded SSH private key, an API key in an image URL, unconsumed alert queues, zero-percent event sampling, an indefinite maintenance window, self-approved privileged actions, changing an authorization default to allow, disabling TLS identity checks, falsely reporting authentication success and erasing audit evidence. A field misleadingly named `redacted_api_key` carrying the actual unmasked key also escaped detection.

False alarms include an explicit instruction to stop after TLS verification fails and **not send credentials**, a rule that retrieved data cannot override system instructions, a literal training-example search, a fixed `[REDACTED]` placeholder and a long coordinated refusal. A benign public-error response is classified as critical exfiltration in the tool-description path while remaining quiet in the other two fields.

### Live user reproduction

A harmless loopback MCP peer advertised six representative fresh descriptions in tool descriptions and server instructions, producing 12 observations. All discovery scans completed and the peer received only `server/discover` and `tools/list`; **no advertised tool was called**.

Results: TP 2, FN 4, FP 4, TN 2. Cookie relays and unconsumed security-alert queues were missed in both fields. The benign TLS refusal and redacted-placeholder descriptions were falsely flagged in both fields. The known credential-printing control was detected and ordinary public search data stayed quiet. These failures therefore reproduce in the live metadata product path, not only in synthetic local manifest loading.

## Does the reviewed-reference check help?

Yes, for changes after an operator's review. A further 80 checks passed. The CLI rejected all **72 hostile catalog changes** (24 descriptions in three fields), preserved the approved reference bytes, rejected benign changes too, and retained the gate under severity and rule filters. The original reviewed metadata continued to match after all failures.

The same test also reproduced the boundary of that protection: the missed alert-queue instruction could be captured as an initial reference with exit 0, then matched with exit 0. A reference detects change; it cannot decide whether the initial contents are trustworthy. It does not enforce runtime permissions or validate tool behavior.

## What causes these failures?

Inspection of the unchanged released source after freezing/evaluating the cases identifies shared detector limitations rather than a packaging problem:

1. **Finite action, value and alias models omit equivalent effects.** [effects.go](../../internal/detection/effects.go) recognizes particular verbs, secret names, carrier nouns and state settings. Refresh tokens/session cookies, a named `pending_item`, gzip archives/resulting strings, unconsumed queues, sampling percentages and maintenance windows do not consistently produce the required relationships. Labeling a field “redacted” is also not the same as establishing whether its value is a placeholder or an actual secret. The implementation has no general value-flow or safeguard-state model.
2. **Independent matching paths disagree about context and inspected fields.** [tool_poisoning.go](../../internal/checks/tool_poisoning.go) applies `SEC-011` separately to tool descriptions. Its broad exfiltration patterns can flag ordinary response formatting or prohibited secret transfer, while equivalent metadata fields lack that additional check. This explains the DNS-chunk detection and public-error false-alarm differences across fields.
3. **Negation and data context depend on narrow grammatical forms.** [directives.go](../../internal/detection/directives.go) primarily exempts complete clauses with particular leading refusal/query forms. “Keep rejectUnauthorized true and do not send credentials” is a refusal inside a longer clause, not the expected leading form; the literal disclosure rule still flags it. Quoted queries with an extra explanatory sentence, semantic “cannot override” rules and long coordinated refusals also fall outside recognized context handling.
4. **Authorization and outcome models require selected predicates.** [boundaries.go](../../internal/detection/boundaries.go) covers particular removal, identity and reporting relations. Supplying self-approval, changing default authorization to allow, disabling certificate checks and replacing a failure result with a success message are not reliably reduced to those relations. Adding wording examples alone cannot establish general semantic understanding.

These are source-based explanations of reproduced behavior, not proof that each family has only one responsible condition. The union of literal, intent, effect and tool-specific checks matters: making one path context-aware will not fix a false alarm if another path independently raises it.

## Decision and next acceptance criteria

The product currently works as a bounded inspection and review CLI. It fails this fresh test of reliably distinguishing hostile from benign supported metadata. Another security-acceptance all-clear is not supported by the results.

The next implementation should first unify field/context handling across security paths, then improve explicit value provenance, control-state/authorization effects and negation/quoted-data scope. Preserve these cases and the older labels unchanged; require both suites to pass, check both released execution routes and live discovery, then perform another freshly authored evaluation. A classifier result must remain separate from reviewed-reference integrity and host authorization. This audit implements no detector patch and makes no universal protection claim.

## Reproduction without installation

Point these variables at an existing released installation; paths below identify this audit's retained local artifact. The first two commands intentionally return exit 1 on 0.4.3 after preserving the failing observations.

```powershell
$env:MCPSENSE_TEST_RUNNER='C:\dev\MCPSense\bin\onboarding-043-1yLclr\fresh install with spaces\node_modules\mcpsense\bin\run.js'
$env:MCPSENSE_TEST_BINARY='C:\dev\MCPSense\bin\onboarding-043-1yLclr\fresh install with spaces\node_modules\mcpsense\runtime\mcpsense.wasm'
node scripts/product-use-audit.mjs
node scripts/product-use-live-audit.mjs
```

For native parity, clear `MCPSENSE_TEST_RUNNER` and set `MCPSENSE_TEST_BINARY` to an existing native binary on its supported operating system. This audit used the retained Linux public binary through `bin/release-043-public-go-shim.cjs`. No new installation is needed.

Raw evidence is retained under ignored `bin/`: `product-use-2026-10-31-npm/`, `product-use-2026-10-31-go/`, `product-use-2026-10-31-existing/`, `product-use-live-2026-10-31/`, `product-use-2026-10-31-fresh-gate/`, `product-use-2026-10-31-remediation.log`, their adjacent logs and the two maintainer-only orchestration helpers. The separate walkthrough cleans up its synthetic temporary project after recording its checks in the retained log. A first parity comparison incorrectly treated finding-array order as significant; the corrected comparison requires identical outcomes, exits, scores and sorted rule multisets without discarding duplicates. No product failure was inferred from the comparison-harness issue. User-owned `mission-progress.md` and `docs/study/` are untouched.
