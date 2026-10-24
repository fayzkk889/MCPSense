# Product retest — 24 October 2026

The product was tested through public installation, the actual unpublished release archive, beginner/expert workflows, live MCP peers and new description cases. Routine workflow success did not establish sufficient detection coverage: fresh examples exposed misses and false alarms that the older authored corpus did not reveal.

## Installation observations

| Route tested | Result | Scope |
| --- | --- | --- |
| Public `npm install mcpsense@latest` in an isolated Windows prefix | npm installed 0.3.0; invoking its wrapper exited 1 with executable startup failure | Windows Code Integrity event 3077 identified the executable and signing-policy rejection; policy ID `0283ac0f-fff1-49ae-ada1-8a933130cad6` |
| Actual unpublished Windows archive `0.4.0-SNAPSHOT-3d1c18b` through the current production npm installer | Installed and started with Go absent from PATH; all 14 installed-user assertions passed | Archive download was supplied from the exact CI artifact, not an unpublished public release URL. Corrupt upgrade rejection preserved the previous installation |
| Public `go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest` in isolated Linux/WSL GOBIN | Installed 0.3.0; version and help start successfully | Node/npm absent from the test PATH; not a native Windows Go-build test |

The current candidate's Windows executable remains unsigned. One successful hash/path/machine test does not predict another Windows device's decision. No protection settings were changed. The published npm startup failure remains a real user-facing blocker until an approved release is delivered and protected-device installation is retested. Public channels still distribute 0.3.0; pushing source does not update them.

## Fresh detection experiment

`testdata/product-retest-2026-10-24.json` was written before reading detector responses and committed before fixes. It contains 12 explicit hostile directives and 12 benign descriptions, each exercised through tool descriptions and server instructions. No advertised tool or attack was executed.

| Injection-check outcome | Original packaged candidate | Corrected source |
| --- | ---: | ---: |
| Hostile observations detected | 4 | 24 |
| Hostile observations missed | 20 | 0 |
| Benign observations flagged | 4 | 0 |
| Benign observations quiet | 20 | 24 |

These are **24 authored texts across two surfaces**, not 48 independent samples. Per surface, the original injection check detected 2/12 hostile descriptions and flagged 2/12 benign ones. One missed hostile tool description also received SEC-011; that separate warning did not constitute successful injection detection. After tuning, these examples are regression cases, not an independent estimate of general accuracy.

Observed gaps included environment-file and named-environment-variable disclosure, secret copying described in the third person, ignoring cancellation, concealed payment substitution, changing users after permission denial, unrelated destructive actions and cross-tenant disclosure. The false alarms involved literal training text and an instruction to treat tool responses as untrusted data.

The correction adds bounded lexical action/object/boundary relations and constrained benign context handling. It distinguishes nominal objects such as “the export” from a second action, preserves negated safety instructions, and detects malicious continuations after a benign prefix. Server instructions use the same untrusted-metadata context handling as descriptions; skills retain their separate literal screening policy. It does not supply general semantic understanding, runtime permission enforcement or a guarantee against unknown paraphrases.

An intermediate fix missed older permission-bypass regressions using “obtain ... via another tool” and “perform ... through an alternative tool.” The existing local product and hosted persona gates caught them. Final review preserves the broad permission relation and confines verb discrimination to negated safety instructions. No labels or older corpus expectations were relaxed.

## Other user workflows

- Actual packaged Windows beginner/expert tests: 44 invocations, with the existing 16 description cases all classified as expected.
- Actual packaged Windows live metadata tests: all 15 assertions passed, including modern/legacy negotiation, server instructions, SSE, pagination, authentication failure, rejected redirects, malformed data, wrong request IDs, repeated cursors and oversized responses. Logs confirmed no tool calls.
- Full product retest: 24 workflow assertions and the existing 164 authored descriptions, including secret redaction, nonexecution, JSON/SARIF agreement, before/after verification, input errors and baseline privacy.
- Dependency and metadata-baseline retests: 22 dependency CLI journeys, including four actual public OSV controls, plus 14 baseline assertions.
- Full Go tests and vet; context-escape and negation regression tests; hosted native Windows/Linux Go 1.22/1.27 checks, race tests, installers and unpublished release packaging must pass on the final source.

Receipts with binary and fixture hashes are retained under ignored `bin/product-retest-2026-10-24/`. `public-install-result.json` and `windows-policy-evidence.json` record the public Windows failure; `installation/installation-summary.json` records the no-Go candidate installation; `fresh-original/` and `fresh-fixed/` retain the before/after experiment.

## Release decision

Routine CLI flows pass, and the observed detection defects have regression coverage. This is still a bounded inspection tool. Runtime tool results, fetched resource bodies, general semantics, effective authorization/session isolation and server resource enforcement remain unassessed. The observed public Windows startup failure and pending signing onboarding keep public publication on hold. No tag, public release or npm publication was performed for this test.
