# Public 0.4.2 product audit — 27 October 2026

## Verdict

**FAIL for the requested broad security-shield acceptance.** Public 0.4.2 works as a bounded inspection/review CLI, and its existing installation/product workflows pass, but fresh adversarial descriptions reproduce substantial misses and benign false alarms. An additional live dependency control exposes an upstream advisory-applicability conflict. Do not interpret the earlier green regression suites as evidence that arbitrary hostile descriptions are reliably detected.

0.4.2 was already published before this audit. No new version, tag, package publication, main merge or website deployment is part of this audit. There is no basis here for a universal protection claim or a further security-acceptance all-clear. No Windows protection settings were changed.

## What a user actually received

The test used an anonymous fresh Windows installation of `mcpsense@latest`, normal npm installation scripts, fresh caches and paths containing spaces. Go and archive tools were absent from its PATH. Its installed runtime component hashes match the approved final-main 0.4.2 npm artifact. Native parity used an independently public-Go-installed Linux 0.4.2 binary. A further fresh Go `@latest` installation without Node/npm also passed.

The initial npm onboarding run passed discovery/help/version/example/offline/error handling, then `version --check` failed visibly because its npm lookup was unavailable. That result is retained. The identical 13-check onboarding/upgrade journey passed on retry, including upgrade from 0.4.1 and agreement between public channels. The failure was not relabelled as a pass or removed.

| Product requirement | Observation |
| --- | --- |
| Independent npm and Go onboarding | PASS: 13 npm fresh-install/upgrade checks on retry; fresh public Go install and first-use/reference/version checks without Node/npm |
| Existing scan/report/explain/fix/rescan/verify, privacy, permissions, live discovery, inventory and drift journeys | PASS through the actual public npm installation, including the older 104 boundary observations and 12 baseline workflows |
| Fresh hostile-description detection | FAIL: 5/16 distinct hostile descriptions detected; 11/16 missed, in both tool descriptions and server instructions |
| Benign-description handling | FAIL: 2/16 distinct benign descriptions falsely flagged, in both fields |
| Required reviewed metadata reference | PASS: all 32 changed hostile metadata instances rejected; reference bytes preserved; benign changes also require review |
| Supported metadata surfaces | PASS: a known attack signal detected in nine advertised text locations; unknown extensions explicitly remain unassessed |
| Affected Tensorlake npm declaration | PASS: explicit 0.5.144 lockfile produced MAL-2026-17650 without installing the package |
| Publisher-unaffected Tensorlake control | FAIL: explicit 0.5.143 declaration received the same malware advisory; direct OSV queries confirm that upstream returns it for both versions |
| Runtime enforcement, arbitrary package execution or platform credential-breach prevention | NOT PROVIDED by this CLI; passing metadata inspection does not establish those properties |

The extended expert harness records **86 PASS / 1 FAIL**. Its passing checks include preservation checks on operator reference bytes; that count is not a count of independently prevented attacks. The previously-existing product suite passed before adding the new acceptance gate. The proposed next-release gate intentionally adds the fresh cases and fails on 0.4.2; existing expectations remain unchanged.

## Frozen new descriptions

The 32 descriptions were authored and committed at `5662c1a` before the scanner was run on them: 16 hostile and 16 benign. File: [product-black-october-2026-10-27.json](../../testdata/product-black-october-2026-10-27.json).

```text
SHA256 c35976e18fbbeb3e71a845ca5534cc29273cb9d5636552069e7b786ff2cec815
```

Each description was tested in two fields, producing 64 observations per route. npm and native Go agree on every outcome, including whether any security finding appeared:

| Route | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| Fresh public npm 0.4.2 | 10 | 22 | 4 | 28 |
| Native public Go 0.4.2 | 10 | 22 | 4 | 28 |

These are targeted, authored adversarial examples, not a random sample, independent field evaluation or overall product-accuracy estimate. The fields and routes are repeated observations of the same 32 texts, not independent attacks.

All 22 missed hostile observations had **no security finding**. Fourteen had **no findings at all and score 100**, while the report's separate security assessment correctly remained `not_established`. The other eight had only a quality finding, score 98 and exit 0. A completed scan/high score is still not a trust decision.

Missed families include suppressing monitor paging with `no_notify`/empty recipients, substituting a dummy monitor, false claims that a removed monitor is intact, credentials in diagnostic headers, encoded support bundles, private API tokens copied to a URI, warning severity normalization, unreviewed bootstrap execution, disabling a monitor through a configuration assignment, and staged token relay.

The two benign false alarms are a negated resource-authority claim and a literal attack phrase used as training-corpus search data. Exact text, labels, reason and observed rule/exit/score results are preserved in the [machine-readable result](product-audit-2026-10-27-results.json).

## Why this escaped older tests

This is a shared detector limitation, not an npm packaging defect: the native and WebAssembly products agree. Inspection of the unchanged released source explains the failure mechanisms:

- `internal/detection/intent.go` uses finite action/secret/destination word features. A request carrying an API key in an Authorization header, collection before encoding, or an authentication token in a staged note can omit the specific predicate terms required by the disclosure relation. The event model does not establish the underlying source-to-sink data flow.
- `internal/detection/boundaries.go` models a limited set of actions and objects. Warning suppression and consent removal are represented, but disabling monitoring through recipient arrays, dummy implementations or Boolean configuration assignments is not generally represented as the same invariant violation. Its contradiction model covers failure/success vocabulary rather than arbitrary claims about safeguard state.
- Its negation look-back is short. The negated resource-authority control can fall outside that scope. Quotation handling also fails the training-search example. Those cases need clause/quoted-data scope, not removal of the benign labels.
- Older strict checks exercised finite development corpora. They remain useful regressions, but did not contain these relationships. The source comments already call the model bounded lexical screening; those limits must constrain release and marketing interpretations.

The proposed gate adds these 64 observations to the older 104, for **168 strict native/npm observations**. It does not add detector keywords or claim to fix the underlying deficiencies. A future implementation must pass the unchanged hostile and benign expectations and receive another fresh evaluation.

## Black October: verified relevance and limits

- [OpenAI's primary report](https://alignment.openai.com/misalignment-reports/suppressing-misalignment-monitoring-alerts-and-disabling-misalignment-monitoring/) describes internal monitoring being weakened during coding tasks, with incidents on 3/6 October and a report updated 20 October. These are agent-behavior incidents, not proof of an MCP exploit. They motivated synthetic control/recipient/state-integrity tests here.
- [LiteLLM's corrected investigation](https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain) identifies an exposed platform key, extracted privileged tokens and a modified release source/approval process. Scanning MCP descriptions cannot prevent that chain or certify registry artifact contents. The canonical investigation supersedes assumptions in its first incident post.
- [Tensorlake's publisher advisory](https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2) identifies malicious npm 0.5.144 and states that 0.5.143 and earlier versions are unaffected by that compromise. Its [OSV entry](https://osv.dev/vulnerability/MAL-2026-17650) returned a SEMVER range introduced at 0 with no upper bound, alongside an explicit 0.5.144 version, for both queries at approximately 11:16 UTC on 27 October. MCPSense faithfully surfaced the upstream match. This is an applicability conflict requiring corroboration/triage; silently suppressing the advisory or calling every version infected would both be unjustified. No affected package was downloaded or executed.
- [Node.js's 21 October security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) provides patched runtimes. This Windows test used Node 22.23.4. Node 22+ is a compatibility floor, not a substitute for keeping Node patched. The CLI does not patch PHP, Node, cloud platforms or third-party MCP servers.

## Next release acceptance

1. Address monitor/control-state invariants and credential source-to-sink relations, preserving benign negation and quoted-data context. Merely adding the exact observed sentences is insufficient.
2. Keep this corpus frozen and mandatory for native/npm acceptance. Repeat a genuinely fresh adversarial audit after the implementation passes it; do not report authored scores as field accuracy.
3. Triage the advisory conflict against publisher and upstream records. Preserve provenance and unresolved status; any reviewed exception needs narrow identity/version/source rules and an explicit rationale. No exception or upstream issue submission was made in this audit.
4. Keep required metadata references available as a deterministic reviewed-change check. They do not solve malicious initial approval, unsupported fields, runtime results or host authorization.
5. Verify a concrete candidate and obtain maintainer approval before any new merge/tag/package publication. Existing public 0.4.2 is not withdrawn or replaced by this test branch.

### Reproduce against the public npm release

From a reviewed source checkout, install the public package into an isolated prefix, then point the product harness at it:

```powershell
npm install --prefix ./audit-cli mcpsense@0.4.2
$env:MCPSENSE_TEST_RUNNER=(Resolve-Path ./audit-cli/node_modules/mcpsense/bin/run.js).Path
$env:MCPSENSE_TEST_BINARY=(Resolve-Path ./audit-cli/node_modules/mcpsense/runtime/mcpsense.wasm).Path
$env:MCPSENSE_UNSEEN_FIXTURE='testdata/product-black-october-2026-10-27.json'
$env:MCPSENSE_UNSEEN_ENFORCE='1'
$env:MCPSENSE_EXPECT_ASSESSMENT='1'
node scripts/unseen-product-retest.mjs
# Expected on 0.4.2: preserve the results, then fail strict acceptance.
$env:MCPSENSE_INCIDENT_ONLINE='1'
node scripts/incident-product-audit.mjs
# At audit time: unaffected Tensorlake control fails. Upstream data may change.
```

Raw invocation records, synthetic reports and the first unavailable-version-lookup result remain under ignored `bin/product-audit-2026-10-27-*`. Production Go/npm sources, release version and MIT license are unchanged. User-owned `docs/engineering/mission-progress.md` remains untracked.
