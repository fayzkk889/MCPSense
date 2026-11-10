# Security research validation — 2026-11-10

Implementation: `e6e3098` (JSON boundary), `b0a3f12` (vendor evidence and final
security journeys), based on main `8861c5c`. Review:
[PR #32](https://github.com/fayzkk889/MCPSense/pull/32).
The 0.5.0 candidate remains unpublished. Publication and merging are not part of
this research/build step.

## Actual before/after results

| Synthetic user scenario | Before | Combined candidate |
| --- | --- | --- |
| Canonical hostile `description` | Exit 1, two SEC-001 findings, completed inspection | Same findings and exit |
| Same description followed by benign `Description` | Exit 0, no SEC-001, completed inspection | Exit 2, ambiguous JSON error; no completed report |
| Duplicate `description` members | Accepted with last-member interpretation | Exit 2, duplicate-member error |
| JSON-RPC `Method: ping` | Successful result | Invalid-request error `-32600`; subsequent canonical requests still work |
| Affected AWS API package with successful empty advisory feed | No vendor warning (regression test failed before rebuild) | One reviewed advisory; source, audience settings and deployment conditions retained |
| Fixed or below-introduced AWS API version | No advisory | No supplemental match |
| AWS Serverless package before 0.2.1 / fixed 0.2.1 | Empty public feed observed for 0.2.0 | Reviewed traversal warning / no supplemental match, respectively |
| Unknown/pre-release vendor version | Summary-only uncertainty in older supplement | Machine-readable `version_unresolved` and `unresolved_applicability`; retained advisory candidate |

Malformed metadata is not called proven malicious; inspection stops visibly.
The serverless advisory retains the publisher's medium severity. CLI exit 0 can
coexist with medium findings under the existing high/critical exit threshold;
the report still requires review and does not assert enforced authorization.

## Completed validation

- The combined candidate's full npm product suite passed, including beginner,
  expert, baseline, verification, dependency and live journeys. All 164 core
  labelled cases had zero false positives/negatives on those frozen fixtures.
  The 232 frozen boundary observations, 486 additional metadata observations
  and 12 live trust-boundary cases also passed. Labels and fixture bytes were
  unchanged; these are finite test results, not a universal accuracy claim.
- Hosted [CI run 42835121204](https://github.com/fayzkk889/MCPSense/actions/runs/42835121204)
  passed all 14 jobs for implementation head `b0a3f12`: native Windows/Linux
  on Go 1.22/1.27; npm Windows/Linux/macOS on Node 22/24; vulnerability audit,
  lint, action and release dry run. Official SDK interoperability runs in the
  designated Ubuntu/Node 22 job; it is intentionally skipped in the other
  matrix jobs.
- Go 1.22: `go test ./... -count=1`, `go test -race ./...`, `go vet ./...` passed
  using the existing Linux toolchain. Windows Application Control blocks the
  local native test toolchain; protection was not disabled. Hosted Windows checks
  provide the Windows native validation.
- The local Windows Node test group had 30 passes, zero failures and one
  pre-existing skip: symlink-command preservation requires a symlink privilege
  unavailable to that process. The hosted Unix matrix exercises that path.
- Identical new attack/advisory user journeys passed on native Linux and the
  Windows npm runtime: canonical hostility, field shadowing, duplicates,
  embedded manifests, client configs, legitimate case-sensitive schema names,
  incoming protocol/argument errors, recovery after errors, affected/fixed/unknown
  package versions and offline behavior.
- Synthetic live discovery confirmed zero peer tool calls, zero external schema
  requests, zero redirect-destination requests for 307/308, visible failure on
  oversized success/error responses, and no private-endpoint contact without an
  explicit grant. Unit tests additionally cover legacy/modern and JSON/SSE framing.
- Parser fuzzing passed: 20 seconds, two workers, **903,815 executions**, 133 new
  interesting inputs, no failure. This is a bounded robustness check, not an
  exhaustive proof.
- Official MCP SDK clients **1.32.2** (legacy) and **2.4.0** (modern) connected,
  listed tools/resources and detected hostile metadata with the combined engine.
- A locally packed npm candidate installed offline in an isolated prefix with
  no Go/archive tools/install scripts; installed user journeys passed.
- Artifact checksums, shared version and Go/runtime/MIT license verification
  passed. `LICENSE`, dependency manifests, package version and `testdata/` were
  unchanged from base.

## Reproducibility

New persisted regression suites:

```text
go test ./internal/jsonpolicy ./internal/scanner ./internal/mcpserver ./internal/checks
go test ./internal/jsonpolicy -run=^$ -fuzz=FuzzUnmarshal -fuzztime=20s -parallel=2
node --test scripts/security-boundary.test.cjs scripts/advisory-boundary.test.cjs
node scripts/npm-product-suite.cjs
node scripts/npm-wasm-smoke.cjs
node scripts/mcp-sdk-interop.cjs
node scripts/release-verify.mjs --npm
```

For native journeys set `MCPSENSE_TEST_BINARY` to the built executable. For npm
journeys also set `MCPSENSE_TEST_RUNNER` to the absolute `npm/bin/run.js` path.
SDK interop uses the isolated development SDK fixture described in its script.
No public release check is claimed for the unpublished candidate.

Local raw evidence is under ignored `bin/security-parser-repro/`,
`bin/security-advisory-before.log`, `bin/security-advisory-feed-2026-11-10.json`,
`bin/security-install-final.log` and `bin/security-product-final.log`.
The committed test fixtures are synthetic and replayable; local evidence is not
an authenticated production attestation.

Candidate WASM SHA-256:
`b7350afb3648aab15e4e49d19c3b9698076ae135e2a5a8d9e82625b0c8fda06e`.
Detector profile for that runtime:
`e3041babfba6a469ceecf6d8959dff299190faacbf8813cac0e6604fa4ec8fb8`.
Native/profile identities may differ by Go/Node runtime; compare only equivalent
completed coverage.
