# Test report — 22 October 2026, audit session

## Environment and constraints

Windows/amd64, PowerShell, Go 1.27.3; module requires Go 1.22. Repository HEAD `9c19c629fe2704a0094944397a090152ebd2e3ac`. `GOPROXY=off` and `GOTOOLCHAIN=local` were set in test command processes to prevent dependency/toolchain downloads. Go still printed “downloading” before failing cache access; no successful installation occurred. Existing user files and MIT license unchanged.

## Exact baseline commands and results

| Command | Observed result |
| --- | --- |
| `go mod verify` | Failed: github.com/fatih/color@v1.18.0 lookup disabled by GOPROXY=off |
| `go test ./... -count=1 -cover` | Failed setup for cmd/checks/detection/report/scanner: missing fatih/color and testify; denied cache directory/lock access. cve/drift/models/utils reported 0.0% with no tests. This is not repository-wide coverage |
| `go test -race ./...` | Failed same dependency setup; four dependency-free packages reported no test files. Race safety not established |
| `go vet ./...` | Failed dependency/cache access; static analysis not completed |
| `go build -o bin/audit-mcpsense.exe ./cmd/mcpsense` | Failed dependency/cache access; CLI executable not built |
| `go run ./docs/engineering/repro` | Completed exit 0 using repository production packages and standard library; defect observations below |
| `gofmt -w docs/engineering/repro/main.go` | Completed; audit harness only |
| `& 'C:\Program Files\Git\bin\bash.exe' docs/engineering/repro/action-audit.sh` | Bash failed startup with NtCreateDirectoryObject access denied. Action shell proof NOT executed |
| `gh release list --limit 3 --repo fayzkk889/MCPSense` | GitHub API connection failed; public release listing separately read through web research tool |

No successful full suite run is claimed. GoReleaser and golangci-lint were not found by command discovery; gcc and gh were found. No installer, Makefile install/clean target, npm lifecycle or release hook was executed. The Makefile test target is Go tests with coverage; lint requires golangci-lint. Full baseline and minimum-version CI remain pending.

## Reproduction evidence

Harness uses an in-memory HTTP RoundTripper, synthetic secret, and temporary directory. The `.invalid` URL is intercepted before networking. No real server commands or exploit strings are executed. The harmless `exec.Command` fixture is read as source text only. The harness prints observations, not formal regression assertions; it is audit evidence to turn into package tests during implementation.

```text
snapshot_contains_synthetic_secret=true env_value_retained=false
normal_JSON_drift_contains_secret=true
DisableCVE_live_HTTP_calls=4 live_error=<nil> report_returned=true
mixed_directory_auto_mode=skill auto_SEC002=false static_SEC002=true
unknown_rule_score=100 unknown_rule_findings=0
saved_baseline_contains_secret=true
action_score_regex_extract="\"score\":" action_severity_regex_matches=false
unicode_casefold_panicked=true
```

The JSON drift reproduction marshals the same exported Finding fields serialized by JSONReporter; full CLI rendering is blocked. Offline is reproduced at the scanner option boundary and linked to CLI by inspected source, not an executed CLI invocation. Four 503/error responses produce nil error and a report; this does not claim that all such reports score 100. The Unicode panic is recovered inside the harness solely to record evidence.

The Action's score regex accepts an empty numeric suffix, extracts only the key/colon from formatted JSON, then defaults an empty field to zero. Its compact severity regex does not match indented output. Go regex check reproduces those expressions; full Bash/Actions semantics, injection execution and threshold integration remain unexecuted. Source confirms direct interpolation and missing-results pass branches.

## Coverage, invariants and remaining gates

No valid overall coverage, benchmark precision/recall, performance measurements or cross-platform test results are available. No >=40-fixture independent benchmark was created during this audit session. Existing tests do not cover drift/CVE/models/utils; full tests in the other packages could not run.

Observed violated invariants: synthetic secrets persist in baseline and ordinary drift JSON; required live discovery failure is not propagated; selected unknown rule can yield clean score; mixed auto coverage misses source; Unicode descriptions can panic. Offline policy violation is supported by source trace plus option-boundary reproduction. Full Action failure/injection risks are source-confirmed but runner reproduction remains pending.

Not verified: no-network CLI guarantee, subprocess opt-in/descendant cancellation, Unix permissions or Windows ACLs, SARIF schema compliance, JSON/SARIF same-scan consistency, SSRF redirect handling, bounded memory, stable fingerprints, remediation verification, Go 1.22, WSL, Linux/macOS runtimes and five release build targets. No release artifacts prepared or published. All production fixes and regression tests are deferred under the mission's first-session restriction.

## Implementation validation — 22 October 2026

The first-session failures above are historical observations, not the current dependency baseline. The user subsequently verified `go mod download`, `go mod verify`, full tests/race/vet, coverage, build and help on original Windows HEAD 9c19c62. User-measured baseline coverage: detection 74.5%, checks 29.4%, scanner 28.6%, report 24.8%, drift/cve/models 0%. Those were user-executed commands.

### Agent-executed checks

- Original Unicode regression failed with the expected slice-bounds panic before the fix. Original snapshot, report, HTTP-error, stdio EOF, offline/rule policy, malformed discovered input, missing second config, Action injection and JSON-extraction defects were reproduced before/alongside their changes.
- `go test ./... -count=1 -cover`, `go test -race ./...`, `go vet ./...`, `go mod verify`: all passed in an elevated Windows implementation-checkpoint run. Later Windows builds intermittently hit Application Control; a final rerun stopped before race/vet after several generated test binaries were blocked. These are separate outcomes, not a claimed final native pass.
- Official Go 1.22.12 Linux archive downloaded and verified against go.dev SHA-256 `4fa4f869b0f7fc6bb1eb2660e74657fbf04cdd290b5aef905585c86051b34d43`. With this toolchain and isolated ignored-bin caches: `go test ./... -count=1 -cover`, `go vet ./...`, `go mod verify`, `go build -o bin/mcpsense-linux ./cmd/mcpsense` and the demo script all passed natively under Ubuntu WSL on the completed implementation.
- `node --test scripts/action.test.mjs npm/package.test.cjs`: seven offline unit tests passed; the additional real-binary wrapper test is intentionally skipped unless MCPSENSE_TEST_BINARY is supplied by CI. `npm pack ./npm --dry-run --json --ignore-scripts --cache ./bin/npm-cache` confirmed wrapper, installer, README, MIT license and package metadata are included. No package was published.
- The first packaging test inadvertently imported the unguarded original installer, triggering a failed v0.3.0 install attempt. No install succeeded. The installer now has a require.main guard and tests perform no installation/network access.
- Real GitHub CI passed Linux/Windows on both Go 1.22 and 1.27, lint and the Action exercise for first pushed commit 57cc2cc: [initial PR run](https://github.com/fayzkk889/MCPSense/actions/runs/39768680248). Later branch updates rerun these checks and add npm wrapper smoke, SARIF upload validation and publication-disabled release snapshots; consult [current PR checks](https://github.com/fayzkk889/MCPSense/pull/3/checks) for exact latest status.
- Official GoReleaser 2.18.3 Linux archive verified against its release checksum manifest. `goreleaser check` passed. `goreleaser release --snapshot --skip=publish,announce,sign,sbom --timeout=10m` succeeded for all five targets; `(cd dist && sha256sum -c checksums.txt)` passed all five archive records. Linux CLI startup and offline demo passed. No publisher or signing step ran. The final fresh CI snapshot uses Go 1.27.3 and an explicit candidate tag override, without creating a Git tag.

### Measured Linux package coverage

At the completed-implementation local run: cmd 55.7%, checks 29.2%, cve 47.5%, detection 100.0%, drift 67.0%, models 56.9%, report 88.4%, scanner 75.6%, utils 34.6%. Statement coverage is not detection accuracy or security completeness. Minor subsequent help/test/packaging edits are validated by hosted CI; do not assume a new exact coverage percentage without reading its output.

### Detection diagnostic

`go test ./internal/detection -run TestDescriptionCorpus -v -count=1` ran 40 authored, semantically labelled descriptions: 20 injection and 20 benign. TP=17, FP=5, TN=15, FN=3; precision=0.7727, recall=0.8500. One measured Windows run took 3.1882ms for classification. False positives: n06–n10 (quotation, defensive and legitimate security text). Misses: p16–p18 (semantic instructions without existing triggers). Labels were retained after measurement; no threshold was invented to make the test pass. This is a small local corpus, not an external independent benchmark or representative real-world accuracy estimate.

### Invariants supported by tests

- Original Unicode offsets/text and line locations remain valid; arbitrary-text fuzz seeds run.
- Synthetic raw secrets are absent from minimized saved snapshots and ordinary CLI/JSON/SARIF output; legacy/future snapshots are explicitly rejected.
- Offline live requests and unapproved local execution are rejected before network/process activity; unknown rule IDs cannot silently select no checks.
- Malformed/error/oversized live responses and failed required listings fail; bounded pagination detects repeated cursors.
- Modern request metadata/headers/result types, JSON/SSE framing and controlled legacy fallback are exercised.
- Private destinations require permission, metadata/link-local addresses stay blocked, and redirects are not followed (local-only integration fixture).
- Authorized silent subprocesses time out and are cleaned up. Process-tree containment against malicious escape is not established.
- Mixed projects include source and skills; multiple config files contribute entries; malformed discovered candidates fail.
- Action metacharacters remain literal argv values; invalid/inconsistent/missing results and execution errors fail even with fail-on none. JSON/SARIF derive from one scan.
- Equivalent complete reports correlate stable rule/component groups; incomplete or changed policy/input inventories cannot resolve findings.
- Synthetic before/after demo returned state completed, one resolved group, no new or persistent groups. This is observational verification, not exploit prevention proof.

### Remaining gates and limits

Inspect the exact final PR CI run and snapshot artifact before publication. macOS and arm64 were built, not runtime-tested locally. Local Ubuntu has no C compiler, so Linux race validation relies on hosted CI. Actual registry installation of unpublished 0.4.0, signing, website deployment and public release verification remain outside this approved preparation step. Detailed compatibility and residual risks are in release-readiness.md.

Final review corrections: exact numeric JSON constraints now use json.Number when hashing schemas, preventing large integer changes from being rounded away. Unicode matching now maps normalized boundaries back to original bytes and retains historical dotted-I lowercasing behavior; all detection tests and the corpus pass (same confusion counts, 1.6098ms in the final focused Windows run). Baseline provenance is part of coverage, so accepting/replacing an approved baseline cannot be mistaken for remediation. Focused regression tests for all three cases passed.
