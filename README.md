# MCPSense

MIT-licensed local security inspection for MCP configurations, source code, agent instructions, and advertised server metadata. Findings are review signals; metadata alone cannot prove exploitability or absence of compromise.

[![CI](https://img.shields.io/github/actions/workflow/status/fayzkk889/MCPSense/ci.yml?branch=main)](https://github.com/fayzkk889/MCPSense/actions)
[![Go](https://img.shields.io/badge/go-1.22%2B-blue)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

This branch prepares **0.4.0**. It has not been released. Public v0.3.0 does not include these fixes; build this reviewed branch to use the behavior below. Publication, release tags, and merging require maintainer approval.

## Start safely

From this checkout, with Go 1.22 or newer:

```sh
go run ./cmd/mcpsense scan ./testdata/compliant_server/manifest.json --offline --no-baseline
```

Build for repeated use:

```sh
# Linux/macOS
go build -o bin/mcpsense ./cmd/mcpsense
./bin/mcpsense scan ./manifest.json --offline --no-baseline
```

```powershell
# Windows
go build -o bin/mcpsense.exe ./cmd/mcpsense
.\bin\mcpsense.exe scan .\manifest.json --offline --no-baseline
```

After publication, installation remains available through `go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest`, GitHub release archives, and the npm wrapper. npm on Windows builds the selected release from source and requires Go. Linux/macOS npm installation verifies the archive against the release checksum file. Checksums detect corruption; no artifact-signing claim is made here.

## Scope and permissions

| Selection | Behavior |
| --- | --- |
| Auto directory | Reads supported source, recognized MCP JSON/configs, and skill files together |
| `--mode static` | Source analysis plus recognized manifests/configs; no skill traversal |
| `--mode manifest` | Reads one MCP manifest |
| `--mode config` | Reads `mcpServers` or `servers` configuration entries |
| `--mode skill` | Reads agent instructions such as AGENTS.md, CLAUDE.md, SKILL.md and supported client rule paths |
| `--mode live` | Enumerates metadata at the explicitly selected endpoint or authorized local process |

A directory scan does not start configured MCP commands or contact configured server URLs. Advisory lookups are a separate network operation enabled by default for recognized package references. Use `--offline` for no scanner networking; it also prohibits all live scans and local server execution. `--no-cve` disables advisory lookups only.

Multiple configs with distinct server names are included. Ambiguous duplicate names or multiple manifests require separate explicit scans; they fail instead of silently omitting a component. Unreadable/malformed discovered inputs and exceeded limits fail the scan. Dependency/build directories are excluded. Supported source extensions are `.go`, `.py`, `.ts`, and `.js`; this is not complete language or dependency coverage.

Input files must be regular non-symlink files, at most 4 MiB. Source, skill, and config discovery each have a 64 MiB phase budget and a 10,000-input cap. These checks are not filesystem isolation against concurrent local path replacement.

## Live metadata discovery

```sh
# Public endpoint: no tool calls, OAuth browser launch or mutating probes
mcpsense scan https://your-authorized-server.example/mcp --mode live --no-baseline

# Explicit local endpoint permission
mcpsense scan http://127.0.0.1:8080/mcp --mode live --allow-private-network --no-baseline

# Local startup executes server code; review it before opting in
mcpsense scan /absolute/path/to/server --mode live --allow-exec --server-arg=--stdio --no-baseline
```

Modern `2026-07-28` discovery sends `server/discover`, per-request metadata and matching HTTP headers, then capability-gated lists. Legacy `initialize` behavior is retained. `--protocol auto` falls back only on recognized incompatibility; `--protocol legacy` is available for reviewed legacy peers that return ambiguous errors. Request-scoped JSON and SSE responses, bounded pagination, and stdio metadata discovery are supported. Deprecated standalone HTTP+SSE GET/endpoint-event transport and OAuth authentication are not implemented. Protected endpoints fail clearly; this client does not bypass authentication.

Redirects and URL userinfo/fragments are rejected. DNS addresses are validated and dialed directly. Loopback/private access requires `--allow-private-network`; link-local, metadata and reserved ranges remain blocked. Live requests do not use environment proxies. Responses are capped at 2 MiB, catalogs at 64 pages per primitive and 50,000 total items, with bounded request/session timeouts. Scanner cancellation terminates the selected process with best-effort process-tree cleanup. A local server can still access the developer's files and environment; `--allow-exec` is not a sandbox.

`--probe` now fails explicitly because active probes were never implemented.

## Findings and reports

There are 32 registered checks: 5 manifest/spec checks, 16 security heuristics, 3 skill checks, 1 advisory check, and 7 quality checks. Seven additional drift IDs are emitted during baseline comparison. Registry counts are not security-coverage guarantees.

Checks include prompt-injection patterns, suspicious execution/URL/file-access patterns, Unicode and cross-tool poisoning signals, annotation inconsistencies, credential exposure, package references, schemas and tool quality. A shell metacharacter or changed annotation alone does not prove command execution or permission escalation. OWASP mappings are advisory classifications.

```sh
# One scan, consistent JSON and SARIF including drift findings
mcpsense scan ./manifest.json --offline --no-baseline --format json --output report.json --sarif-output report.sarif

# Rule filters are validated; unknown IDs and conflicting filters fail
mcpsense scan ./manifest.json --offline --no-baseline --checks SEC-001,SPEC-002
```

JSON schema 2 includes coverage, selected/skipped checks, advisory state, input identities, target identity, severity filter, confidence and stable rule/component fingerprints. Multiple occurrences of one rule in one component share an identity. SARIF carries the same fingerprints and coverage. Local metadata findings retain their actual input file; no line number is invented. GitHub Code Scanning requires physical source locations, so purely live logical findings may require sarif-upload: false and separate JSON/SARIF review. `needs_review` describes heuristics; `advisory_match` describes database matches. Neither means exploitation was verified.

A score starts at 100 and subtracts severity weights for reported findings. Filtering affects the score. A zero finding count or score 100 does not establish overall security. Advisory lookup failure or stale-only fallback fails the requested scan; `--no-cve` explicitly records that this phase was skipped. Package extraction is heuristic, not a resolved dependency inventory.

Exit codes: **0** completed without reported high/critical findings, **1** completed with those findings, **2** execution/configuration/policy failure. This changes the old conflated error status.

## Baselines and privacy

Manifest/config/live scans and directory scans with metadata save a baseline by default under `~/.mcpsense/snapshots/`. `--baseline` selects a file; `--no-baseline` disables this behavior; `--update-baseline` explicitly accepts reviewed changes.

Snapshots are capped at 4 MiB; oversized saves fail, and verification accepts regular report files up to 16 MiB. Format 2 stores digests and minimal booleans instead of raw tool descriptions, commands, arguments, target URLs, resource names or environment values. Environment values are excluded even from the config digest. Raw before/after text is not exported; `--show-diff` is a compatibility flag. Digests support change comparison, not encryption: low-entropy values may still be guessable. Do not commit private baselines without review.

Old plaintext baselines and unknown future formats fail with a recreation instruction. Review the target, recreate with `--update-baseline`, and separately review/remove old sensitive copies under your own retention policy. They are not silently rewritten or deleted. Writes use a temporary file with restrictive requested permissions before replacement; Windows ACLs depend on the containing directory.

Reports remove raw diffs and redact recognized credentials, URL credentials/query values, and known configuration argument/environment values. Redaction is best effort for arbitrary text, not a guarantee that every possible secret format can be recognized. Review artifacts before sharing them.

## Verify a remediation

```sh
mcpsense verify before.json after.json
```

Verification is offline and requires completed, equivalent schema-2 scans: same target, mode, input inventory, protocol, selected checks, advisory/baseline policy, approved-baseline digest and severity filter. Changed or incomplete coverage remains unverified. `resolved` means a rule/component group was no longer detected in that equivalent scope; it does not prove exploit prevention or authenticity of unsigned report files.

See the [reproducible before/after demonstration](docs/engineering/remediation-demo.md), [test report](docs/engineering/test-report.md), and [release readiness](docs/engineering/release-readiness.md).

## GitHub Action

Until 0.4.0 is approved, pin a reviewed commit from the feature branch. The snippet intentionally uses the branch for development; pin its final SHA for production.

```yaml
permissions:
  contents: read
  security-events: write # only needed when uploading SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - uses: fayzkk889/MCPSense@codex/security-evidence-hardening
        with:
          target: ./manifest.json
          version: source
          offline: 'true'
          sarif-upload: 'true'
          fail-on: high
```

The Action builds its trusted source revision by default, or downloads a selected release and verifies its checksum. Published binaries must support schema 2 and these exit codes; older versions fail validation. Acquisition/building may need networking even when the scanner's `offline` input is true.

Inputs: `target` (required), `mode` (auto), `severity` (low), `fail-on` (high), `sarif-upload` (true), `no-cve` (false), `offline` (false), `baseline` (empty), `version` (source). There is no Action `format` input. Without an explicit baseline the Action skips baseline writes. It always renders JSON and SARIF from one scan, parses results structurally, and never treats `fail-on: none` as permission to ignore execution failure. SARIF upload failures fail the job. Outputs: `score`, `findings-count`, `sarif-file`.

## Contributing and limits

Run `go test ./... -count=1`, `go test -race ./...`, `go vet ./...`, and `node --test scripts/action.test.mjs npm/package.test.cjs`. CI tests Linux/Windows with Go 1.22 and 1.27. GoReleaser builds Linux amd64/arm64, macOS amd64/arm64 and Windows amd64. Cross-compilation alone does not demonstrate runtime correctness.

The [40-description diagnostic corpus](testdata/description_benchmark.json) includes benign security documentation and semantic attacks. Observed precision was 0.7727 and recall 0.8500, with five false positives and three misses. It is a small authored corpus, not an independent field evaluation; detection percentages and statement coverage are not security guarantees.

See [baseline audit](docs/engineering/repository-audit.md), [security research](docs/research/2026-10-security-landscape.md), and [commercial hypothesis](docs/research/commercial-validation.md) for evidence and remaining uncertainty. No hosted service, payment system, exploit verification or incident-response claim is included. MIT remains unchanged.
