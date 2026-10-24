# MCPSense

MIT-licensed local security inspection for MCP configurations, source code, agent instructions, and advertised server metadata. Findings are review signals; metadata alone cannot prove exploitability or absence of compromise.

[![CI](https://img.shields.io/github/actions/workflow/status/fayzkk889/MCPSense/ci.yml?branch=main)](https://github.com/fayzkk889/MCPSense/actions)
[![Go](https://img.shields.io/badge/go-1.22%2B-blue)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![npm latest](https://img.shields.io/npm/v/mcpsense?label=npm%20latest)](https://www.npmjs.com/package/mcpsense)
[![GitHub release](https://img.shields.io/github/v/release/fayzkk889/MCPSense?label=GitHub%20release)](https://github.com/fayzkk889/MCPSense/releases/latest)

This checkout describes the **0.4.0 candidate**. The linked npm/GitHub badges show the published versions; changes on main are delivered by package commands only after a release is published. Run `mcpsense version` after installing. The candidate also supports `mcpsense version --check` to compare both public channels explicitly; older versions may not have that flag.

**Release readiness:** the [beginner/expert retest](docs/engineering/persona-retest-2026-10-23.md) exposed first-run gaps, missed attack paraphrases, unexamined metadata fields and source-analysis false alarms. Follow-up fixes and their measured limits are tracked in the [release-blocker report](docs/engineering/release-blockers-2026-10-23.md). Earlier corpus scores do not establish general detection reliability. Public installation receives these changes only after publication.

## Start safely

Choose one installation route for a published release:

```sh
# Node.js/npm users: no Go compiler required
npm install -g mcpsense@latest
# Go users: no Node.js/npm required
go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest
```

For a first offline walkthrough, open an empty project directory and run:

```sh
mcpsense init --example
mcpsense scan ./mcp.json --offline --no-baseline
```

This creates a synthetic example manifest and refuses to overwrite an existing `mcp.json`. It does not connect to or configure your real MCP server. For a real inspection, replace the target path with your existing manifest or client MCP configuration. `mcpsense init` without `--example` creates scanner settings; it does not create a scan target.

Check installation with `mcpsense version` and `mcpsense --help`. In the candidate, `mcpsense version --check` contacts only GitHub/npm for published-version metadata and prints both versions, channel disagreement, and update commands. It never installs automatically; ordinary startup and offline scans do not perform version lookups. An installed development preview can be newer than the published stable release.

### From a source checkout

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

npm downloads the selected platform executable and verifies its release SHA-256 checksum on Windows, Linux and macOS. It checks startup and the version before replacing an existing installation. Checksums detect corruption; they are not code signatures. To select 0.4.0 explicitly, use `npm install -g mcpsense@0.4.0` or `go install github.com/fayzkk889/MCPSense/cmd/mcpsense@v0.4.0` once that version appears in the public release list.

### Windows installation

On Windows x64, the npm route needs Node.js/npm only. The separate Go route needs Go 1.22 or newer only. The optional standalone PowerShell installer below is a convenience for Go users: it builds from source, verifies startup, installs without administrator privileges, and adds its directory to your user PATH. No installation route changes Windows protection settings. Downloaded and locally built executables can both be restricted by machine policy; no warning-free guarantee is made.

Windows behavior has varied by executable: earlier unsigned candidates and the published 0.3.0 npm binary were blocked by local Code Integrity policy, while the newer unpublished `0.4.0-SNAPSHOT-3d1c18b` archive installed and ran with Go absent during the [24 October product retest](docs/engineering/product-retest-2026-10-24.md). The candidate remains unsigned. Windows release readiness still requires trusted signing and a protected-device retest; ZIP packaging or installing Go does not supply a publisher signature. See the [Windows readiness record](docs/engineering/windows-signing-readiness-2026-10-23.md).

From a downloaded or cloned checkout:

```powershell
# Latest published version
.\install.ps1
# Select a published release explicitly, after publication
.\install.ps1 -Version 0.4.0
# Preview an authorized exact commit without changing PATH
.\install.ps1 -Version <full-40-character-commit> -InstallDir C:\dev\mcpsense-preview -NoPathUpdate
```

Update the npm installation with `npm install -g mcpsense@latest`, or update the Go installation by rerunning the Go install command. Package users do not need an npm account. Supported npm release targets are Windows x64 and Linux/macOS x64/arm64; the downloaded executable uses the operating system's archive utility during installation.

On Linux/macOS, `sh install.sh` installs the latest published release into `~/.local/bin`, verifies its SHA-256 manifest before installation and checks startup. `MCPSENSE_VERSION=0.4.0` selects a published version; `MCPSENSE_INSTALL_DIR` selects a writable directory. Add that directory to PATH when instructed. No automatic sudo or Windows-binary fallback is used.

## Scope and permissions

| Selection | Behavior |
| --- | --- |
| Auto directory | Reads supported source, recognized MCP JSON/configs, and skill files together |
| `--mode static` | Source analysis plus recognized manifests/configs; no skill traversal |
| `--mode manifest` | Reads one MCP manifest |
| `--mode config` | Reads `mcpServers` or `servers` configuration entries |
| `--mode skill` | Reads agent instructions such as AGENTS.md, CLAUDE.md, SKILL.md and supported client rule paths |
| `--mode live` | Enumerates metadata at the explicitly selected endpoint or authorized local process |
| `--mode dependencies` | Reads an explicitly selected npm v2/v3 lockfile, including nested, development and optional entries |

A directory scan does not start configured MCP commands or contact configured server URLs. Advisory lookups are a separate network operation enabled by default for recognized package references. Use `--offline` for no scanner networking; it also prohibits all live scans and local server execution. `--no-cve` disables advisory lookups only.

Multiple configs with distinct server names are included. Ambiguous duplicate names or multiple manifests require separate explicit scans; they fail instead of silently omitting a component. Unreadable/malformed discovered inputs and exceeded limits fail the scan. Dependency/build directories are excluded. Supported source extensions are `.go`, `.py`, `.ts`, and `.js`; this is not complete language or dependency coverage.

Input files must be regular non-symlink files, at most 4 MiB. Source, skill, and config discovery each have a 64 MiB phase budget and a 10,000-input cap. These checks are not filesystem isolation against concurrent local path replacement.

### Dependency inspection (0.4.0 candidate)

```sh
# Auto-detect a package-lock.json or npm-shrinkwrap.json
mcpsense scan ./package-lock.json --no-baseline
# Include one selected lockfile alongside project checks
mcpsense scan ./server --dependencies ./server/package-lock.json --no-baseline
# Inspect declarations locally without querying advisories
mcpsense scan ./package-lock.json --offline --format json --no-baseline
# A differently named lockfile needs an explicit mode
mcpsense scan ./saved-lock.json --mode dependencies --no-baseline
```

Directory scans do not automatically read lockfiles or send their package names. Selecting a dependency inventory explicitly enables OSV queries for recognized names and exact versions unless `--offline` or `--no-cve` is set. Public-registry tarball identities are supported, including aliases with an explicit actual package name. Git, local/workspace links, private registries, missing source metadata and unsupported versions remain unresolved. Online advisory checks fail before querying an incomplete inventory; use offline JSON inspection to see `dependencies.packages[].unresolved`. No packages are installed and no lifecycle scripts run.

The JSON and SARIF inventory records the input SHA-256, package locations and declared versions. Missing required package references are unresolved; nested and hoisted resolution is checked, while optional omissions and peer installation remain environment-dependent. It describes the selected file, including nested/development/optional entries; it does not attest the installed tree, environment-specific omissions or running code. A `package.json` version range is not an installed version. Other ecosystems, SBOM formats, other lockfiles and effective server security settings remain outside this inventory's scope.

Advisory lookup allows up to 2,048 distinct identities and 10,000 locations, with eight concurrent lookups, a 30-second phase budget, five seconds per request, at most 32 pages/16 MiB per package, a 64 MiB aggregate response budget, and 10,000 advisory findings. Duplicate identities share a query while findings retain each location. Failed pages, stale data after a failed refresh, cancellation and exceeded limits fail the scan; they do not produce a successful partial report. Fresh complete results are cached for 24 hours. Cache entries from the older non-paginating client are discarded.

For remediation comparison, keep the same inventory file, format, package names and locations. Version upgrades can be compared; removing entries changes coverage and cannot count as an equivalent completed remediation. The inventory hash is evidence of the file read, not a signature or proof that its contents are authentic.

Recent MCP SDK advisories require deployment changes as well as upgrades: for example, [tool-input element limits must be enabled](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-46jr-4wx8-v453), and [token audience checks require both middleware and verifier configuration](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-rvq5-wwqv-78pq). A quiet dependency report does not verify those settings. See the [threat review](docs/research/2026-10-23-mcp-threat-review.md) for the remaining runtime enforcement priorities.

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

There are 32 registered checks: 5 manifest/spec checks, 16 security heuristics, 3 skill checks, 1 advisory check, and 7 quality checks. Thirteen additional drift IDs are emitted during baseline comparison. Registry counts are not security-coverage guarantees.

Checks include prompt-injection patterns, suspicious execution/URL/file-access patterns, Unicode and cross-tool poisoning signals, annotation inconsistencies, credential exposure, package references, schemas and tool quality. A shell metacharacter or changed annotation alone does not prove command execution or permission escalation. OWASP mappings are advisory classifications.

Credential-name heuristics include generic API_KEY/APIKEY/ACCESS_KEY names and provider-specific names; their values are not printed. Tool descriptions that consist entirely of a narrowly recognized document-query operation treat a quoted search phrase as data. Arbitrary quotation marks or the word “example” do not exempt instructions; appended directives are still screened. Literal skill rules inspect the original instructions. Relational rules combine lexical action, object and scope signals for authority replacement, disclosure, deception, routing, permission bypass and persistent policy changes. They can miss paraphrases or misinterpret legitimate tasks; they do not determine authorization or understand arbitrary language.

Metadata screening includes server descriptions/instructions, tool names/titles/descriptions, schema string values and keys, annotation titles, resource names/URIs/descriptions and prompt names/descriptions/arguments. Reports list this scope and what was not assessed. Resource contents, prompt bodies, runtime tool responses and unknown extension fields are not inspected. Source shell findings distinguish direct argument arrays from explicit shell evaluation for recognized Go/Python forms; this is not full parsing of every language or dataflow/alias analysis.

```sh
# One scan, consistent JSON and SARIF including drift findings
mcpsense scan ./manifest.json --offline --no-baseline --format json --output report.json --sarif-output report.sarif

# Rule filters are validated; unknown IDs and conflicting filters fail
mcpsense scan ./manifest.json --offline --no-baseline --checks SEC-001,SPEC-002
```

JSON schema 2 includes coverage, selected/skipped checks, advisory state, input identities, target identity, severity filter, confidence and stable rule/component fingerprints. Multiple occurrences of one rule in one component share an identity. SARIF carries the same fingerprints and coverage. Local metadata findings retain their actual input file; no line number is invented. GitHub Code Scanning requires physical source locations, so purely live logical findings may require sarif-upload: false and separate JSON/SARIF review. `needs_review` describes heuristics; `advisory_match` describes database matches. Neither means exploitation was verified.

Advisory lookup recognizes supported primary-package launch forms for npx/npm exec, uvx/uv tool run and pipx run. Local Node/Python scripts and modules, arbitrary wrappers, unsupported options, URL/Git sources, project dependencies and transitive packages are not a resolved dependency inventory. Recognized moving npm tags/ranges are not exact version pins. JSON/SARIF `coverage.advisory_scope` identifies OSV plus a small vendor-reviewed supplement dated 2026-10-23; that supplement covers AWS PostgreSQL advisory GHSA-fph8-pg5w-78fv, which the research lookup did not find in OSV. Unknown version applicability remains a candidate for review. Both sources are skipped with `--offline`/`--no-cve`; requested OSV failures still fail the scan. Advisory findings require package-specific remediation and configuration review; an upgrade alone may not enable the protection.

The [23 October threat review](docs/research/2026-10-23-mcp-threat-review.md) documents recent SDK isolation, authorization and resource-exhaustion advisories, reproduced scanner gaps, and the enforcement boundaries required for prevention. MCPSense does not enforce runtime permissions, session isolation or resource limits. Those properties are explicitly unassessed in reports.

A score starts at 100 and subtracts severity weights for reported findings. Filtering affects the score. A zero finding count or score 100 does not establish overall security. Advisory lookup failure or stale-only fallback fails the requested scan; `--no-cve` explicitly records that this phase was skipped. Package extraction is heuristic, not a resolved dependency inventory.

Exit codes: **0** completed without reported high/critical findings, **1** completed with those findings, **2** execution/configuration/policy failure. This changes the old conflated error status.

## Baselines and privacy

Manifest/config/live scans and directory scans with metadata save a baseline by default under `~/.mcpsense/snapshots/`. `--baseline` selects a file; `--no-baseline` disables this behavior; `--update-baseline` explicitly accepts reviewed changes.

Baseline comparisons flag new tools/resources/prompts, changed tool descriptions, input/output schemas, titles and annotations, changed resource/prompt metadata, changed server descriptions/instructions, removed authentication declarations and changes to existing client server configurations. A change requests review; it does not establish malicious intent. Removed tools/resources/prompts, new or removed client server entries, environment values, runtime responses, resource contents, prompt bodies and unknown extensions are not compared.

New format-2 baselines include a versioned metadata extension. Existing format-2 files remain usable for their captured fields; terminal, JSON and SARIF reports explicitly warn that server text, tool titles/output schemas and prompts were not compared. After reviewing the actual target, use `--update-baseline` to capture these fields. Comparisons never silently upgrade a baseline. JSON/SARIF `coverage.baseline_fields` lists the evaluated comparisons, and remediation verification refuses differing baseline scope. Unsupported future extensions fail visibly.

Snapshots are capped at 4 MiB; oversized saves fail, and verification accepts regular report files up to 16 MiB. Format 2 stores digests and minimal booleans instead of raw tool descriptions, commands, arguments, target URLs, resource names or environment values. Environment values are excluded even from the config digest. Raw before/after text is not exported; `--show-diff` is a compatibility flag. Digests support change comparison, not encryption: low-entropy values may still be guessable. Do not commit private baselines without review.

Old plaintext baselines and unknown future formats fail with a recreation instruction. Review the target, recreate with `--update-baseline`, and separately review/remove old sensitive copies under your own retention policy. They are not silently rewritten or deleted. Writes use a temporary file with restrictive requested permissions before replacement; Windows ACLs depend on the containing directory.

Reports remove raw diffs and redact recognized credentials, URL credentials/query values, and known configuration argument/environment values. Redaction is best effort for arbitrary text, not a guarantee that every possible secret format can be recognized. Review artifacts before sharing them.

## Verify a remediation

```sh
mcpsense verify before.json after.json
```

Verification is offline and requires completed, equivalent schema-2 scans: same target, mode, input inventory, protocol, selected checks, advisory/baseline policy, approved-baseline digest and severity filter. Changed or incomplete coverage remains unverified. `resolved` means a rule/component group was no longer detected in that equivalent scope; it does not prove exploit prevention or authenticity of unsigned report files.

Reports also carry a detector fingerprint derived from the checked-in rule source and Go toolchain. Verification refuses changed or missing fingerprints, so upgrading the scanner cannot masquerade as fixing the target. Recreate both reports with the same detector when comparing older reports or changing toolchains. The fingerprint is an equivalence guard, not a signature.

See the [reproducible before/after demonstration](docs/engineering/remediation-demo.md), [test report](docs/engineering/test-report.md), and [release readiness](docs/engineering/release-readiness.md).

## GitHub Action

The snippet uses main for development; pin a reviewed full commit SHA or release tag for production.

```yaml
permissions:
  contents: read
  security-events: write # only needed when uploading SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - uses: fayzkk889/MCPSense@main
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

A [broader product acceptance check](docs/engineering/product-acceptance-2026-10-23.md) tested 60 newly labelled descriptions on Windows and Linux. Across all security rules, 16 of 30 hostile cases were flagged and 9 of 30 benign cases were falsely flagged (64.0% precision, 53.3% recall). Injection-rule-only recall was 26.7%. Two hostile examples scored 100. These exploratory results expose substantial detection limits; a clean scan must not determine whether an integration is safe. The same walkthrough reproduced an unsupported critical command-injection claim for literal argument data.

Those are the preserved pre-fix results. The [subsequent fixes and evaluation](docs/engineering/product-improvements-2026-10-23.md) address directive families, benign metadata context and literal argv. A further40 pre-labelled examples initially produced20/20 hostile detections and2/20 benign false alarms. Reused datasets are regression evidence; none of these small agent-authored sets establishes deployment accuracy or universal protection.

See [baseline audit](docs/engineering/repository-audit.md), [security research](docs/research/2026-10-security-landscape.md), and [commercial hypothesis](docs/research/commercial-validation.md) for evidence and remaining uncertainty. No hosted service, payment system, exploit verification or incident-response claim is included. MIT remains unchanged.
