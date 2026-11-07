# MCP interface verification — 8 November 2026

Status: **0.5.0 development candidate; not published or merged.** Public 0.4.5
artifacts and the website are unchanged. Implementation checkpoints are
`9bc3e20` (shared interface), `94ed300` (cancellation before writes), and
`fe8086f` (configuration-number preservation and protocol errors).

## Product contract

- A local stdio MCP interface runs the installed CLI engine, rather than a
  separately maintained detector or separately published package.
- It exposes every implemented scan mode/filter, current registry, live
  metadata/dependencies, report formats/exports, remediation verification,
  initialization, and explicitly reviewed baselines. Version checks and software
  updates remain terminal maintenance commands.
- One installed update replaces both interfaces. An existing running MCP
  connection must restart; `mcpsense_status` identifies the loaded engine.
- Default operation is scoped to an approved directory, offline, without
  subprocess execution or file writes. Broader operations require startup grants
  and appropriate per-call selections. This is not an inline enforcement gateway
  for other servers, an OS sandbox, or a promise of universal hostile-text detection.
- Client setup preserves other entries, exact original backups, large JSON
  numbers, Codex comments, and invalid/conflicting configurations. It rejects
  temporary npx setup paths that would pin an obsolete cached package.

## Local verification

| Check | Observed result |
| --- | --- |
| Full Go suite with production Windows Go 1.27.3 | Passed; race suite and `go vet ./...` passed. Focused tests repeated after cancellation and configuration-preservation fixes. |
| Full Go suite with minimum supported Linux Go 1.22 | Passed; native Linux MCP user journeys passed. |
| MCP product journeys via Windows npm/WASM | Passed hostile/benign inspection, CLI finding/version parity, discovery, source/skills/dependencies, permission denials, live HTTP and stdio, reviewed baselines, required-reference mismatch, report exports, remediation verification and initialization. |
| Generated client configuration | Cursor, VS Code, Claude Code, Claude Desktop and Codex settings preserve other settings and repeat idempotently. The JSON-client entries are launched exactly as generated and complete actual scans; Codex TOML is parsed and compared using the TOML parser. |
| Official TypeScript SDK clients | SDK 1.32.2 and client 2.4.0 connected, listed tools/resources, read the embedded app, and detected hostile metadata through native Linux and npm. |
| Actual packed npm installation | Installed offline into an isolated prefix containing spaces, with no Go/archive tools on PATH and install scripts disabled. Installed CLI/MCP product journeys passed. |
| Full existing npm product suite | Passed existing core, persona, live, baseline, threat, dependency, fresh/user-labelled, and frozen-boundary acceptance. Detection code is unchanged; this is regression evidence, not a field-accuracy estimate. |
| Embedded app in a local synthetic browser host | Passed initialization handshake, severity filter, expanded remediation, zero findings with limitations, explicit failed state, and cancellation clearing old results. Synthetic HTML markup displays as text. Screenshot retained locally at `bin/mcp-panel-preview.jpg`. |
| License/dependency checks | `go mod verify` passed. MIT project license remains unchanged. New parser attribution is included in both npm and native archives and checked for consistency. |

The full npm regression suite initially ran against the development engine
using its previous 0.4.5 metadata. The final identified 0.5.0 package is separately
packed and tested; hosted CI rebuilds and repeats all gates from the exact branch
commit. Logs and generated tarballs remain under ignored `bin/` paths.

Local Windows security blocked the newly compiled native executable (`spawn
UNKNOWN`); this was not worked around by disabling protection. Native Linux and
the Windows npm delivery route were exercised. The Windows native CI matrix is
required before treating that route as verified for this change. Client-setting
tests and a synthetic app host do not establish real UI behavior in every
Cursor/Claude/VS Code/Codex release.

## Automated gates

`TestMCPScanFeatureParity` fails when a new CLI scan flag has neither an MCP
mapping nor an explicit classification. The MCP check catalog comes directly
from `checks.NewRegistry()`. Product tests compare CLI/MCP findings and versions.
CLI validation/help and MCP schema/status also use shared mode, severity, and
report-format definitions, rather than independent lists.
Native and npm CI invoke the same MCP user journeys; actual npm packing and the
tagged release workflow also run them. Official SDK interoperability is checked
in the Linux Node 22 job. CI builds and snapshots read the candidate version
from `npm/package.json`, replacing duplicated hard-coded build versions.

Hosted checks, the refreshed vulnerability audit, and archive snapshot are
pending the review-branch run. Publication still requires maintainer approval,
a new tag/version alignment, public onboarding updates and post-publication
channel/installation checks. No current stable version is relabelled or replaced
by this work.

Initial hosted run [42410822248](https://github.com/fayzkk889/MCPSense/actions/runs/42410822248)
passed Linux native, lint and the vulnerability audit, but caught a test-identity
assumption on macOS and Windows. MCP canonicalized the approved input, while the
CLI test used macOS `/var` aliases or Windows `RUNNER~1` short names. Findings
were identical except path-based locations/fingerprints. The corrected fixture
uses one canonical target for both interfaces and retains full deep equality;
an additional directory-alias scan must yield identical MCP findings. Existing
reference identity checks and path permission boundaries are not relaxed.

## Reproduce

```sh
go test ./... -count=1
go test -race ./...
go vet ./...
node scripts/build-npm-runtime.cjs
node scripts/release-verify.mjs --npm
node scripts/npm-wasm-smoke.cjs
node scripts/npm-product-suite.cjs
```

The scripts accept `MCPSENSE_TEST_BINARY` and optional
`MCPSENSE_TEST_RUNNER` to target the native or npm entrypoint. For independent
client interoperability, install the pinned development-only clients with
`npm install --prefix bin/mcp-sdk-check --ignore-scripts --no-audit --no-fund --no-package-lock @modelcontextprotocol/sdk@1.32.2 @modelcontextprotocol/client@2.4.0`,
then run `node scripts/mcp-sdk-interop.cjs` with those target variables set.
`node scripts/mcp-app-preview.cjs` serves only a synthetic local app test host.

See [MCP onboarding and boundaries](../mcp.md) for the user workflow.
