# MCPSense inside your assistant

**0.5.0 development candidate:** this interface is in the source checkout, not the published 0.4.5 release. Do not expect `npm install -g mcpsense@latest` to provide these commands until a release containing this change is approved and published.

MCPSense can run as a local MCP server. Ask your coding assistant to inspect an MCP configuration, source project, agent instruction file, dependency lockfile, or live server. It uses the installed MCPSense scanner, check registry, reports, and baseline logic. There is no second detection engine or separate MCP package to keep synchronized.

## Connect once

After installing a release that contains MCP support, open the project you want to inspect and choose your assistant:

```sh
mcpsense mcp install --client cursor --root .
# Or choose one of these instead:
mcpsense mcp install --client vscode --root .
mcpsense mcp install --client copilot --root .
mcpsense mcp install --client claude-code --root .
mcpsense mcp install --client claude-desktop --root .
mcpsense mcp install --client codex --root .
```

Restart the assistant, approve its MCPSense connection, and ask:

> Check my MCP configuration. Discover configurations in the approved project, ask me to select the one to inspect, and explain the findings, coverage, and what remains unassessed.

Setup preserves other servers and settings, keeps an exact private backup of an existing configuration, and prints its location. Running the same setup twice does not rewrite it. A different existing `mcpsense` entry is preserved for manual review. Setup does not silently expand its permissions or change its approved project.

Default locations: Cursor uses `~/.cursor/mcp.json`; VS Code uses the approved project's `.vscode/mcp.json`; Copilot uses `$COPILOT_HOME/mcp-config.json` or `~/.copilot/mcp-config.json`; Claude Code uses the project's `.mcp.json`; Codex uses `$CODEX_HOME/config.toml` or `~/.codex/config.toml`. Claude Desktop uses its standard Windows/macOS/Linux location (Linux: `~/.config/Claude/claude_desktop_config.json`); other platforms require its actual `--config` path. Shared project settings contain machine-specific absolute launch paths: keep these local or adapt them before sharing with teammates.

VS Code currently forwards eligible `.vscode/mcp.json` entries to its Copilot runtime. `--client copilot` writes the direct portable Copilot configuration instead. The [VS Code format reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) explains that distinction; Claude Desktop locations follow the [official local-server guide](https://modelcontextprotocol.io/docs/develop/connect-local-servers).

For another location, add `--config /path/to/settings`. For another client, use `--client generic --config /path/to/settings.json`. JSON client files must be valid JSON; files containing comments, invalid settings, symlinks, or incompatible Codex inline tables are preserved with an error. Generate a snippet and merge it in your editor:

```sh
mcpsense mcp config --client cursor --root .
mcpsense mcp config --client codex --root .
```

The npm route needs Node.js 22+/npm, with no Go compiler or MCPSense `.exe`. The independent Go route needs Go 1.22+, with no Node/npm. Use a persistent global npm installation for setup: temporary `npx` cache paths would freeze an obsolete copy and are rejected. For this preview, build a persistent native binary from the checkout, or build the npm runtime and install the resulting local tarball as described below.

## What you can ask

| Tool | Purpose |
| --- | --- |
| `mcpsense_status` | Installed engine version, approved root, startup permissions, supported modes. |
| `mcpsense_discover` | Find common configuration paths inside the approved project without reading their contents into chat. |
| `mcpsense_checks` | Current complete check registry, directly from the installed scanner. |
| `mcpsense_scan` | All implemented scanner modes and filters, explicit dependencies, guarded live metadata, baseline comparison, JSON/SARIF/terminal reports, optional exports. |
| `mcpsense_verify` | Compare equivalent completed JSON reports with the CLI's remediation verification. |
| `mcpsense_accept_baseline` | With write permission, accept current metadata only after explicit human review. |
| `mcpsense_init` | With write permission, create scanner settings or a synthetic example without replacing existing files. |

Examples:

> Inspect `.cursor/mcp.json` offline. Do not start any configured commands.

> Scan this project's source and instruction files. Explain the high-severity findings and suggested actions.

> Inspect `package-lock.json` offline and explain unresolved package identities. Do not install dependencies.

> Compare `before.json` with `after.json`. Only claim a resolution if their assessed coverage is comparable.

Scans default to all registered checks, minimum severity low, offline operation, and no baseline handling. `checks`, `exclude`, `severity`, explicit `dependencies`, and all supported CLI scan modes are available. Select `format: "json"`, `"sarif"`, or `"cli"`; every completed scan also supplies its structured report. CLI display-only/compatibility flags are classified in the parity test. The CLI's unimplemented `--probe` is not advertised as a working MCP feature. Version checks and package updates remain terminal maintenance commands.

Supporting MCP Apps hosts can show a local findings panel with severity filters and expandable remediation. Other hosts receive the same structured and text report. The view has no network access and renders finding text as text. It does not change permissions or approve fixes.

Maintainers can inspect the embedded view with synthetic data using `node scripts/mcp-app-preview.cjs`. Open the printed local URL, check severity filtering and remediation details, and use its completed, zero-findings, failed, and cancelled test states. This local test host does not establish that every assistant implements MCP Apps.

## Choose permissions deliberately

Default setup permits local inspection within one approved directory. Networking, local server execution, and writes are disabled. Existing client configs are inspected as data; configured commands are not automatically launched. `mcpsense_status` shows the actual grants.

To enable a broader workflow, generate a new configuration with only the required startup permissions and review the existing entry before replacing it:

```sh
# Online OSV queries and public HTTP metadata
mcpsense mcp config --client cursor --root . --allow-network
# Explicitly selected local MCP executables
mcpsense mcp config --client cursor --root . --allow-network --allow-exec
# Also permit a selected loopback/private HTTP endpoint
mcpsense mcp config --client cursor --root . --allow-network --allow-private-network
# Report exports, example/settings creation, reviewed baseline acceptance
mcpsense mcp config --client cursor --root . --allow-write
```

Grants can be combined. Each live scan must also request `offline: false`; starting a program needs `allow_exec: true`; private endpoints need `allow_private_network: true`. Scanner URL validation still blocks metadata/link-local endpoints. Live inspection discovers advertised metadata without invoking target tools. Explicit local executables and their literal arguments run with your OS privileges; the root scope is not an OS sandbox for those programs or protection against concurrent malicious filesystem changes.

Scans never create a baseline implicitly. Supply an existing `baseline` to compare it; `require_metadata_baseline: true` fails if supported metadata differs. To accept a new reference, first review the target, then explicitly approve `mcpsense_accept_baseline` with its `baseline` path and `reviewed: true`. A clean scan is not approval. Baselines can replace a reviewed reference; report exports require new files and never overwrite an existing report. Output parent directories must already exist within the approved root.

MCP resolves local targets to canonical absolute paths for root approval. When sharing reports or baselines with terminal scans, use that same absolute target path; directory aliases, Windows short names, and relative target spellings can produce different CLI evidence identities. An existing reference with a different target identity is rejected for review rather than silently accepted or rewritten.

The scanner executes locally. Findings, selected target paths, and report metadata are returned to the assistant and may be processed by its model provider. Secret redaction is best effort; inspect your sharing policy. Online advisory lookup discloses recognized package names and versions to OSV. A completed scan, zero findings, or a score of 100 does not establish safety or enforce runtime authorization. This MCP interface is an inspection assistant, not an inline gateway that blocks other MCP servers' tool calls.

## Updates stay together

```sh
mcpsense update --check
mcpsense update
```

Restart the MCP connection after an installed update, then ask for `mcpsense_status` to confirm the new version. Generated settings point at the persistent installed entrypoint, not a versioned download or an `npx` cache. Both interfaces load the same release artifact. The MCP server does not silently download software or replace a running engine.

The test suite checks CLI option mappings, the live check registry, CLI/MCP version and finding parity, actual stdio workflows, permission denials, baseline review, report export, client setup, and both official SDK generations. Native Windows/Linux and npm Windows/Linux/macOS run these through the existing CI/release gates. New CLI flags fail the parity test until mapped or explicitly classified, preventing an independently outdated MCP feature list.

## Try this checkout before publication

Native Go, from the repository (choose your binary name on Windows):

```sh
go build -o bin/mcpsense-preview ./cmd/mcpsense
./bin/mcpsense-preview mcp install --client cursor --root /path/to/project
```

For an npm preview, maintainers use the pinned production Go compiler to build the bundled runtime. End users of the resulting package do not need Go:

```sh
node scripts/build-npm-runtime.cjs
npm pack ./npm --ignore-scripts
npm install -g ./mcpsense-0.5.0.tgz
mcpsense mcp install --client cursor --root /path/to/project
```

This local candidate identifies itself as 0.5.0; it is not a public release. Reinstall the published package when done. Do not relabel candidate bytes as an existing version. Final release approval must confirm the new version and refresh the public onboarding text.

The server supports stdio only, both legacy initialization (2024-11-05 through 2025-11-25) and per-request modern MCP (2026-07-28). It uses a cooperative 60-second operation timeout, an 8 MiB protocol-message limit, a 3 MiB rendered-report limit, and one active tool operation per server process. Cancellation stops supported ongoing work and suppresses success responses; local analysis must reach a cancellation checkpoint, and writes already completed are not rolled back. Oversized targets need smaller inspections. If a connection fails, check the assistant's MCP logs, the configured approved root, the installed runtime, and `mcpsense mcp serve --help`.

Protocol references: [modern versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning), [stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio), [legacy tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), [MCP Apps](https://apps.extensions.modelcontextprotocol.io/api/documents/Quickstart.html).
