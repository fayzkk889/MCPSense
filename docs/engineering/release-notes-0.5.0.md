## MCPSense 0.5.0 — the same engine, inside your assistant

MCPSense's existing security scanner now works from supported coding assistants
as well as the terminal. CLI and MCP ship together and share the checks,
inspection policy, findings and version.

### Connect your assistant

Install through either independent route:

```sh
npm install -g mcpsense@latest
# Or, with Go instead of Node/npm:
go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest
```

From the project you want to inspect:

```sh
mcpsense version
mcpsense mcp install --client cursor --root .
```

Select `vscode`, `copilot`, `claude-code`, `claude-desktop` or `codex` for another
supported client. Restart its MCP connection, then ask it to scan a file or
project you selected. See the [setup guide](https://github.com/fayzkk889/MCPSense/blob/main/docs/mcp.md).

- Offline and read-only by default, limited to the approved project root.
- Optional networking, executable startup and writes require explicit startup
  grants and operation choices. Baseline acceptance also requires human review.
- Shared scanning, check discovery, report verification, baseline workflows and
  optional findings panel in clients supporting MCP Apps.
- Existing client settings and server entries are preserved; supported setup
  formats include JSON and TOML, with explicit manual instructions for JSONC.
- Update once with `mcpsense update`, then restart the MCP connection. No second
  package or client-configuration replacement is needed.

### Security corrections

- Reject ambiguous JSON field aliases, including Unicode folding, and duplicate
  members before metadata inspection or MCP dispatch. A reproduced case let a
  benign `Description` hide the hostile canonical `description`. Malformed or
  ambiguous input now fails visibly; ordinary case-distinct schema map keys work.
- Bound JSON parsing depth and work, and include the interpretation policy in
  detector identity.
- Retain reviewed AWS API token-audience and AWS Serverless path-traversal
  advisory evidence when a successful feed lookup returns no records. Preserve
  affected ranges, deployment conditions, source dates and unresolved versions.

### Verification and limits

Native Windows/Linux and npm Windows/Linux/macOS matrices exercise product
journeys, frozen hostile/benign cases, permissions, client setup, live metadata,
updates and remediation. Both official MCP protocol client generations were
tested. [Research and reproduction evidence](https://github.com/fayzkk889/MCPSense/blob/main/docs/engineering/security-research-2026-11-10.md)
and [validation results](https://github.com/fayzkk889/MCPSense/blob/main/docs/engineering/security-research-2026-11-10-results.md)
retain their measured scope.

These results do not establish universal detection, runtime authorization or an
OS sandbox. Tool results, resource contents, prompt bodies and unknown semantic
attacks remain outside the scanner's attested coverage. Explicit dependency
inventory currently supports npm v2/v3 lockfiles, not Go/Cargo lockfiles.

npm requires Node.js 22+ and bundles WebAssembly/JavaScript, with no Go compiler
or MCPSense `.exe`. Go remains independent and requires a current patched Go
compiler (minimum 1.22). Optional native Windows archives remain unsigned;
device policy can restrict them. Protection settings are unchanged. MIT is
preserved, with third-party notices included in both distribution routes.
