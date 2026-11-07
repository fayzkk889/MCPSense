# mcpsense npm CLI

MIT-licensed MCPSense CLI requiring Node.js 22+ and npm. This package uses WebAssembly delivery; versions before 0.4.0 used a native executable. Check `mcpsense version` for the installed version, or `mcpsense version --check` to compare the published npm and GitHub channels. Release status and known limitations are recorded in the repository README and release notes; a source push does not update the public package.

Install a published version:

```
npm install -g mcpsense@latest
mcpsense version
mcpsense init --example
mcpsense scan ./mcp.json --offline --no-baseline
```

Run the example in an empty directory. It creates a synthetic offline manifest, refuses to overwrite an existing `mcp.json`, and does not connect to your server. To inspect your own setup, scan the path to its existing MCP manifest or client configuration. Plain `mcpsense init` creates scanner settings, not a scan target.

Node.js 22+/npm is sufficient for this route: Go is not required on Windows, Linux or macOS. The package bundles the same Go security engine compiled to WebAssembly, its matching Go runtime and small Node host adapters. A Node-only global installation hook verifies the runtime and handles an identified older Go copy taking precedence on PATH. It preserves that executable in a uniquely named backup and routes its command to this npm installation. Unknown, linked or newer commands are preserved and reported. Local/project/npx installations do not migrate global commands. No executable download, archive utility or local compilation is needed. Runtime component checksums reject accidental corruption or mixed files; they are not publisher signatures. npm supplies its normal registry/tarball integrity checks.

Supported targets: Windows/Linux/macOS x64/arm64 with Node.js 22+. Older Node.js installations must be updated. NVM is optional. Users who prefer a source installation can instead use `go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest` with Go 1.22+ and without Node.js/npm. This npm package contains no MCPSense `.exe`. Device policies may still restrict Node.js or scripts; neither route disables protection or guarantees zero warnings.

Update with `mcpsense update`, or `npm install -g mcpsense@latest`. The update command requires npm and GitHub to agree on the latest stable release, keeps the existing global npm prefix and verifies the installed runtime and PATH selection. It does not install Go, change PATH or downgrade a newer release. Users do not need to log in to npm to install or update this public package. Publisher login is required only for maintainers publishing a new version.

`mcpsense update --check` and `mcpsense version --check` compare published versions without installing. Interactive human-readable scans and `version` can announce an update on stderr, using a one-hour cache and a two-second total lookup limit. Offline scans, machine-readable output, CI, help and piped commands skip automatic checks. Disable automatic checks with `--no-update-check` or `MCPSENSE_NO_UPDATE_CHECK=1`. No update installs automatically. The repository can contain a newer candidate than either published channel; see the live version badges in its README.

If an earlier Windows installation still runs an old Go executable, install this version normally so its global hook can repair the conflict. If lifecycle scripts were deliberately disabled, run the owning npm shim explicitly: `mcpsense.cmd update --repair-path`. Unknown command conflicts need manual review; the diagnostic names the preserved path. A global npm prefix must be on PATH. On Windows where policy restricts npm's PowerShell shim, use `mcpsense.cmd`.

The CLI preserves literal arguments and exit status. Explicit local-server scans use process argument arrays without a shell. Exit 0 means completed without high/critical findings, 1 means those findings were found, and 2 means execution/policy failure. WebAssembly is an execution format, not a sandbox for authorized local MCP commands; the scanner still reports its unassessed security boundaries.

Directory inspection does not execute MCP commands. Live local startup requires --allow-exec. Offline prohibits scanner networking and local server execution; installing/building the package itself may need network access.

Full behavior, protocol limits, report privacy and remediation verification are documented in the [repository README](https://github.com/fayzkk889/MCPSense#readme). Website deployment is not part of this checkout.

The source checkout also adds an upcoming MCP interface using this exact bundled engine, with no additional server package. It is not in the published 0.4.5 package. See the [MCP guide](https://github.com/fayzkk889/MCPSense/blob/main/docs/mcp.md) for preview setup and the shared CLI/MCP update lifecycle.
