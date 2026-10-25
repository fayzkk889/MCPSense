# mcpsense npm CLI

MIT-licensed MCPSense CLI, version 0.4.0 candidate, requiring Node.js 22+ and npm. Earlier public versions use a native executable and do not contain the same safety controls or installation architecture. Check `mcpsense version` after installation. This candidate reaches `@latest` only after publication.

Install a published version:

```
npm install -g mcpsense@latest
mcpsense version
mcpsense init --example
mcpsense scan ./mcp.json --offline --no-baseline
```

Run the example in an empty directory. It creates a synthetic offline manifest, refuses to overwrite an existing `mcp.json`, and does not connect to your server. To inspect your own setup, scan the path to its existing MCP manifest or client configuration. Plain `mcpsense init` creates scanner settings, not a scan target.

Node.js 22+/npm is sufficient for this route: Go is not required on Windows, Linux or macOS. The package bundles the same Go security engine compiled to WebAssembly, its matching Go runtime and small Node host adapters. No install hook, executable download, archive utility or local compilation is needed. Runtime component checksums reject accidental corruption or mixed files; they are not publisher signatures. npm supplies its normal registry/tarball integrity checks.

Supported targets: Windows/Linux/macOS x64/arm64 with Node.js 22+. Older Node.js installations must be updated. NVM is optional. Users who prefer a source installation can instead use `go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest` with Go 1.22+ and without Node.js/npm. This npm package contains no MCPSense `.exe`. Device policies may still restrict Node.js or scripts; neither route disables protection or guarantees zero warnings.

Update with `npm install -g mcpsense@latest`. Users do not need to log in to npm to install or update this public package. Publisher login is required only for maintainers publishing a new version.

`mcpsense version --check` explicitly compares the installed version with the latest GitHub release and npm version. It reports unavailable or disagreeing channels clearly and never auto-installs. Ordinary startup and offline scanning do not make version-check requests. The repository can contain a newer candidate than either published channel; see the live version badges in its README.

The CLI preserves literal arguments and exit status. Explicit local-server scans use process argument arrays without a shell. Exit 0 means completed without high/critical findings, 1 means those findings were found, and 2 means execution/policy failure. WebAssembly is an execution format, not a sandbox for authorized local MCP commands; the scanner still reports its unassessed security boundaries.

Directory inspection does not execute MCP commands. Live local startup requires --allow-exec. Offline prohibits scanner networking and local server execution; installing/building the package itself may need network access.

Full behavior, protocol limits, report privacy and remediation verification are documented in the [repository README](https://github.com/fayzkk889/MCPSense#readme). Website deployment is not part of this checkout.
