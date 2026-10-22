# mcpsense npm wrapper

MIT-licensed wrapper for the MCPSense CLI, version 0.4.0. Earlier versions do not contain the same safety controls. Check `mcpsense version` after installation.

Install a published version:

```
npm install -g mcpsense
mcpsense scan ./manifest.json --offline --no-baseline
```

Node.js/npm is sufficient for this route: Go is not required on Windows, Linux or macOS. The installer downloads the selected platform archive, verifies its release SHA-256 checksum, extracts only the CLI executable and checks its version/startup before replacing an existing installation. A checksum is not a signature.

Supported release targets: Windows x64 and Linux/macOS x64/arm64. Modern Windows includes the archive utility used by installation; Linux/macOS use system tar. NVM is optional. Users who prefer a source installation can instead use `go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest` without Node.js/npm. Windows machine policies may still restrict executable startup; neither route disables protection or guarantees zero warnings.

Update with `npm install -g mcpsense@latest`. Users do not need to log in to npm to install or update this public package. Publisher login is required only for maintainers publishing a new version.

The wrapper forwards argument arrays and exit status without a shell. Exit 0 means completed without high/critical findings, 1 means those findings were found, and 2 means execution/policy failure.

Directory inspection does not execute MCP commands. Live local startup requires --allow-exec. Offline prohibits scanner networking and local server execution; installing/building the package itself may need network access.

Full behavior, protocol limits, report privacy and remediation verification are documented in the [repository README](https://github.com/fayzkk889/MCPSense#readme). Website deployment is not part of this checkout.
