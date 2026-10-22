# mcpsense npm wrapper

MIT-licensed wrapper for the MCPSense CLI, version 0.4.0. Earlier versions do not contain the same safety controls. Check `mcpsense version` after installation.

Install a published version:

```
npm install -g mcpsense
mcpsense scan ./manifest.json --offline --no-baseline
```

Windows installation requires Go and compiles the selected release into the package's binary directory. Linux/macOS download the platform archive, verify its release SHA-256 checksum, and extract only the CLI executable. A checksum is not a signature.

On Windows, install Go 1.22 or newer before running npm installation; Node.js alone is insufficient. NVM is optional. For a route requiring only Go, use the repository's `install.ps1`; it never downloads a Windows executable and supports an explicit version or full commit. Source builds do not guarantee acceptance under every Windows application-control policy.

Update with `npm install -g mcpsense@latest`. Users do not need to log in to npm to install or update this public package. Publisher login is required only for maintainers publishing a new version.

The wrapper forwards argument arrays and exit status without a shell. Exit 0 means completed without high/critical findings, 1 means those findings were found, and 2 means execution/policy failure.

Directory inspection does not execute MCP commands. Live local startup requires --allow-exec. Offline prohibits scanner networking and local server execution; installing/building the package itself may need network access.

Full behavior, protocol limits, report privacy and remediation verification are documented in the [repository README](https://github.com/fayzkk889/MCPSense#readme). Website deployment is not part of this checkout.
