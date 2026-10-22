# mcpsense npm wrapper

MIT-licensed wrapper for the MCPSense CLI. This checkout prepares 0.4.0; publication is pending maintainer approval. Existing published 0.3.0 does not contain the new safety behavior.

After release:

```
npm install -g mcpsense
mcpsense scan ./manifest.json --offline --no-baseline
```

Windows installation requires Go and compiles the selected release into the package's binary directory. Linux/macOS download the platform archive, verify its release SHA-256 checksum, and extract only the CLI executable. A checksum is not a signature.

The wrapper forwards argument arrays and exit status without a shell. Exit 0 means completed without high/critical findings, 1 means those findings were found, and 2 means execution/policy failure.

Directory inspection does not execute MCP commands. Live local startup requires --allow-exec. Offline prohibits scanner networking and local server execution; installing/building the package itself may need network access.

Full behavior, protocol limits, report privacy and remediation verification are documented in the [repository README](https://github.com/fayzkk889/MCPSense#readme). Website deployment is not part of this checkout.
