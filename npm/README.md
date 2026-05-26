# mcpsense

Security scanner for MCP (Model Context Protocol) servers. Catches prompt injection, command injection, SSRF, path traversal, data exfiltration, and more.

## Install

```
npm install -g mcpsense
```

Or run without installing:

```
npx mcpsense scan ./mcp.json
```

## Usage

```
mcpsense scan ./mcp.json              # Scan MCP client config
mcpsense scan ./my-server/            # Static analysis of source code
mcpsense scan https://my-server.com   # Scan live MCP server
mcpsense scan ./mcp.json -f json      # JSON output for CI/CD
mcpsense scan ./mcp.json -f sarif     # SARIF for GitHub Code Scanning
```

## Documentation

Full docs, check list, and research: [mcpsense.site](https://mcpsense.site)

## Source

[github.com/fayzkk889/MCPSense](https://github.com/fayzkk889/MCPSense)

## License

MIT
