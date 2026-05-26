# MCPSense

**Security scanner for MCP servers. Think ESLint + Snyk, but for the Model Context Protocol.**

[![Build Status](https://img.shields.io/github/actions/workflow/status/fayzkk889/MCPSense/ci.yml?branch=main)](https://github.com/fayzkk889/MCPSense/actions)
[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue)](https://go.dev)
[![npm](https://img.shields.io/npm/v/mcpsense)](https://www.npmjs.com/package/mcpsense)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Install

```
npm install -g mcpsense
```

Or run without installing:

```
npx mcpsense scan ./mcp.json
```

<details>
<summary>Other install methods</summary>

**Go install (requires Go 1.22+):**

```
go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest
```

**Linux/macOS binary download:**

```
curl -sSL https://raw.githubusercontent.com/fayzkk889/MCPSense/main/install.sh | sh
```

**Windows PowerShell installer:**

```
irm https://raw.githubusercontent.com/fayzkk889/MCPSense/main/install.ps1 | iex
```

**Pre-built binaries:** [GitHub Releases](https://github.com/fayzkk889/MCPSense/releases)

</details>

---

## Quick Start

Scan your MCP client config for command injection, credential leaks, and supply chain risks:

```
mcpsense scan ./mcp.json
```

Scan Claude Desktop config:

```
mcpsense scan ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Scan a source code directory:

```
mcpsense scan ./my-mcp-server/
```

Scan a live MCP server:

```
mcpsense scan https://my-server.example.com
```

JSON output for CI/CD:

```
mcpsense scan ./mcp.json --format json --output report.json
```

SARIF output for GitHub Code Scanning:

```
mcpsense scan ./mcp.json --format sarif --output results.sarif
```

---

## What It Catches

### Security (16 checks)

| ID | Check | Severity |
|----|-------|----------|
| SEC-001 | Prompt injection in tool descriptions | Critical |
| SEC-002 | Shell command execution | High |
| SEC-003 | SSRF risk | High |
| SEC-004 | Path traversal | High |
| SEC-005 | Missing authentication | Medium |
| SEC-006 | Overly permissive resource access | Medium |
| SEC-007 | Command injection via string interpolation | Critical |
| SEC-008 | Data exfiltration vectors | Medium |
| SEC-009 | Invisible Unicode / ASCII smuggling | Critical |
| SEC-010 | Homoglyph / mixed script detection | High |
| SEC-011 | Data exfiltration instructions | Critical |
| SEC-012 | Cross-tool manipulation | High |
| SEC-013 | Annotation integrity mismatch | High |
| SEC-014 | Config command injection | Critical |
| SEC-015 | Sensitive env var leakage | Medium |
| SEC-016 | Unverified server source | Medium |

### Spec Compliance (5 checks)

SPEC-001 through SPEC-005: manifest structure, input schemas, naming, resource URIs, protocol version.

### Tool Quality (7 checks)

QUAL-001 through QUAL-007: description clarity, parameter naming, missing descriptions, duplicate tools, examples, tool count, input constraints.

**27 checks total across 3 categories.**

---

## Scan Modes

MCPSense auto-detects the right mode, or set it manually with `--mode`:

| Mode | Target | What it does |
|------|--------|-------------|
| `config` | mcp.json, claude_desktop_config.json | Scans client configs for command injection, env leaks, unpinned packages |
| `manifest` | MCP manifest JSON | Scans tool definitions for prompt injection, SSRF, path traversal |
| `static` | Source directory | Analyzes Go, Python, TypeScript, JavaScript source code |
| `live` | URL or command | Connects via stdio or HTTP, performs full protocol handshake |

---

## Output Formats

**CLI** (default): Colored terminal output with severity-coded findings and remediation guidance.

**JSON**: Structured output for CI/CD pipelines. Exits with code 1 on Critical or High findings.

```
mcpsense scan ./mcp.json --format json
```

**SARIF**: SARIF 2.1.0 for GitHub Code Scanning and VS Code.

```
mcpsense scan ./mcp.json --format sarif
```

---

## CI/CD

**GitHub Actions:**

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  mcpsense:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fayzkk889/MCPSense@v0.2.2
        with:
          target: ./mcp.json
```

Or install and run manually:

```yaml
- run: npm install -g mcpsense
- run: mcpsense scan ./mcp.json --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## CLI Reference

```
mcpsense scan <target> [flags]

Flags:
  -m, --mode string      Scan mode: static, live, manifest, config, auto (default "auto")
  -f, --format string    Output format: cli, json, sarif (default "cli")
  -s, --severity string  Minimum severity: critical, high, medium, low, info (default "low")
  -c, --checks string    Comma-separated check IDs to run (default: all)
      --exclude string   Comma-separated check IDs to skip
      --probe            Enable active probing in live mode
  -o, --output string    Output file path (default: stdout)
      --no-color         Disable colored output
```

---

## Research

We scanned 35 real MCP servers and client configs from public GitHub repos. 62% had security findings. 486 total findings across 22 servers. [Read the full research writeup](https://mcpsense.site/blog/).

---

## Contributing

Contributions welcome. Fork, branch, write tests, submit a PR. To add a new check, implement the `checks.Check` interface and register it in `checks.NewRegistry()`.

---

## License

MIT. See [LICENSE](LICENSE) for details.

Built by [Faizan](https://github.com/fayzkk889).
