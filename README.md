# MCPSense

**Security scanner for MCP servers. Think ESLint + Snyk, but for the Model Context Protocol.**

[![Build Status](https://img.shields.io/github/actions/workflow/status/fayzkk889/MCPSense/ci.yml?branch=main)](https://github.com/fayzkk889/MCPSense/actions)
[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

MCPSense scans MCP servers, source code, and client configurations for security vulnerabilities, spec compliance issues, and tool quality problems. It detects tool poisoning attacks (invisible Unicode injection, cross-tool manipulation, annotation lying), client config command injection (the CVE class behind CVE-2025-6514, CVE-2026-30615), prompt injection in tool descriptions, shell execution risks, SSRF vectors, and more.

27 checks. 4 scan modes. 3 output formats. One binary.

---

## Quick Demo

```
mcpsense scan ./my-mcp-server

╔══════════════════════════════════════════════════════╗
║   mcpsense v0.2.0 — MCP Server Security Scanner     ║
╠══════════════════════════════════════════════════════╣
║  Target:  ./my-mcp-server                           ║
║  Mode:    static                                    ║
║  Score:   42/100                                    ║
╚══════════════════════════════════════════════════════╝

  CRITICAL   SEC-009  Invisible Unicode characters in tool "get_data" description
             Tool: get_data
             → 47 invisible Unicode tag characters detected (ASCII smuggling).
             Fix: Remove all invisible characters from tool definitions.

  CRITICAL   SEC-014  Shell metacharacters in config server "dev-tools" command
             File: .cursor/mcp.json
             → Command contains shell metacharacters. This is the exact
               attack vector behind CVE-2025-6514 and CVE-2026-30615.
             Fix: Use only direct binary paths in MCP configs.

  HIGH       SEC-013  Tool "delete_records" claims readOnly but name implies mutation
             Tool: delete_records
             → readOnlyHint=true but name contains "delete". Annotation lying
               can bypass confirmation dialogs on destructive tools.
             Fix: Set readOnlyHint to false.

  ────────────────────────────────────────────────────────
  Summary: 3 Critical │ 2 High │ 3 Medium │ 1 Low │ 0 Info
  ────────────────────────────────────────────────────────
```

---

## Install

```bash
go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest
```

Or download a pre-built binary from the [releases page](https://github.com/fayzkk889/MCPSense/releases).

---

## Quick Start

```bash
# Scan a directory (static analysis of source + manifests + configs)
mcpsense scan ./my-mcp-server/

# Scan a manifest file
mcpsense scan ./manifest.json

# Scan your Cursor/Claude MCP config for command injection
mcpsense scan ~/.cursor/mcp.json

# Scan a live running server (stdio)
mcpsense scan ./bin/my-server

# Scan a live server (HTTP/SSE)
mcpsense scan https://my-server.example.com

# Output as SARIF for GitHub Code Scanning
mcpsense scan . --format sarif --output results.sarif

# Output as JSON for CI/CD
mcpsense scan . --format json --output report.json
```

---

## Scan Modes

| Mode | Trigger | What It Does |
|------|---------|-------------|
| **static** | Directory path | Reads source files (Go, Python, TypeScript, JS) + discovers manifests and client configs |
| **manifest** | JSON file with tool definitions | Analyzes tool definitions, descriptions, schemas, and annotations |
| **config** | JSON file with `mcpServers` key | Scans MCP client configs (mcp.json, claude_desktop_config.json) for command injection, env leakage, supply chain risks |
| **live** | URL or executable binary | Connects to a running MCP server via stdio or HTTP, performs full protocol handshake, interrogates tools |

Mode is auto-detected. Override with `--mode static|manifest|config|live`.

---

## What MCPSense Checks

### Security (16 checks)

| ID | Name | Severity | What It Catches |
|----|------|----------|----------------|
| SEC-001 | Prompt injection in tool descriptions | Critical | Directive language that manipulates agent behavior |
| SEC-002 | Shell command execution | High | exec.Command, subprocess.run, os.system in source |
| SEC-003 | SSRF risk | High | Unvalidated URLs passed to HTTP clients |
| SEC-004 | Path traversal | High | ../../../etc/passwd style access patterns |
| SEC-005 | Missing authentication | Medium | Servers exposing sensitive tools without auth |
| SEC-006 | Overly permissive resource access | Medium | Wildcard URIs like file:///* |
| SEC-007 | Command injection via interpolation | Critical | User input interpolated into shell commands |
| SEC-008 | Data exfiltration vectors | Medium | Tools that read and return arbitrary file contents |
| SEC-009 | Invisible Unicode characters | Critical | Zero-width spaces, ASCII smuggling via tag characters (U+E0000 range) |
| SEC-010 | Homoglyph / mixed script detection | High | Cyrillic 'а' vs Latin 'a' in tool names, mixed-script bypasses |
| SEC-011 | Data exfiltration instructions | Critical | Descriptions telling agents to read ~/.ssh/id_rsa or send credentials |
| SEC-012 | Cross-tool manipulation | High/Critical | "Always use this tool first", "ignore other tools" in descriptions |
| SEC-013 | Annotation integrity mismatch | High | readOnlyHint=true on tools named "delete_user", destructiveHint=false on "drop_table" |
| SEC-014 | Config command injection | Critical | Shell metacharacters in mcp.json server entries (CVE-2025-6514 class) |
| SEC-015 | Sensitive env var leakage | Medium | AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN passed to MCP servers |
| SEC-016 | Unverified server source | Medium/High | Unpinned npx packages, HTTP (non-HTTPS) server URLs |

### Spec Compliance (5 checks)

| ID | Name | Severity |
|----|------|----------|
| SPEC-001 | Valid manifest structure | Medium |
| SPEC-002 | Tool input schema validity | High |
| SPEC-003 | Tool naming conventions | Low |
| SPEC-004 | Resource URI format | Medium |
| SPEC-005 | Protocol version compatibility | Info |

### Tool Quality (7 checks)

| ID | Name | Severity |
|----|------|----------|
| QUAL-001 | Description clarity score | Medium/Low |
| QUAL-002 | Ambiguous parameter names | Medium |
| QUAL-003 | Missing parameter descriptions | Low |
| QUAL-004 | Duplicate or overlapping tools | Low |
| QUAL-005 | Missing examples | Info |
| QUAL-006 | Excessive tool count | Info |
| QUAL-007 | Missing input constraints | Low |

---

## Output Formats

### CLI (default)
```bash
mcpsense scan ./mcp.json
```
Colored terminal output with severity-coded findings and inline remediation.

### JSON
```bash
mcpsense scan ./mcp.json --format json
```
Structured output for CI/CD pipelines and programmatic consumption.

### SARIF
```bash
mcpsense scan ./mcp.json --format sarif --output results.sarif
```
SARIF 2.1.0 output for GitHub Code Scanning, VS Code, and any SARIF-compatible tool. Upload to GitHub's Security tab for inline PR annotations.

---

## GitHub Action

Add MCPSense to your CI/CD pipeline with 4 lines:

```yaml
# .github/workflows/mcpsense.yml
name: MCP Security Scan
on:
  push:
    paths: ["**mcp*.json", "**claude_desktop_config.json", ".cursor/**"]
  pull_request:

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fayzkk889/MCPSense@v0.2.0
        with:
          target: "."
          format: "sarif"
          sarif-upload: "true"
          fail-on: "high"
```

**Action inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `target` | (required) | File, directory, or URL to scan |
| `mode` | `auto` | Scan mode: auto, static, live, manifest, config |
| `format` | `sarif` | Output format: sarif, cli, json |
| `severity` | `low` | Minimum severity to report |
| `fail-on` | `high` | Fail workflow at this severity or above |
| `sarif-upload` | `true` | Upload SARIF to GitHub Code Scanning |
| `version` | `latest` | MCPSense version to use |

**Action outputs:** `score`, `findings-count`, `sarif-file`

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

Other commands:
  mcpsense init          Create .mcpsenserc.json with defaults
  mcpsense version       Print version
```

---

## Configuration

```bash
mcpsense init
```

Creates `.mcpsenserc.json`:

```json
{
  "min_severity": "medium",
  "exclude_ids": ["QUAL-005", "QUAL-006"],
  "check_ids": [],
  "format": "json"
}
```

| Field | Description |
|-------|-------------|
| `min_severity` | Only report findings at or above this level |
| `exclude_ids` | Check IDs to skip (suppress known false positives) |
| `check_ids` | Run only these checks (empty = all) |
| `format` | Default output format |

---

### Add this badge to your server
[![MCP Security: MCPSense](https://img.shields.io/badge/MCP_Security-scanned_by_MCPSense-2ea043?logo=shield)](https://github.com/fayzkk889/MCPSense)

---

## Contributing

Contributions welcome.

1. Fork and create a feature branch
2. Write tests alongside your changes
3. Ensure `go test ./...` passes
4. Submit a PR with a clear description

To add a new check, implement the `checks.Check` interface and register it in `checks.NewRegistry()`.

---

## License

MIT. See [LICENSE](LICENSE).

Built by [Faizan](https://github.com/fayzkk889).
