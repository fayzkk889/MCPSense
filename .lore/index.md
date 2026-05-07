# MCPSense Project Overview

MCPSense is a security scanner for MCP (Model Context Protocol) servers, designed to detect security vulnerabilities, spec compliance issues, and tool quality problems before deployment.

## Major Components

- [[cmd/mcpsense]] - CLI executable entrypoint for mcpsense.
- [[internal/checks]] - Security, Spec Compliance, and Quality checks implementation.
- [[internal/detection]] - Pattern detection engine and predefined attack vectors.
- [[internal/models]] - Data models representing MCP manifests, findings, severities, and reports.
- [[internal/report]] - Reporting module emitting CLI and JSON format outputs.
- [[internal/scanner]] - Core scanning logic supporting manifest, static, and live scan modes.
- [[internal/utils]] - Utility helpers including file discovery and logging.

## Technology Stack

- Language: Go (>=1.22)
- CLI Framework: cobra
- Testing: testify
- CI: GitHub Actions
- Release: GoReleaser

[inferred]