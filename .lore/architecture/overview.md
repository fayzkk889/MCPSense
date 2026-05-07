# System Architecture Overview

MCPSense is structured as a modular Go application with a focus on scanning MCP servers through different methods and producing categorized security, spec compliance, and tool quality reports.

## Core Architecture

1. **CLI Entrypoint ([[cmd/mcpsense]])**
   - Parses CLI input and invokes scan operations.

2. **Scanner ([[internal/scanner]])**
   - Orchestrates scans in three modes:
     - **Manifest**: Reads MCP manifest JSON files ([[internal/scanner/manifest.go]]).
     - **Static**: Performs static source analysis by discovering files ([[internal/utils/files.go]]) and parsing code contents.
     - **Live**: Connects to a running MCP server over stdio or SSE ([[internal/scanner/live.go]]).
   - Populates a [[internal/checks.ScanContext]] with manifest data and source files.

3. **Checks ([[internal/checks]])**
   - Defines checks implementing the Check interface, grouped as:
     - Security checks ([[internal/checks/security.go]]): e.g., injection detection.
     - Spec compliance ([[internal/checks/spec_compliance.go]]): validation against MCP specs.
     - Tool quality ([[internal/checks/tool_quality.go]]): e.g., description clarity.
   - Checks use pattern matching from [[internal/detection]], which contains regex-based detection engines loaded with known attack signatures.

4. **Data Models ([[internal/models]])**
   - Define core representations: MCP manifests, findinds ([[Finding]]), severity levels, and aggregate [[Report]].

5. **Reporting ([[internal/report]])**
   - Provides output formats:
     - CLI reporter with color highlighting.
     - JSON reporter for automated consumption.

## Data Flow

- The CLI triggers a scan via [[internal/scanner.Scanner]].
- Scanner loads input (manifest, source files, or live server).
- Builds a [[ScanContext]] passed to [[internal/checks.Registry]].
- Registry runs all registered [[Check]] implementations.
- Checks produce [[Finding]] results collected into a [[Report]].
- Reporter serializes the [[Report]] to stdout or file.

## Entry Points

- `main.go` invokes `scanner.Scan()` with CLI arguments.
- Scanner coordinates with checks and detection engines.
- Reporting interfaces consume the result report.

## Dependencies

- cobra for CLI commands
- Github.com/fatih/color for CLI colors
- testify for unit testing

[inferred]