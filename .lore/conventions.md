# Coding and Project Conventions

## Naming Conventions

- Go standard camelCase for variable and function names.
- Package names are lowercase, no underscores.
- Struct types use PascalCase.
- Check IDs follow UPPERCASE-dash-number format (e.g., "SEC-001", "SPEC-001", "QUAL-001").
- Severity constants use PascalCase with "Severity" prefix.

## Folder Structure

- `cmd/` contains CLI binaries. Each subfolder represents a command binary.
- `internal/` holds all internal packages:
  - `checks/` - implementations of security/spec/quality checks.
  - `detection/` - pattern engines and regex rules for attack vector detection.
  - `models/` - data structures for manifests, findings, severities.
  - `report/` - reporting formats for output.
  - `scanner/` - scanning logic supporting multiple scan modes.
  - `utils/` - helper utilities like file discovery and logging.
- `testdata/` contains example manifests and server code used for tests.

## Imports and Module Organization

- Internal package imports use full module path, e.g. `github.com/fayzkk889/MCPSense/internal/...`.
- External dependencies include:
  - `github.com/spf13/cobra` for CLI
  - `github.com/fatih/color` for terminal color
  - `github.com/stretchr/testify` for tests

## Formatting and Linting

- Uses standard `gofmt` formatting.
- CI workflow runs `go mod tidy` and `go test -cover` for validation.
- GoReleaser configurations confirm build and distribution settings.

[inferred]