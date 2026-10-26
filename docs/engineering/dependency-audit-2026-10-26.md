# MCPSense dependency audit — 26 October 2026

## Scope and method

The audited production source is implementation revision 219ce9132eb1173dde9779902a6faa02ff71924e. Release-preparation worktree changes were CI/scripts/documentation only; application Go sources, go.mod and go.sum were unchanged during this audit.

The official Go 1.27.3 Linux toolchain was downloaded from go.dev and checked against SHA256 `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`. It matches the release compiler. Official govulncheck v1.9.0 was installed with Go module verification, and queried https://vuln.go.dev. The reported database modification time was 2026-10-21T00:27:29Z. This is known-vulnerability analysis, not a guarantee against unknown issues.

All source targets were scanned at symbol/call reachability level: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 and js/wasm. Human-readable invocations returned0 on all six. JSON reports were saved for inspection, but their exit 0 was not treated as evidence: govulncheck's structured-output modes return0 even when findings exist.

## Findings and decision

The npm js/wasm target had no advisory finding. Native target analysis reported no reachable affected functions, while retaining an indirect module advisory in golang.org/x/sys v0.25.0. Windows additionally imports the affected package.

[GO-2026-5024 / CVE-2026-39824](https://pkg.go.dev/vuln/GO-2026-5024) concerns unchecked string-length overflow in windows.NewNTUnicodeString, fixed upstream in v0.44.0. Source analysis found no call from MCPSense to that function. A Windows counterpart built without symbol stripping had no affected linked symbol in `go tool nm`; govulncheck binary analysis likewise returned0 with no vulnerable symbol found. Neither Windows audit executable was run.

A stripped counterpart conservatively produced a symbol-level warning and human-readable exit 3. Its raw bytes did not contain the affected symbol name. The unstripped/source checks and linked-symbol inventory were therefore inspected rather than silently treating the stripped scan as clean. The [official checker documentation](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) explains that stripped or unavailable symbol information may cause dependency-wide findings; binary analysis may also over-report unreachable code. Both reports are retained.

The fixed x/sys v0.44.0 declares a Go 1.25 requirement. The module's Go 1.22 compatibility floor is preserved instead of silently changing customer compiler requirements for an uncalled function. This triage does not assert that x/sys v0.25.0 has no advisories. A policy requiring zero module-level advisories, regardless of reachability, would need a separate compatibility decision. No blanket suppression or advisory allowlist was added.

## Preventing regression and stale release evidence

`scripts/audit-go-vulnerabilities.sh` pins the auditor and production compiler, checks all six source targets, then checks a symbol-preserving Windows counterpart. Any reachable vulnerability reported by the checker, or an audit/tool/database failure, fails the gate. It deliberately uses human-readable output for meaningful exit status. The gate runs in CI and refreshes before publication, so future applicable advisories and call changes are checked again rather than relying on today's result.

Raw local evidence is retained under ignored `bin/launch-audit-042-aok4144ijtd/`: toolchain/checker identity, six JSON reports, stdout/stderr, Windows binary reports and linked symbols. Reproducible human-output gate results are in `bin/launch-audit-042-final-gate.log`. Only this small interpretation report is committed; generated tools and executables are not.

This audit does not cover arbitrary MCP-server dependencies, packages a user installs later, unknown vulnerabilities, malicious runtime results or process containment. Those are separate from MCPSense's own release dependency graph. MIT, application dependency versions and independent npm/Go user installation remain unchanged.
