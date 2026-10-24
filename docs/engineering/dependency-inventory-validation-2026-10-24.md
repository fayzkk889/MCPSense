# Explicit npm inventory checkpoint — 24 October 2026

MCPSense now reads a selected npm v2/v3 package-lock or shrinkwrap, including nested versions, aliases with an explicit actual package name, and development/optional entries. This closes the npm declaration-inventory gap identified in the [threat review](../research/2026-10-23-mcp-threat-review.md). It does not attest installed code or complete the remaining runtime protection work.

## Confirmed defect and change

A deterministic test against the previous advisory client returned one advisory and a `next_page_token`, then supplied a second advisory on the next page. The old client made one request and omitted the second advisory. The regression failed before implementation and now passes.

The client follows pagination, deduplicates advisory IDs, rejects page cycles and exceeded limits, and never caches a partial response as complete. Eight workers query distinct identities concurrently; repeated identities retain each original finding location. Cancellation, failed pages and failed stale-cache refreshes fail the scan. Old cache entries are invalidated because their completeness cannot be established. Advisory POST redirects are rejected.

Limits are 4 MiB per input, 10,000 locations, 2,048 distinct advisory identities, a 30-second phase budget, five seconds per request, 32 pages/16 MiB per identity and 64 MiB aggregate response data. These are scanner limits, not resource restrictions on an MCP server.

Inventory selection is explicit: `mcpsense scan package-lock.json`, `--mode dependencies` for a differently named file, or `--dependencies <file>` alongside a project scan. Directory discovery does not silently add lockfile package names to outbound advisory queries. Online queries send recognized package names and exact versions to OSV; offline/no-CVE inspection does not query advisories or use cached results as findings.

The parser bounds nesting and package paths, rejects duplicate JSON keys, and uses exact case-sensitive npm field names. Required references are resolved through nested and hoisted package locations; a missing required entry is explicitly unresolved. Optional omissions and peer installation are not treated as proof of missing required packages. Unsupported/local/private/Git sources and unresolved versions are recorded as unresolved during offline inspection. An incomplete inventory fails online advisory checking before any package query. Registry tarball locations are declarations supplied by the file, not proof of registry integrity, installation or current execution.

## Product validation

The real CLI acceptance harness covers 18 deterministic dependency journeys plus four live public advisory controls. The deterministic journeys use clearly synthetic, isolated cache records to test wiring independently of network availability. They cover first-run auto-detection, expert combined scans, duplicate locations and nested versions, offline behavior, terminal scope text, unsupported identities, missing required entries, range rejection, malformed/oversized input, output/input collision protection, JSON/SARIF provenance and before/after remediation comparison.

Live public OSV queries confirm these specific pairs:

| Package | Version | Advisory | Observed match |
| --- | --- | --- | --- |
| lodash | 4.17.20 | GHSA-35jh-r3h4-6jhm | Yes |
| lodash | 4.17.21 | GHSA-35jh-r3h4-6jhm | No |
| @modelcontextprotocol/sdk | 1.31.0 | GHSA-46jr-4wx8-v453 | Yes |
| @modelcontextprotocol/sdk | 1.32.0 | GHSA-46jr-4wx8-v453 | No |

The lodash 4.17.21 control initially assumed no advisories; the current feed correctly returned three newer ones. The harness was corrected to test the specific advisory boundary instead of treating a historical fix as universally safe. Publisher sources describe the [older lodash fix](https://github.com/advisories/GHSA-35jh-r3h4-6jhm), newer [array-path bypass](https://github.com/lodash/lodash/security/advisories/GHSA-f23m-r3pf-42rh) and [template imports injection](https://github.com/lodash/lodash/security/advisories/GHSA-r5fr-rjxr-66jc).

A separate real npm-generated lockfile contains **96 package locations**, including SDK 1.31.0 and an alias of SDK 1.32.0. All 96 identities resolved; online lookup completed with four advisory findings, including the input-element-limit advisory for 1.31.0. The alias retained its actual SDK package identity and 1.32.0 version. Generation used package-lock-only/ignore-scripts; no node_modules directory was created. No vulnerable package code or exploit was executed.

Local full Go tests and vet pass. Parser fuzzing and the existing product/persona/baseline/packaging suites were also run; hosted Windows/Linux Go 1.22/1.27 gates provide native execution, race tests, installer tests and unpublished release builds. The dependency journey is now part of each hosted matrix job. CI results must be checked on the final commit before merging.

Local receipts are retained under ignored `bin/dependency-*` and `bin/real-npm-inventory/`; they include binary hashes, invocations and reports. Declared-input hashes are unsigned evidence, not authenticity guarantees. Remediation comparison permits version upgrades in the same declared scope; deleting packages or changing their identity/location changes coverage and is rejected.

## Remaining priorities and release boundary

1. Verify effective security settings using deployment evidence. The [SDK input-element advisory](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-46jr-4wx8-v453) requires opt-in limits after upgrading; the [audience-validation advisory](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-rvq5-wwqv-78pq) requires both middleware and token-verifier changes. A lockfile cannot prove either setting is active.
2. Add enforceable runtime policy and per-principal isolation with explicit trust boundaries. A metadata scanner or protocol proxy alone cannot restrict a server's operating-system permissions, database privileges or outbound network access.
3. Add runtime body/element/concurrency/time limits and data-flow controls, with negative tests proving each enforcement point. Tool allowlists alone cannot stop an allowed sensitive read followed by an allowed public write.
4. Expand beyond the selected npm lockfile to other dependency formats, SBOMs and deployed inventories. `package.json` ranges remain declarations rather than resolved installed versions.

MIT is preserved. Independent npm and Go installation routes are unchanged. No tag, public GitHub release or npm publication is authorized by this checkpoint. Signing approval and a protected-Windows retest remain required before public release.

## Format references

- [npm package-lock format and source semantics](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/)
- [OSV query and pagination contract](https://google.github.io/osv.dev/post-v1-query/)
