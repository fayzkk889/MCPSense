# 0.4.0

This minor release adds modern MCP metadata discovery, explicit coverage and offline report comparison alongside security hardening. It preserves MIT licensing and the existing GoReleaser distribution targets. Module minimum remains Go 1.22; release builds use Go 1.27.3.

## Security and correctness

- Match original Unicode bytes instead of slicing original text using case-converted offsets.
- Minimize snapshot metadata, remove raw drift diffs, and redact recognized/known sensitive report values.
- Propagate discovery, malformed input, advisory and baseline errors; distinguish execution errors from findings.
- Enforce offline behavior, local-execution opt-in, guarded destination policy, bounded reads/catalogs and best-effort process cleanup.
- Reject unknown rule IDs and omitted/ambiguous directory coverage.
- Pass GitHub Action inputs as data; validate JSON, status and SARIF from one scan; verify downloaded archives.
- Restore the missing npm executable wrapper, avoid shell interpolation in the installer, and verify archive checksums.
- Make the standalone Windows installer source-only, version-selectable and noninteractive; require Go explicitly. Linux/macOS installation verifies checksums before replacing the executable and uses a writable user directory by default.
- Detect generic API-key credential names, indirect private-key disclosure and safety-policy overrides. Limit quoted document-query exceptions to tool metadata; preserve agent-instruction scanning and reject appended-directive exemptions.
- Stop treating ordinary “ignore” as character-substitution evasion, preserve explicit user-request override detection, and improve manifest syntax errors and the clean-start example.

## Added workflow

- Modern 2026-07-28 `_meta` and HTTP headers, discovery and request-scoped SSE, with supported legacy initialize behavior.
- Stable rule/component fingerprints, explicit review confidence and coverage state in JSON/SARIF.
- Offline before/after verification that refuses changed or incomplete scope.
- A limited 40-description diagnostic corpus, including false-positive and missed-detection examples.
- Hosted Linux/Windows tests on Go 1.22/1.27, a real Action exercise, and publication-disabled five-target release snapshots.
- Recurring compiled-CLI product journeys and installer failure/integrity tests on Linux/Windows.

## Compatibility changes

- Snapshot format 2 rejects old plaintext snapshots; review and recreate explicitly. Old copies are not deleted automatically.
- Exit 1 means completed high/critical findings; exit 2 means execution/policy/configuration failure.
- `--offline` rejects all live activity and local server execution. Local startup requires `--allow-exec`.
- Private/loopback live targets require `--allow-private-network`. Redirects, URL userinfo/fragments and link-local/metadata ranges are blocked; live HTTP bypasses environment proxies.
- Directory auto mode combines source/config/skill discovery. Malformed/unreadable candidates, multiple manifests or duplicate config server names require explicit review/separate scans.
- Unknown rule IDs, conflicting rule filters, malformed project config, invalid enums and unsafe output/baseline collisions now fail.
- `--probe` fails explicitly; raw `--show-diff` content is unavailable.
- The Action defaults to building its trusted source revision. Downloaded versions require schema 2 and the new error semantics; `fail-on: none` never suppresses execution failure.

## Limits

These are metadata/heuristic checks, not exploit verification. Redaction cannot recognize arbitrary secrets; digests are not encryption. The diagnostic corpus is authored and small (precision 0.7727, recall 0.8500 in the measured run), not an independent estimate of field accuracy. OAuth, deprecated standalone HTTP+SSE GET transport and active exploitation are not implemented. macOS/arm64 cross-builds do not establish runtime correctness. No code-signing, public release or npm publication has been performed.
