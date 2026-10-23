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
- Preserve two independent install choices: npm downloads verified binaries without Go on Windows/Linux/macOS; Go installation needs no Node.js/npm. The optional standalone PowerShell installer is version-selectable and noninteractive for Go users. Shell installation verifies checksums before replacement and uses a writable user directory by default.
- Detect generic API-key credential names, indirect private-key disclosure and safety-policy overrides. Limit quoted document-query exceptions to tool metadata; preserve agent-instruction scanning and reject appended-directive exemptions.
- Stop treating ordinary “ignore” as character-substitution evasion, preserve explicit user-request override detection, and improve manifest syntax errors and the clean-start example.
- Screen enumerated server instructions, tool/schema text, resource metadata and prompt metadata; fail visibly when inspection limits are exceeded. Reports disclose inspected and unassessed surfaces.
- Combine lexical action/object/scope signals for authority replacement, disclosure, deception, routing, permission bypass and persistent policy changes. Constrained benign context cannot exempt an appended hostile directive.
- Distinguish formatted direct argv from explicit shell evaluation in recognized Go/Python forms, ignore Python comments/docstrings for that check, and avoid a malformed-Go crash. This is not complete language/dataflow analysis.

## Added workflow

- Modern 2026-07-28 `_meta` and HTTP headers, discovery and request-scoped SSE, with supported legacy initialize behavior.
- Stable rule/component fingerprints, explicit review confidence and coverage state in JSON/SARIF.
- Offline before/after verification that refuses changed or incomplete scope.
- A limited 40-description diagnostic corpus, including false-positive and missed-detection examples.
- Hosted Linux/Windows tests on Go 1.22/1.27, a real Action exercise, and publication-disabled five-target release snapshots.
- Recurring compiled-CLI product journeys and installer failure/integrity tests on Linux/Windows.
- A non-overwriting `init --example` offline walkthrough, conventional `--version`, and explicit `version --check` comparison of public GitHub/npm versions.
- Detector fingerprints that reject before/after comparisons across changed or missing scanner identities. This is an equivalence guard, not a report signature.
- Baseline comparisons for server text, tool titles/output schemas/annotations, existing resource metadata and prompt additions/edits. Existing format-2 baselines retain their captured comparisons with an explicit missing-field warning; expanding scope requires a reviewed `--update-baseline`. Drift implementation is included in detector identity.
- Enforced beginner/experienced-user scenarios, four labelled description sets, and live poisoned-instruction checks over legacy and modern discovery.

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

These are metadata/heuristic checks, not exploit verification or a host authorization boundary. Redaction cannot recognize arbitrary secrets; digests are not encryption. The latest 164-case synthetic regression evaluation caught all 82 hostile cases with no alarms on 82 benign cases, and the separate 16-case persona rerun cleared its observed misses/false alarms. These authored, related examples do not estimate field accuracy or establish universal detection. See the [fix and evaluation report](release-blockers-2026-10-23.md) and preserved earlier failing reports.

Runtime outputs, fetched resource contents, prompt bodies and unknown metadata extensions are unassessed. Drift coverage is narrower than metadata screening, source analysis is partial, and unsigned reports are editable. OAuth, deprecated standalone HTTP+SSE GET transport and active exploitation are not implemented. macOS/arm64 cross-builds do not establish runtime correctness. Windows policies/reputation can still block executables. No code-signing, public 0.4.0 release or npm publication has been performed during preparation.
