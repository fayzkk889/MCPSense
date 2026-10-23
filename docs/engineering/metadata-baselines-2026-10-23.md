# Expanded baseline comparisons

The prerelease review reproduced nine silent baseline misses on main `3372446`: changing a server description, server instructions, tool title, output schema, annotation title, existing resource description, prompt description or prompt arguments, or adding a prompt produced no drift finding. The reproduction is committed independently in `internal/drift/metadata_test.go`.

The [MCP schema reference](https://modelcontextprotocol.io/specification/2025-11-25/schema) defines server instructions, output schemas, annotations and prompt metadata as distinct surfaces. MCPSense already screens the represented text for hostile patterns; preserving digests for subsequent comparisons closes a separate workflow gap. A benign edit also produces drift: these findings request review rather than prove hostility.

## Implementation and compatibility

- `DRIFT-008`: changed annotations, except read-only weakening retains the existing `DRIFT-004` alone.
- `DRIFT-009`: changed metadata of an existing resource.
- `DRIFT-010`: changed tool title or output schema.
- `DRIFT-011`: changed server description or instructions.
- `DRIFT-012`: new prompt metadata.
- `DRIFT-013`: changed description or arguments of an existing prompt.

New snapshots retain format 2 and add `metadata.version: 1`. Old format-2 baselines continue comparing the hashes they actually contain, including annotation/resource hashes. They cannot reconstruct missing historical server text, titles, output schemas or prompts. Reports explicitly describe that limited scope and direct the maintainer to review the target before explicitly updating the baseline. No comparison writes or upgrades the approved file. Unknown extension versions fail rather than silently dropping coverage.

JSON and SARIF contain identical baseline fields and warnings. Verification already requires identical coverage and baseline identities; new tests guard the added scope fields. Drift production sources now participate in detector identity so changing the comparison implementation cannot masquerade as remediation. Snapshot hashes exclude raw metadata and environment values; digests remain susceptible to guessing and are not encryption.

## Verification

The nine regression cases failed before the fix and pass after it. Local Linux Go 1.22 full tests and vet pass. The real CLI passes 14 saved-baseline acceptance assertions covering all nine edit cases, consistent JSON/SARIF results, unchanged and repeated scans, legacy warnings in terminal output, unchanged baseline bytes, explicit approval, refused verification across changed scope, and future-extension rejection. Privacy, exact large-integer constraints, JSON key/whitespace canonicalization, config-only scope and existing read-only behavior have focused regression checks.

`scripts/baseline-acceptance.mjs` is enforced alongside the existing user/installer/live journeys in every Windows/Linux Go 1.22/1.27 CI matrix. Its invocation records are kept under the ignored `bin/` directory when run locally. The baseline test is independent of hostile-description classification; no new classifier accuracy claim follows from these results.

The existing local product rerun passes all 24 assertions and all 164 labelled description cases (82 TP, 82 TN, no observed misses or false alarms); the beginner/experienced-user rerun passes with 8 TP and 8 TN across its 16 descriptions. These related authored data sets are regression checks, not field-accuracy estimates. Packaging/Action checks pass (12 tests, one native-binary test deferred to CI). Local race testing cannot start because this Linux environment lacks a C compiler; the full race suite remains required in hosted CI.

## Windows installer failure found by CI

The first CI run, [39994734006](https://github.com/fayzkk889/MCPSense/actions/runs/39994734006), passed both Linux matrices, Windows Go 1.22, lint and the Action. Windows Go 1.27 failed in the real npm installer with `EBUSY` removing the staged executable. The immediate cleanup exception masked any preceding failure, so the log alone does not identify the lock owner or prove which installation operation failed first.

The installer now retries the same atomic rename for bounded transient file-access errors and uses bounded cleanup retries documented by [Node's filesystem API](https://nodejs.org/api/fs.html#fsrmsyncpath-options). It never deletes the previous executable to force replacement. Persistent failures still fail installation, and a cleanup failure preserves the original installation error. The declared Node minimum is corrected to 14.14, when the already-used `rmSync` API became available. The smoke harness also retries cleanup of its own temporary directory. Simulated transient/permanent locks, prior-installation preservation, and primary-error preservation are tested. All 14 local packaging/Action tests pass, with one native wrapper test deferred to hosted CI. This is separate from the Smart App Control signing blocker; no protection settings or trust requirements are changed.

## Remaining scope and release gate

Removed tools/resources/prompts, added/removed client server entries, environment values, runtime outputs, resource contents, prompt bodies and unknown fields remain outside these comparisons. Input/baseline size limits remain enforced. This change does not solve executable trust: SignPath has acknowledged the application but has not approved signing access. Windows protected-device installation still requires trusted signing and a fresh retest. No public release, tag or npm publication is authorized or performed here.
