# MCPSense 0.4.4 release record

The maintainer explicitly requested review, merge, release and updating the existing public information on 1 November 2026. This authorizes the 0.4.4 npm and GitHub/Go publication and static-site update. npm's account-security steps remain controlled by the account holder.

## Review and source identity

Review found no remaining release-blocking defect in the proposed changes. It examined shared context/value handling, original evidence offsets, host-owned credential references, reassignment/redaction, control effects, field enumeration and propagation of analysis limits into execution errors. The documented limitations remain: bounded lexical/relational analysis does not provide general language understanding or runtime authorization. A completed clean assessment remains `not_established`.

[PR #21](https://github.com/fayzkk889/MCPSense/pull/21) is merged. Its reviewed head `a761250a799591164d51b9d7800a2893f50a7d78` and merged/tagged source `7ae44654f6c2e7f6c578437610cd49f65b12ed9d` have identical trees. The annotated `v0.4.4` tag identifies that merged source. Existing user-owned engineering notes were not included.

All 15 PR checks passed before merge in [run 41292701653](https://github.com/fayzkk889/MCPSense/actions/runs/41292701653): Linux/Windows Go 1.22/1.27 tests/race, six npm platform/Node jobs, vulnerability checks, lint, Action contracts, release dry-run and the repository's scan check. The merged-source and tag workflows are checked separately.

The [candidate verification](metadata-trust-verification-2026-11-01.md) preserves the original public audit, intermediate failed evaluation and final artifact identities. Both tested routes passed 718 frozen description observations (TP353/FN0/FP0/TN365), matching outcomes, exits, scores and rule multisets. Live metadata passed TP6/FN0/FP0/TN6 without tool execution; all 12 required-reference journeys, the complete npm user suite, 87 expert checks and six capacity/error journeys passed. Authored/repeated observations are regression evidence, not field accuracy or future zero-miss protection.

## Publication checkpoints

The release workflow is [run 41294901803](https://github.com/fayzkk889/MCPSense/actions/runs/41294901803). Publication, canonical npm identity, public-channel agreement and Cloudflare deployment receipts are recorded below only after verification. The staged website is not deployed before npm/GitHub agree. The separate documentation/site follow-up does not change the tagged executable source or released package bytes.

The release workflow succeeded and GitHub published the non-draft, non-prerelease [0.4.4 release](https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.4) at `2026-11-01T10:03:26Z`. The [merged-source CI](https://github.com/fayzkk889/MCPSense/actions/runs/41294873855) and [static-site check](https://github.com/fayzkk889/MCPSense/actions/runs/41294901843) also passed. The release workflow repeated source/security checks and the installed npm product suite before publishing all five native archives with checksums.

The canonical npm tarball was downloaded from release workflow artifact `npm-candidate-7ae44654f6c2e7f6c578437610cd49f65b12ed9d`, ID `13078828015`. Its integrity, ten-file inventory, runtime checksums, version and unchanged MIT bytes were verified after offline installation on Windows in a path containing spaces. No package source or bytes were rebuilt for publication.

```text
SHA256 975f91bf00b7f022e6d2e40e87d12d8a8696242d216444efe7f3ebacbe9233d4
Integrity sha512-2fsM25eMHk3imxSsoQHbvRApR7f/5VBoYDWI8WPOWS9X+mhb0d154xP80GYJ7eN5TA9UH9aV1VMSaJI+K3oudA==
WASM SHA256 d2fb3440b1d132bd3bf8527153cd8997d2b0c43c42a73e8ba7fb7cfa87084a5a
```

A fresh public Go `@latest` installation with isolated module/build caches and no Node/npm on its PATH resolved 0.4.4. Example creation, offline JSON inspection, baseline capture and required-reference matching passed. That independently installed binary also passed all 718 frozen observations and 12 required-reference journeys. Its SHA256 is `439acb2f0a6245730550b207643284a73efd9e00afb1aecf767d3b0b242ba786`.

The canonical npm installation passed the complete Windows product suite and all 87 expert checks with online public OSV queries enabled for synthetic declarations. It preserves explicit uncertainty/source-conflict evidence without installing or executing the named third-party packages. The final comparison against the public Go binary passed all 718 observations with matching outcomes, exits, scores and rule multisets; the fresh live check passed TP6/FN0/FP0/TN6 without tool execution.

### npm authorization and propagation

The expired publisher session was refreshed through npm's official browser flow. A non-interactive publish correctly refused to proceed without two-factor authentication; the interactive flow then required a separate publication confirmation, completed by the account holder. npm accepted the exact canonical tarball and explicitly reported processing. Immediately afterward, public latest still returned 0.4.3 and the 0.4.4 lookup returned no record. This propagation interval is retained as a staging observation, not counted as final public acceptance. The site remained staged during the disagreement.

### Final public package verification

Public npm latest subsequently resolved 0.4.4 with the exact canonical SHA512 integrity and byte-identical tarball. A fresh anonymous Windows installation with normal install-script policy passed startup, public-version awareness, example creation, offline inspection and refusal to overwrite the existing example. Its installed WASM SHA256 matches the canonical manifest above. `version --check` returned exit 0 and confirmed installed/npm/GitHub agreement at 0.4.4.

The first delivery helper run stopped on its own incorrect process-status property (`exit` instead of Node's `status`); its recorded CLI command had returned 0. Correcting the maintainer-only helper, without changing product bytes or assertions, produced the completed public receipt. This harness error is not recorded as a CLI failure or silently counted as an earlier pass.

The unchanged public archive gate passed on the exact tagged source: candidate tag, npm latest, GitHub latest, all five downloaded archives and their checksums agree. Canonical installed product verification, native/npm parity and public byte equality establish that the tested package is the published package. A separate public smoke check verified delivery and first use of those same bytes.

## Website publication

The existing Cloudflare assets-only `mcpsense` Worker now serves the 0.4.4 snapshot and released changelog at [mcpsense.site](https://mcpsense.site/). Production version `350457f5` was observed **100% Ready**. Previous production `8848580b` remains available for rollback. The project, custom domain and audience are unchanged.

The upload contained only the 20 built static files, 205,270 uncompressed bytes, with `index.html` at the root and preserved subdirectories. Nine website tests passed. Actual public verification passed eight HTML pages, ten byte-exact assets, the original robots rules after Cloudflare's managed prefix, security/cache headers and the custom 404. No repository files, credentials or CLI binaries were uploaded.

The public browser confirmed `Latest stable · v0.4.4`, npm/GitHub agreement and the released 0.4.4 entry. Public changelog and getting-started pages were checked at 390px: one main heading per page, no horizontal overflow, and phone navigation closed after following its link. The normal desktop viewport was restored. Screenshot: ignored `bin/mcpsense-044-live-release.jpg`; public site receipt: `bin/release-044-site-public-receipt.json`.

README now leads with published 0.4.4 and keeps earlier audits in a clearly labelled historical section. Release readiness, the website snapshot/changelog, historical article notices and user-facing GitHub notes identify the current release. The source follow-up changes documentation and static release information only; it does not alter the approved tag, runtime code or published package bytes.

The [machine-readable release receipt](release-0.4.4-2026-11-01-results.json) retains canonical artifact identities, unchanged corpus digests, runtime parity, public delivery and website verification. Detailed local evidence remains under ignored `bin/release-044-*`. These bounded tests do not establish universal detection, runtime authorization or execution of every cross-built architecture. The MIT license and independent npm/Go routes remain unchanged.
