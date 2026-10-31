# MCPSense 0.4.3 release record

The maintainer requested that all remaining work and tests be completed and the release published on 30 October 2026. This authorizes preparing, merging and publishing the tested follow-up; npm still requires its account-security confirmation when requested.

## Remaining blocker resolution

The historical expert audit's 0.5.143 control required absence of the Tensorlake feed advisory. The publisher says that exact version is unaffected by the 0.5.144 compromise, while OSV still reports it. Silently hiding a feed warning or presenting it as established applicability would both mislead users.

The release therefore adds an explicit `advisory` object to dependency findings: `id`, `applicability`, `feed_url` and, for the exact reviewed disagreement, `reviewed_url`, `reviewed_at` and `review_note`. `conflicting_sources` keeps both sources, `unresolved_applicability` confidence, the original severity and the review-required security assessment. The CLI title and explanation explicitly say conflict. JSON and SARIF preserve this evidence and redact credentials without mutating the original report.

The review is limited to npm `tensorlake@0.5.143` and `MAL-2026-17650` / its known GHSA alias. Other packages, ecosystems, versions, unknown versions, new advisories and the compromised 0.5.144 are not exempted. Tests cover these exclusions. The feed itself is not changed. Snapshot provenance is the publisher page rechecked on 30 October.

The expert harness now requires an accurate match on 0.5.144 and explicit high-severity disagreement evidence on 0.5.143 if the feed still returns that advisory. It also accepts a future corrected feed with no such match on 0.5.143. This is a documented product behavior change, not relabelling the historical audit or disabling its detection criteria. Original hostile/benign labels and historical failed results remain unchanged.

## Verification and publication checkpoints

[PR #19](https://github.com/fayzkk889/MCPSense/pull/19) is merged. Its tested head `7a373d348cb90ad44759beb33e760f47fb7388e4` and merged/tagged source `09f8022f300880244c4f91a961fbd59c243506c9` have identical trees. The annotated `v0.4.3` tag identifies that merged source.

- All 17 PR checks and all 17 merged-source checks passed. [Main CI](https://github.com/fayzkk889/MCPSense/actions/runs/41104927173) and the [release workflow](https://github.com/fayzkk889/MCPSense/actions/runs/41104993835) succeeded.
- Source tests passed with Go 1.27.3 and the Go 1.22 compatibility floor. Vet, installer/Action contracts, website tests and the official six-target vulnerability audit passed. The documented uncalled x/sys advisory remains visible; this is not a claim that dependencies have no advisories.
- The release workflow repeated its source/security checks and actual installed npm product suite before publishing the five native archives. The [GitHub/Go release](https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.3) became public at `2026-10-30T18:17:45Z`.
- A fresh public Go `@latest` installation with empty build/module caches and no Node/npm on PATH resolved 0.4.3. Example creation, offline JSON inspection, baseline capture and required-reference matching passed. The actual public binary also passed all 232 frozen description observations and 12 required-reference journeys.
- The canonical npm tarball came from successful release workflow artifact `npm-candidate-09f8022f300880244c4f91a961fbd59c243506c9`, ID `13000004457`. It contains ten files, the bundled WebAssembly engine and matching runtime, with no install hooks or MCPSense native executable. MIT bytes and component hashes were verified.

```text
SHA256 01011c7f1f81361943619cf21f0c61b96d2884f3a3bc63faf67a5ac66d64198c
Integrity sha512-cg6MEf1bT5csGYC9cNRXI/9u7/sclnKagkn5zOD9+buEFKrhfG4dQLORb+N7als99ZsSzlXmu/A7ZCMSwkUxsw==
WASM SHA256 3f408c15b0533160e1899bc3fa84c2d8aea8c4c41f9380e8258584b203a899b9
```

The exact canonical tarball passed the complete Windows installed-product suite and all 87 online expert checks. These cover reports, privacy, supported inventory, offline/live permission boundaries, configuration errors and source applicability, as well as all 232 frozen observations and 12 metadata-reference journeys. Anonymous installation and upgrade from public 0.4.2 passed in paths containing spaces with Go and archive tools absent. These are authored regressions and bounded workflows, not a field-accuracy estimate or universal protection guarantee. Cross-built archives are not evidence that every architecture was executed locally.

### Staged publication observations

The first canonical onboarding run occurred after GitHub became 0.4.3 while npm remained 0.4.2. `version --check` correctly returned exit 2 for release-channel disagreement. The initial failed run is preserved. A separate staging run explicitly expected that disagreement and passed the other onboarding/upgrade checks; it is not evidence of final public channel agreement. A mistakenly started fallback product run was stopped and excluded from canonical acceptance; the corrected run asserted the canonical installation source and passed in full.

At the start of the continuation on 31 October, npm still served 0.4.2 and its publisher login had expired overnight. The maintainer completed the refreshed official sign-in and separate publication confirmation. npm accepted the canonical upload, then briefly reported processing while the public endpoints still returned 0.4.2 / no 0.4.3 record. The public registry subsequently served 0.4.3 with exactly the canonical integrity above. Neither the staging mismatch nor the processing interval was counted as final public acceptance.

### Final public verification — 31 October

The actual public npm tarball SHA256 and SHA512 integrity match the release-workflow artifact byte for byte. Its freshly installed runtime manifest also matches the canonical receipt. Anonymous public `mcpsense@latest` installation and upgrade from 0.4.2 passed all 13 onboarding checks on Windows, including paths with spaces, no Go or archive utility, preserved existing files and actionable input errors. With the staging override absent, `version --check` returned exit 0 and confirmed installed/npm/GitHub agreement at 0.4.3.

The unchanged public release gate ran from the exact tagged source and passed: tag, GitHub latest, npm latest and all five actual downloaded native archives/checksums agree. The public Go installation described above also resolved that version. No released package bytes were rebuilt or changed during the website/documentation follow-up.

The newly installed public npm CLI also passed all 87 expert checks, with online advisory lookup explicitly enabled. This repeated the affected-version and exact source-conflict controls against the public distribution, using synthetic declarations without installing or executing the named third-party packages.

## Website publication — 31 October

The existing Cloudflare assets-only Worker `mcpsense` now serves the 0.4.3 snapshot and released changelog at [mcpsense.site](https://mcpsense.site/). Its custom domain and audience are unchanged. Production version `8848580b` was observed **100% Ready**; prior production `1d1c567d` remains available for rollback.

The upload contained only the 20 built static files, 203,733 bytes uncompressed, with root `index.html` and preserved subdirectories. Nine website tests passed before upload. Actual public verification passed for all eight HTML pages, ten byte-exact assets, the site's original robots rules after Cloudflare's managed prefix, security/cache headers and the genuine custom 404. Repository files, credentials and CLI binaries were not uploaded.

The public browser confirmed npm/GitHub agreement and `Latest stable · v0.4.3`, a released 0.4.3 entry and no candidate. The changelog and getting-started guide were checked at a 390px phone width, and the changelog at 1280px: one main heading and no horizontal overflow. Phone navigation opened and closed on navigation. The copy control displayed success feedback, but the automation clipboard reader returned an empty value, so a clipboard-paste attestation is not claimed. Commands remain visible and selectable. A local preview initially timed out; it loaded after restarting the owned server with browser connectivity, before upload.

Website receipts: `bin/release-043-site-public-receipt.json` and `bin/mcpsense-043-live-release.png`. The source follow-up changes release information and records only; published CLI/package bytes remain unchanged.

Raw local evidence is retained under ignored `bin/`: `release-043-canonical-receipt.json`, `release-043-canonical-verified-product.log`, `release-043-canonical-expert.log`, `release-043-canonical-onboarding.log`, `release-043-canonical-channel-window.log`, `release-043-public-onboarding.log`, `release-043-public-npm-receipt.json`, `release-043-public-artifacts.log`, `release-043-public-native-receipt.json`, `release-043-public-go.log`, `release-043-public-go-boundary.log`, `release-043-go122.log`, `release-043-vet.log` and `release-043-vulnerability.log`. Credentials, binaries and user-owned engineering notes are not committed.

The npm and GitHub/Go releases must identify 0.4.3 before the website advertises it as stable. A source push alone does not publish a package. The unchanged MIT license and independent installation routes remain release requirements.
