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

As of the continuation on 31 October, npm still serves 0.4.2. Its publisher login expired overnight; a new official login is pending. No pending npm publication, public npm installation or website deployment is implied to have passed by this record. The website must continue to distinguish the release channels until publication and fresh public verification succeed.

Raw local evidence is retained under ignored `bin/`: `release-043-canonical-receipt.json`, `release-043-canonical-verified-product.log`, `release-043-canonical-expert.log`, `release-043-canonical-onboarding.log`, `release-043-canonical-channel-window.log`, `release-043-public-go.log`, `release-043-public-go-boundary.log`, `release-043-go122.log`, `release-043-vet.log` and `release-043-vulnerability.log`. Credentials, binaries and user-owned engineering notes are not committed.

The npm and GitHub/Go releases must identify 0.4.3 before the website advertises it as stable. A source push alone does not publish a package. The unchanged MIT license and independent installation routes remain release requirements.
