# MCPSense 0.4.3 release record

The maintainer requested that all remaining work and tests be completed and the release published on 30 October 2026. This authorizes preparing, merging and publishing the tested follow-up; npm still requires its account-security confirmation when requested.

## Remaining blocker resolution

The historical expert audit's 0.5.143 control required absence of the Tensorlake feed advisory. The publisher says that exact version is unaffected by the 0.5.144 compromise, while OSV still reports it. Silently hiding a feed warning or presenting it as established applicability would both mislead users.

The release therefore adds an explicit `advisory` object to dependency findings: `id`, `applicability`, `feed_url` and, for the exact reviewed disagreement, `reviewed_url`, `reviewed_at` and `review_note`. `conflicting_sources` keeps both sources, `unresolved_applicability` confidence, the original severity and the review-required security assessment. The CLI title and explanation explicitly say conflict. JSON and SARIF preserve this evidence and redact credentials without mutating the original report.

The review is limited to npm `tensorlake@0.5.143` and `MAL-2026-17650` / its known GHSA alias. Other packages, ecosystems, versions, unknown versions, new advisories and the compromised 0.5.144 are not exempted. Tests cover these exclusions. The feed itself is not changed. Snapshot provenance is the publisher page rechecked on 30 October.

The expert harness now requires an accurate match on 0.5.144 and explicit high-severity disagreement evidence on 0.5.143 if the feed still returns that advisory. It also accepts a future corrected feed with no such match on 0.5.143. This is a documented product behavior change, not relabelling the historical audit or disabling its detection criteria. Original hostile/benign labels and historical failed results remain unchanged.

## Verification and publication checkpoints

Preparation is in PR #19. Full source tests pass locally after the applicability fix. Final version-specific native/npm, onboarding, online expert, hosted matrices, canonical artifact identity and publication receipts will be added once complete. No pending check is implied to have passed by this preparation record.

The npm and GitHub/Go releases must identify 0.4.3 before the website advertises it as stable. A source push alone does not publish a package. The unchanged MIT license and independent installation routes remain release requirements.
