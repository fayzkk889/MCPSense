# Release readiness — proposed 0.4.0

## Superseding persona retest

The [beginner/expert retest](persona-retest-2026-10-23.md) on main5f94d78 found eight new hostile paraphrases missed, four benign false alarms in16 stress descriptions, five unexamined metadata-field probes, safe argv source called critical injection, and public npm-only Windows installation still failing on0.3.0. These are corroborated Windows/Linux observations, not a field-accuracy estimate. **Broad-release acceptance remains blocked despite green engineering CI and the earlier140-case results.** Read that report before interpreting the historical checkpoints below.

## Current product acceptance — 23 October 2026

The follow-up [PR7](https://github.com/fayzkk889/MCPSense/pull/7) contains the pushed detection, config evidence, detector-identity verification and onboarding fixes. See its current checks for the authoritative final matrix. The [improvement report](product-improvements-2026-10-23.md) supersedes the pre-fix verdict: the final local evaluation caught all70 hostile descriptions across140 labelled cases, with two benign false alarms confined to the separate40-case validation set. All24 expanded product assertions passed. These are small authored examples, not field accuracy or universal protection. Public channel/package availability remains a separate gate.

The paragraphs below preserve the earlier pre-fix and PR3 checkpoints; their branch/merge statements are historical rather than current delivery status.

PRs3–6 are merged; main `dfdefd7c289a1b8fdc6522e40c21bbf107ec8c1c` passed all seven jobs in [CI39831488309](https://github.com/fayzkk889/MCPSense/actions/runs/39831488309). npm and Go candidate installation routes work independently. Public latest is still0.3.0; no0.4 publication is approved.

**Engineering CI is green; broad product-security acceptance is not.** A [fresh user-level evaluation](product-acceptance-2026-10-23.md) passed the core workflow but found substantial misses/false alarms on new descriptions and reproduced an unsupported critical injection finding for literal argv. Across all security rules, the new60-case set caught16/30 hostile descriptions and falsely flagged9/30 benign ones. Two hostile cases scored100. Address these findings and re-evaluate before broad security promotion. The detailed sections below preserve the earlier PR3 engineering checkpoint and must not be read as current merge status or full product approval.

## Delivery

- Feature branch: `codex/security-evidence-hardening`.
- [Pull request #3](https://github.com/fayzkk889/MCPSense/pull/3), prepared for review; main is unchanged.
- Proposed version: **0.4.0**, because protocol/evidence capabilities and documented safety compatibility changes go beyond a patch. npm metadata is prepared, not published.
- MIT and module minimum Go 1.22 are preserved. Production release workflow is pinned to Go 1.27.3 and GoReleaser 2.18.3; minimum-version testing does not force old-toolchain production builds.

## Executed evidence

User independently verified the original Windows baseline. Agent-executed implementation checks include full Windows tests/race/vet/module verification at an implementation checkpoint, full Linux Go 1.22.12 tests/vet/module verification, Node Action/package tests, npm pack dry run without lifecycle scripts, and a successful synthetic finding → remediation → verification demonstration.

Windows Application Control intermittently rejects generated executables even outside the sandbox; the final local Windows rerun stopped at that environmental block. Earlier full native and hosted Windows runs passed. Do not represent the blocked rerun as a pass. Hosted Linux/Windows Go 1.22/1.27 tests, lint and real Action execution all passed on initial pushed code `57cc2cc`. Current commit status and artifacts are authoritative in [PR checks](https://github.com/fayzkk889/MCPSense/pull/3/checks).

The existing GoReleaser configuration passed `goreleaser check`. A local `release --snapshot --skip=publish,announce,sign,sbom` run built all configured targets, produced five archives and verified all five SHA-256 entries. The Linux binary completed the offline remediation demo. That first local snapshot was generated from a development working tree and inherited a historical `v0` tag label; it is not a public release or a reproducible provenance attestation.

CI additionally builds a fresh, publication-disabled snapshot with `GORELEASER_CURRENT_TAG=v0.4.0`, using Go 1.27.3. This environment override labels artifacts; it does not create or push a tag. The job verifies checksums, CLI startup and the remediation demo, then uploads a seven-day CI artifact keyed to the exact commit. Inspect the final job before approving a release. No snapshot binary should be presented as a signed public release.

## Target status

| Target | Evidence |
| --- | --- |
| Linux amd64 | Native Go 1.22 tests and demo; hosted 1.22/1.27 tests/race and snapshot startup |
| Windows amd64 | Native focused/full checkpoint tests; hosted 1.22/1.27 tests/race; npm wrapper smoke test in updated CI |
| Linux arm64 | GoReleaser cross-build/archive; runtime not exercised locally |
| macOS amd64 | GoReleaser cross-build/archive; runtime not exercised locally |
| macOS arm64 | GoReleaser cross-build/archive; runtime not exercised locally |

## Remaining limitations

- Heuristics and inferred package references can miss threats or flag benign content. Forty authored descriptions are not independent field validation.
- Modern support covers metadata discovery, not full client/OAuth conformance, active probes or deprecated standalone HTTP+SSE transport.
- Snapshot digests can reveal low-entropy values through guessing; arbitrary secrets cannot be guaranteed redacted. Old plaintext copies need user retention review.
- Process cleanup is best effort, not containment of malicious code. Local execution remains an explicit opt-in.
- Ambiguous multi-manifest/duplicate-server config projects must be scanned separately; excluded extensions/dependency directories remain outside coverage.
- Server instructions and prompt argument/content semantics do not have comprehensive security or drift analysis. No clean-health claim follows from enumeration alone.
- Windows ACLs, external commercial demand, complete incident research/vendor corroboration and bit-for-bit reproducibility are not established.
- No verified signing infrastructure or website source/deployment exists in this checkout.

## Approval boundary

No merge, version tag, GitHub release or npm publication occurred. The tag-triggered release workflow would publish if a version tag were pushed, so **do not push one without explicit maintainer approval**. After review and green final checks, obtain approval for the exact commit, version and publication process; then verify public artifact/checksum URLs and npm package contents. Until then, this is a tested contribution and release preparation, not a completed public release.

Final review also requires the same approved-baseline digest when drift evidence is compared. Reapproval is a policy change, not a remediation. Schema digests preserve arbitrary JSON numeric constraints without float rounding, and Unicode offset tests include dotted-I compatibility. These are covered by focused regressions.
