# Release readiness — 0.4.2 published

**Subsequent product audit:** the [27 October fresh audit](product-audit-2026-10-27.md) reproduces new hostile-description misses, benign false alarms and an upstream advisory-applicability conflict in public 0.4.2. The installation/release receipts below remain historical delivery evidence; they do not establish broad security acceptance. This audit branch adds a failing 168-observation gate for a future fix. No follow-up release is approved by this document.

Updated 27 October 2026. The maintainer approved PRs 17 and 16 and npm/GitHub/Go publication after checks. Both PRs are merged; public npm latest, GitHub latest and a fresh Go @latest installation now deliver **0.4.2**. The tagged source is 14a8b957d90fbd321c20f09fbcd7e3178df68031.

The [public release record](release-0.4.2-2026-10-27.md) contains artifact identities, test scope, retained propagation failures and the deployed website receipt. [Final main CI](https://github.com/fayzkk889/MCPSense/actions/runs/40452217107) passed all 14 jobs; the [publication workflow](https://github.com/fayzkk889/MCPSense/actions/runs/40452848413) passed its repeated audit and product gates. The public archive/checksum gate also passed.

| Customer requirement | Current evidence |
| --- | --- |
| npm installation without Go | Actual public package: fresh anonymous Windows install, upgrade from 0.4.1 and 13 onboarding checks passed; no Go/archive tools on PATH; Node.js 22+ only |
| Independent Go installation without Node/npm | Fresh public Go @latest install and first-use/reference/version checks passed on Linux without Node/npm; native Windows/Linux source matrices passed in CI |
| Product workflows and original misses | Complete actual public npm product suite passed, including 104 authored boundary observations and 12 required-reference workflows; no labels or assertions relaxed |
| Published versions and package identity | npm/GitHub/Go identify 0.4.2; actual npm download matches the tested final-main artifact; all five public native archive checksums verified |
| Website and current onboarding | Existing Cloudflare site updated to 0.4.2; eight public pages, static assets, headers and 404 verified; updated phone/desktop guides checked |
| Licensing and delivery format | MIT preserved, bundled Go runtime license/integrity verified; npm and Go remain independent |

MCPSense remains a local inspection tool, not universal attack prevention or runtime authorization. Authored regression results are not field accuracy. Operators review/protect initial metadata references; unknown wording, runtime results and unsupported surfaces remain outside the guarantee. Optional Windows native archives remain unsigned and may be restricted by device policy. No protection setting was changed.

The [dependency audit](dependency-audit-2026-10-26.md) retains the indirect x/sys advisory and its non-reachable-symbol triage. Final CI and publication refreshed the six source-target and symbol-preserving Windows audits. The Go 1.22 compatibility floor is unchanged; use a current patched compiler. Every native architecture was not executed locally.

<details>
<summary>Historical release preparation — superseded; not the current delivery state</summary>

# Release readiness — 0.4.2 candidate

Updated 26 October 2026. Publication is on hold while the maintainer makes over the Cloudflare website. No 0.4.2 tag, npm upload or public release has been created. PR 16 remains the review boundary; this document does not authorize merging or publishing.

## Release contract and current delivery

MCPSense is a local inspection tool for recognized MCP metadata/configurations, supported source/skill files and explicitly selected dependency inventories. It provides findings and an optional deterministic metadata-reference check. It does not promise that every hostile description is detected or that any MCP server is protected from every historical/future attack. Runtime permissions, initial trust decisions, unknown extensions and tool-result contents remain outside this CLI's guarantees.

Public npm/GitHub latest is 0.4.1. The tested fix candidate is 0.4.2. A source push does not update public package installation. Until 0.4.2 is approved and verified after publication, do not advertise its fixes as available through @latest.

## Customer requirements and evidence

| Requirement | Evidence/status |
| --- | --- |
| npm installation without Go or an MCPSense executable | PASS: actual candidate install/upgrade; Node.js 22+ only, no install hooks or executable download |
| Independent Go installation without Node/npm | PASS: native Windows/Linux Go 1.22/1.27 CI; Go 1.22 is a language-compatibility floor, use a current patched compiler |
| First-user onboarding, spaces, errors and upgrade from public 0.4.1 | PASS: 13 normal anonymous Windows command journeys on the tested tarball |
| Scan, explain, fix, rescan, compare and export | PASS: complete installed-package suite, including JSON/SARIF agreement and detector-identity verification |
| Local-process/network permissions, offline behavior and privacy checks | PASS in controlled workflows; authorized processes are not sandboxed |
| Reproduced hostile-description misses | PASS in candidate: 104 strict original/validation observations, TP52/FN0/FP0/TN52; 232 texts also receive fast case/prefix tests |
| Unknown changes cannot rely on classifier wording | PASS: 12 optional required-metadata-baseline journeys; reference must be reviewed/protected externally |
| Cross-platform package behavior | PASS: Windows/Linux/macOS with Node 22/24; native Windows/Linux matrices and five-target archive snapshot |
| Every native architecture executed | NOT ESTABLISHED: cross-building/checksums do not constitute native runtime tests on every architecture |
| No known reachable Go dependency vulnerabilities | PASS in fresh source audits of all five native targets plus js/wasm and a symbol-preserving Windows binary counterpart; see the advisory triage below |
| Unchanged MIT and runtime licensing/integrity | PASS: matching MIT files, bundled Go BSD license and runtime component checksums |
| Current, accurate website and release announcement | OPEN: maintainer's site makeover; use the supported scope and live version information below |
| Public0.4.2 installation and channel agreement | PENDING: can only be checked after approved publication |

Implementation 219ce9132eb1173dde9779902a6faa02ff71924e passed all 13 jobs in [CI40275363831](https://github.com/fayzkk889/MCPSense/actions/runs/40275363831). [PR 16](https://github.com/fayzkk889/MCPSense/pull/16) also carries release-preparation documentation and a new mandatory vulnerability job; inspect the exact final head's checks. No detector expectation or hostility label was relaxed. Corrected authored examples are regression evidence, not field accuracy.

## Dependency advisory triage

The 26 October audit used official govulncheck v1.9.0, the production Go 1.27.3 compiler and the official vulnerability database. All six source targets and an unstripped Windows counterpart reported no reachable affected symbols. The js/wasm target had no advisory finding. These results do not assert absence of unknown vulnerabilities.

The indirect x/sys v0.25.0 dependency has [GO-2026-5024 / CVE-2026-39824](https://pkg.go.dev/vuln/GO-2026-5024), affecting windows.NewNTUnicodeString. Source analysis found it uncalled, the linked symbol inventory contained no such function, and the symbol-preserving binary check reported zero affected vulnerabilities. A stripped-PE scan conservatively reported it; [govulncheck documents](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) that missing binary symbol information can produce dependency-wide reports. Both outcomes are retained in audit evidence rather than suppressing the advisory.

The upstream fixed module version0.44.0 requires Go 1.25. The module's Go 1.22 floor is preserved instead of silently changing the supported compiler requirement for an unused function. This is not a clean-module-inventory claim. Mandatory source/symbol audits fail on affected reachable code and are refreshed before publication. A future stricter policy requiring zero module-level advisories would require a deliberate compatibility decision.

## Website handoff

The website can accurately describe local MCP security inspection, metadata/skill/config/source review, supported advisory checks, reports and drift/reference checks. Use these constraints during the makeover:

- Provide npm and Go as independent installation choices. npm needs Node.js 22+ and no Go compiler; Go users do not need npm. Installing the public package requires no npm login.
- Use live release badges/links or version checks. Prepare0.4.2 copy privately, and announce availability only when public npm and GitHub both serve0.4.2.
- Explain findings as review signals. Avoid promises of all attacks blocked, full attack-surface protection, automatic runtime enforcement, zero false positives or universally warning-free Windows execution.
- The registry has32 inspection checks plus13 drift IDs; counts are not coverage guarantees. New boundary families are within SEC-001, not extra registered checks.
- Advisory inventory is explicit and bounded. Do not claim automatic inspection of every installed/transitive package.
- Windows npm delivers WebAssembly/JavaScript. Optional native Windows archives remain unsigned and subject to policy; no route disables protection settings.

## Concrete release sequence after the site is ready

1. Review PR 16 and the exact final head's passing checks, including the new pinned six-target source and Windows-symbol audit. Confirm source/version/licenses and preserve user-owned local changes.
2. Merge only under maintainer authorization, then verify final main CI. Select the npm artifact from that approved source; verify its hashes and actual installed workflows. Rebuilding from a different Git revision can change artifact bytes even when production source is unchanged.
3. Finish the website's accurate copy and obtain explicit approval for the concrete0.4.2 commit/artifacts/publication. A tag push triggers public native-archive publication; do not push it early.
4. Publish approved GitHub/Go and npm artifacts. npm may require account confirmation and registry processing time; command success alone is not public availability proof.
5. From the released tag run scripts/release-verify.mjs --public; verify npm/GitHub/tag agreement, five public archives/checksums and actual anonymous public npm install/upgrade plus Go install. Verify installed version --check before announcing the release.
6. Record final public artifact identities and update release status. Keep the site and documentation aligned with what the public channels actually deliver.

Prepared [release notes](release-notes-0.4.2.md), [root-cause report](detection-root-cause-2026-10-26.md), and [preserved public 0.4.1 failures](user-test-2026-10-26.md) provide the review context. Local receipts are under ignored bin/root-cause-* and bin/launch-audit-*; no credentials or generated binaries are committed.

<details>
<summary>Historical preparation records — superseded; not current delivery status</summary>

# Release readiness — proposed 0.4.0

## Current follow-up

[PR13](https://github.com/fayzkk889/MCPSense/pull/13) is merged at `247824f30d3c31cdf22ece3c4029fe56b353ef5e`. Its exact reviewed head `03ad077928072241465bff9e7ba0f24ca38d922d` passed all 13 jobs in [CI40172108106](https://github.com/fayzkk889/MCPSense/actions/runs/40172108106): six npm OS/Node combinations, four native Go/race combinations, lint, Action and a publication-disabled five-target snapshot. Main's source tree matches that head. [CI40208949378](https://github.com/fayzkk889/MCPSense/actions/runs/40208949378) records the separate post-merge run. See the [npm verification record](npm-runtime-2026-10-25.md), [24 October product retest](product-retest-2026-10-24.md) and [release notes](release-notes-0.4.0.md). The sections below preserve historical failures and delivery states; their branch/merge statements are not the current status.

**Independent npm route:** the 0.4.0 candidate bundles Go WebAssembly and JavaScript, with no MCPSense native executable, install hook, archive utility or user Go prerequisite. It requires Node.js 22+; Go users keep their independent Go 1.22+ source route. Actual offline npm tarball installation, Windows command shim and installed product journeys pass. Signing work remains open for native Windows archives, not a prerequisite for the new npm execution format. Machine policies can still restrict Node.js/scripts; no universal warning-free guarantee is made. Nothing changes Windows protection settings.

**Public-delivery gate remains open:** no 0.4.0 tag, GitHub release or npm publication is authorized yet. Public channels still distribute 0.3.0. Obtain explicit approval for the concrete version/commit/artifacts, then verify actual public installs/updates. Source merges and passing private CI artifacts do not update `@latest`. Description regression scores do not establish universal attack prevention.

## Historical persona retest

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

Implementation PRs have been merged under the user's standing review/merge authorization. No 0.4.0 version tag, public GitHub release or npm publication has occurred. The tag-triggered release workflow would publish native archives if a version tag were pushed, so **do not push one without explicit maintainer approval**. After review and green final checks, obtain approval for the exact commit, version and publication process; then verify public artifact/checksum URLs and npm package contents. Until then, this is tested release preparation, not a completed public release.

Final review also requires the same approved-baseline digest when drift evidence is compared. Reapproval is a policy change, not a remediation. Schema digests preserve arbitrary JSON numeric constraints without float rounding, and Unicode offset tests include dotted-I compatibility. These are covered by focused regressions.

</details>

</details>
