# Installation precedence and update verification

Status: 0.4.5 candidate, unpublished. Public npm/GitHub stable remains 0.4.4. Review: [PR #23](https://github.com/fayzkk889/MCPSense/pull/23). Historical release receipts and website deployment are unchanged.

## Reproduction and cause

`npm install -g mcpsense@latest` successfully installed npm 0.4.4, but Windows PowerShell 5.1 selected `C:\Users\hells\go\bin\mcpsense.exe`, a Go-installed 0.3.0 executable before npm on PATH. Running the npm shim explicitly returned 0.4.4. Embedded build information identified the older executable without executing an unknown file. Package installation and command selection were independent states; reinstalling the same npm package could not change the earlier Go executable.

The implementation follows the [update contract](update-contract-2026-11-01.md): verify the delivered runtime, identify a supported older installation, retain a unique backup, hand off its command name, and verify command selection. It does not edit PATH, install Go for npm users, disable protection or claim that all command aliases/profiles and unknown programs can be repaired automatically.

## Implemented behavior

- A Node-only **global** postinstall hook verifies the bundled runtime. An older regular MCPSense Go executable in a configured/default Go bin directory can be preserved and replaced with a bridge to npm's verified entrypoint. Local/project/npx and isolated prefixes outside PATH do not migrate global files. Unknown, newer, ambiguous or linked commands are preserved and reported.
- `mcpsense update` validates agreement between the npm/GitHub stable releases. The npm route keeps its configured global prefix, pins the agreed version, disables dependency lifecycle scripts for the explicit installation, verifies the new runtime and checks command selection. Native Go users stage the pinned source build with their existing compiler, verify it, retain a backup, replace the executable and verify PATH. No route silently downgrades a newer installation.
- Interactive human-readable scans and `version` can announce an update on stderr. A one-hour cache and two-second total lookup budget limit automatic checks. Offline scans, JSON/SARIF, CI, pipes, help, init and verification skip automatic lookups. `--no-update-check` and `MCPSENSE_NO_UPDATE_CHECK=1` opt out. Notices do not install anything or authorize an update from cached data.

## Local product evidence

Windows host: Node 22.23.4, npm 10.9.9, Go 1.27.3; actual command resolution tested through Windows PowerShell 5.1.

| Check | Result |
| --- | --- |
| Normal global tarball install, copied real Go 0.3.0 first on PATH | Plain command changed from 0.3.0 to candidate 0.4.5 |
| Installation with no Go on PATH | Passed, Node-only runtime verification and handoff |
| Repeated installation | Still 0.4.5; exactly one preserved old backup |
| Original executable and unrelated Go tools | Backup byte-for-byte identical; unrelated file unchanged |
| Bridge path/argument quoting | Spaces, percent signs, ampersands, exclamation marks and carets handled |
| Actual npm self-update in an isolated prefix | Private old-version fixture updated to real published 0.4.4; same prefix; plain command verified |
| Native Go self-update of the running Windows executable | Private old-version fixture updated to real published 0.4.4; backup retained; plain command verified |
| Check-only mode | Package/executable unchanged |
| Notice with a warm cache | Appeared on stderr; stdout remained the exact version line |
| Quiet journeys | Eight scenarios passed: explicit flag, CI, environment opt-out, pipes, help, offline, JSON and SARIF |
| Unknown/newer/equal/foreign-directory/hardlink/ambiguous/locked targets | Safe preservation or idempotent equal-version handling passed |
| Offline package installation with hooks deliberately disabled | Installed archive and existing user journeys passed without Go/archive tools |
| Full Go regression suite and vet | Passed on Windows; CLI tests also passed on Linux |
| Full npm user/security suite | Passed; frozen descriptions unchanged |

The Windows symlink unit case was skipped because this host does not grant symlink creation; the Unix CI case exercises it. Local Linux race execution was unavailable because this WSL image has no C compiler; GitHub's Linux/Windows jobs provide the required race gate. The initial CI run passed Linux Go 1.22/1.27 tests, race checks, lint, vulnerability audit and action integration; its new Unix npm test fixture failed as described below. Final cross-platform CI results must be checked on the PR head before merge/publication.

The mandatory frozen description gate retained **718 observations: TP 353, FN 0, FP 0, TN 365**. The additional live gate retained TP 6/TN 6 with no tools called. These are regression observations, not universal detection guarantees. No detection rules or labels were changed by the updater work.

Evidence paths under ignored `bin/`:

- `update-045-go-all.log`, `update-045-vet.log`, `update-045-linux-go.log`, `update-045-node-unit.log`.
- `update-045-npm-product.log`, `npm-product/boundary/`, `update-045-package-smoke.log`, `npm-install-wasm/pack.json`.
- `update-install-Hr0KPa/results.json`: actual older user binary copied into isolation, normal/repeated installs.
- `update-command-HNvMUf/results.json`: real npm/native updates, eight quiet journeys and notices. The private fixture is explicitly versioned 0.3.0 for testing the new updater against public 0.4.4; it was not distributed or published.

The locally tested archive has 11 explicit files, MIT license, SHA-256 `793c82c8fab6bb89d43c2950cb3663fdea8878bc88df43137357ae0f00ea9a02`, and npm integrity `sha512-62QCorPs68iPOjg8JNQcU7pAC1vUDTtLckqNV1PrUTs4LssXJkgYncsbZQrmmUPbyXgbCeuMI4Tsvq/T+NW6HA==`. This is a validation build, not a canonical released artifact. CI builds its own platform/toolchain-stamped archive.

## Intermediate failures retained

The first real self-update exposed verification using the new `--no-update-check` flag against old published 0.4.4, which lacks that flag. Child verification already pipes output, so it now uses the compatible plain `version` command. Another fixture exposed Go 1.27 VCS pseudo-versions: identity parsing now accepts the explicit stable linker version used by source/archive builds, matching the native Go reader, while rejecting unknown development versions.

The initial Linux/macOS install acceptance fixture excluded the operating-system shell along with Go. npm could not launch its lifecycle hook (`spawn sh ENOENT`). The fixture now exposes only the existing OS shell through an isolated tools directory, continues to exclude Go, and leaves the normal lifecycle hook enabled. This was a fixture defect; no release check was weakened or bypassed.

## Current user's repair

After the isolated PowerShell test passed, the same guarded handoff was applied to the existing public npm 0.4.4 installation. The old executable is preserved at `C:\Users\hells\go\bin\mcpsense.exe.mcpsense-backup-060cf0f5-5691-4089-9285-c4f298b6e12c`, SHA-256 `94149ed7de5c70d873b275d8f51b8a2dfc94f96c3046ea34fcfd20231c014c19`.

Plain Windows PowerShell 5.1 `mcpsense version` returned **mcpsense v0.4.4**. The published npm package bytes, PATH and other Go tools were unchanged. The new updater/notices remain unpublished candidate functionality; the public 0.4.4 installation does not yet implement those commands.

## Release boundary

PR #23 contains incremental pushed commits and cross-platform checks. It must pass review and final CI before an approved 0.4.5 merge/publication. No tag, npm publication, public GitHub release or website deployment was performed for this candidate.
