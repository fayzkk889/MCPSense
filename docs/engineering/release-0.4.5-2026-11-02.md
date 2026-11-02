# MCPSense 0.4.5 release record

The maintainer approved merging PR #23 and publishing 0.4.5 to npm and GitHub/Go on 2 November 2026. This includes the existing optional unsigned native Windows archive. npm account-security confirmation remains with the account holder.

## Reviewed source

[PR #23](https://github.com/fayzkk889/MCPSense/pull/23) merged as `4ad87fc5aa8dd03cfc7be6d67f23f2111144c2c7`. Its tree matches reviewed head `e9116c46ce36a8ec800961d5b5019dd15eda4bb6`; annotated tag `v0.4.5` identifies that merged source. User-owned untracked notes were preserved.

All 15 PR checks passed in [run 41319640376](https://github.com/fayzkk889/MCPSense/actions/runs/41319640376): native Linux/Windows Go 1.22/1.27 tests and race checks, six npm platform/Node product jobs, lint, known-vulnerability audit, Action integration, scanner check and release dry-run. The [implementation verification](update-verification-2026-11-01.md) retains the original PATH defect, intermediate failures and local product tests.

The release adds a guarded Node-only global npm handoff, verified npm/native update commands and bounded interactive notices. Check-only semantics use Cobra's parsed decision rather than a second boolean parser in Node. Offline scans and machine-readable output skip automatic update checks. MIT licensing and the independent npm/Go routes remain unchanged.

## Publication checkpoints

The tagged [release workflow](https://github.com/fayzkk889/MCPSense/actions/runs/41390293291) repeats source, vulnerability and installed npm product checks before publishing. The [merged-source CI](https://github.com/fayzkk889/MCPSense/actions/runs/41390186670) is tracked separately. Canonical artifact and public-delivery receipts will be appended after actual verification; this staging record does not assert completed publication.

The earlier publisher session returned 401. The account holder completed npm's official fresh sign-in; the terminal confirmed it and `npm whoami` succeeded. The immutable release workflow artifact will be tested and published without rebuilding its bytes locally.

The existing static website's 0.4.5 notes are staged locally. Nine website tests passed. The changed guide and changelog passed a 390px layout check with one main heading and no horizontal overflow; the viewport was restored. Production remains unchanged until npm/GitHub agree. Prior Cloudflare production `350457f5` remains available for rollback.

## Verified tagged artifacts

The release workflow succeeded and published the non-draft, non-prerelease [GitHub 0.4.5 release](https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.5) at `2026-11-02T04:58:27Z`, with all five native archives and checksums. All 14 merged-source CI jobs also passed, independently of the 15 pre-merge PR checks.

Canonical npm artifact `npm-candidate-4ad87fc5aa8dd03cfc7be6d67f23f2111144c2c7`, ID `13117027227`, was downloaded unchanged from the release workflow. Its 11-file inventory, SHA512 integrity, runtime component checksums, version and original MIT license bytes were verified after normal offline global installation on Windows with no Go on PATH. A copied real Go 0.3.0 executable earlier on PATH was preserved byte for byte; plain PowerShell then selected 0.4.5. Repeat installation kept one backup and left the unrelated tool unchanged.

```text
Tarball SHA256 77fa8995b72d66dda90557edebaa61152683d14fa583b1a1c02ba3218f6dc147
Integrity sha512-jEQncvhllhhxhLEQ85vNT9acEAOKlP9GjAKzs8+AhueLmRTM24z0wYUXQqUBHeWn3/rOEynS0lABbzbQP4JfQw==
WASM SHA256 c9100400d43775db342a9df6685c57085f7baa32a4c1834ed6a279bab2a55ae6
```

Fresh public Go `@latest` installations in isolated module/build caches resolved 0.4.5 on Windows and Linux without Node/npm on their PATHs. The Linux first-use example and offline JSON scan passed. The Windows Go binary passed the user journeys, all 718 frozen description observations and the live gate (TP6/TN6, no tools called). Its SHA256 is `1738e21afa39c9fe5e01f1ed91fe8b66684c2045edc85b2f3798c7ac1736245d`. These results establish the tested delivery paths and bounded regressions, not universal detection or execution of every cross-built native architecture.

The unchanged canonical npm artifact also passed the complete Windows npm product suite: first-use/remediation, beginner/expert personas, baselines, permission boundaries, dependency inventory, frozen descriptions and live discovery. npm then required a separate publication-security confirmation, completed by the account holder. It accepted `mcpsense@0.4.5` and explicitly reported that processing could take a few minutes. The first public lookup still returned 0.4.4; this propagation observation is retained in `bin/release-045-public-propagation.log`, and was not counted as a successful public install. The canonical tarball hash remained unchanged.

## Final public package and user command

Public npm latest subsequently resolved 0.4.5. Its SHA512 integrity and downloaded tarball bytes exactly match the canonical artifact above. The anonymous-consumer test used empty npm authentication configurations, confirmed no publisher session and no Go on PATH, then installed `mcpsense@latest` with normal lifecycle scripts enabled. Plain PowerShell changed from copied Go 0.3.0 to npm 0.4.5 with one preserved backup.

The installed public runtime passed component verification, example creation, offline JSON inspection and refusal to overwrite the example. `version --check`, the alternate boolean `update --check=1`, and an already-current `update` all passed against agreeing public channels. See `bin/release-045-public-npm-receipt.json` and `bin/release-045-public-check.log`.

The unchanged public archive gate also passed on the tagged source: npm latest, GitHub latest, tag identity, all five downloaded platform archives and their checksum records agree. The maintainer's existing normal global npm installation was then updated to 0.4.5. Plain Windows PowerShell 5.1 returned `mcpsense v0.4.5`, `update --check` reported installed/latest 0.4.5, and its installed WASM SHA256 matched the canonical manifest. The original Go backup remains retained; PATH and other Go tools were unchanged.

## Website and final records

The existing assets-only Cloudflare `mcpsense` Worker now serves the 0.4.5 snapshot, changelog entry and current installation/update guidance at [mcpsense.site](https://mcpsense.site/). Production version **80226ef7** was observed **100% Ready**; previous production **350457f5** remains available for rollback. The project, domain, audience and security settings were unchanged.

The upload contained only the 20 built static files, 208,237 uncompressed bytes, with `index.html` at the upload root and preserved subdirectories. Actual public verification passed eight HTML pages, ten byte-exact assets, the original robots rules after Cloudflare's managed prefix, security/cache headers and the custom 404. The browser confirmed `Latest stable · v0.4.5`, npm/GitHub agreement and the released 0.4.5 entry. Screenshot: ignored `bin/mcpsense-045-live-release.jpg`; public receipt: `bin/release-045-site-public-receipt.json`.

README, release readiness and website source now describe published 0.4.5. Their follow-up changes documentation/static content only; the tagged source and published npm/archive bytes remain unchanged. The [machine-readable release receipt](release-0.4.5-2026-11-02-results.json) preserves source, artifact, public-install, corpus and website identities. Detailed local evidence remains under ignored `bin/release-045-*`.
