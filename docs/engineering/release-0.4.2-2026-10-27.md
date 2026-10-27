# MCPSense 0.4.2 — public release verification

Verified 27 October 2026. The maintainer explicitly approved merging PRs 17 and 16 and publishing 0.4.2 to npm and GitHub/Go after final checks. Both PRs are merged. Public distributions and the website now identify 0.4.2.

## Source and publication identity

- Source/tag: `v0.4.2` → `14a8b957d90fbd321c20f09fbcd7e3178df68031`.
- [Final main CI](https://github.com/fayzkk889/MCPSense/actions/runs/40452217107): all 14 jobs passed, including native tests/race/vet, six npm OS/Node combinations, lint, Action, five-target archive dry run and the six-target dependency audit.
- [Tag publication workflow](https://github.com/fayzkk889/MCPSense/actions/runs/40452848413): passed. It repeated source tests, known-vulnerability auditing and installed npm product acceptance before publishing native archives.
- [Public GitHub release](https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.2): non-draft, non-prerelease, latest; all five native archives and `checksums.txt` are available.
- [Public npm package](https://www.npmjs.com/package/mcpsense/v/0.4.2): `latest` is 0.4.2. Its actual downloaded tarball matches the tested final-main Ubuntu/Node 22 artifact, not a separately rebuilt local package.

Artifact: `npm-product-ubuntu-latest-node22-14a8b957d90fbd321c20f09fbcd7e3178df68031`, GitHub artifact ID `12710858407`.

```text
SHA256 36271c978477042fd71669aee15fc5e4f9c2b0fe97fa36ce9bad752039d4db2e
Integrity sha512-b/4CAGizLAWdHYN7rcTBnmbUz4WvuHxQaH8jnJ7s5IgFrYnRljMzvtMzFetU/DF/3IdgDIHAg3MFh5Kj3JpA/A==
```

## Actual public installation and product checks

The unchanged public artifact gate passed: released tag, npm latest, GitHub latest, all five downloaded archives and their SHA256 entries agree. This validates bytes and version identity; architecture execution evidence is listed separately below.

The actual public npm package was installed anonymously on Windows with fresh caches, a prefix/workspace containing spaces, normal installation scripts and no Go or archive tools on PATH. All 13 onboarding/upgrade checks passed, including help, version, example creation, first offline scan, preservation of an existing example, actionable input errors and upgrade from public 0.4.1. The installed runtime manifest and component hashes were checked. No MCPSense native executable or install/download hook is included.

The complete product suite then passed through that public installation with existing expectations retained: scan/report/export, explain/fix/rescan/verify, live permissions, offline behavior, privacy, configuration, dependency inventory, metadata drift and description regressions. In particular, all 104 original/frozen-validation metadata observations and all 12 required-metadata-reference workflows passed. The 52 hostile and 52 benign observations are authored development regressions, not independent field accuracy or a guarantee about arbitrary descriptions.

A separate fresh Linux installation used the documented command unchanged:

```sh
go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest
```

Go 1.27.3, fresh build/module caches and a PATH without Node/npm were used. Installed version 0.4.2, synthetic example creation, offline JSON inspection, separate baseline capture, an unchanged required reference and public version awareness all passed. Native Windows/Linux source/runtime matrices passed in CI; the public Go install was executed locally on Linux. Cross-built macOS/ARM64 archives were checksum-verified, not executed on every native architecture.

Both installed routes report:

```text
mcpsense v0.4.2
Latest published GitHub release: 0.4.2
Latest npm version: 0.4.2
Installed version matches both published channels.
```

### Propagation observations retained

An initial public npm acceptance attempt ran while npm had 0.4.2 but GitHub still had 0.4.1. `version --check` correctly returned exit 2 for channel disagreement; it was not counted as a pass. The complete acceptance check passed unchanged after both channels aligned.

The first fresh Go proxy query selected cached 0.4.1. The official proxy's explicit 0.4.2 metadata and subsequent `@latest` lookup resolved the reviewed commit; the identical Go install command then passed with new caches. No version assertion, detector label or test expectation was relaxed, and no Windows protection setting was changed.

## Website and onboarding delivery

- [Live website](https://mcpsense.site/), existing Cloudflare assets-only Worker `mcpsense`; custom domain and hosting audience unchanged.
- Uploaded website source: `9a4535374fadcddf489482cece8c2e5d6acdcb75`. The follow-up documentation commit does not change deployed assets or released CLI code.
- Production version `1d1c567d`, observed **100% Ready**. Previous `7a98293d` remains available for rollback.
- Upload: 20 static files, 202,527 bytes uncompressed. Repository files, test evidence, credentials and CLI binaries were not uploaded.
- Nine website tests passed. The updated docs, changelog and two historical article notices were additionally checked at 390px and 1280px: eight render observations, one h1 each and no horizontal page overflow.
- Actual public verification passed for eight HTML pages, ten byte-exact assets, original robots rules after Cloudflare's managed prefix, security/cache headers and a genuine custom 404.
- Public browser confirms `Latest stable · v0.4.2`, npm/GitHub agreement, a released 0.4.2 entry and no unreleased candidate. The phone metadata-reference guide and its copy feedback work. The copy feedback observation is not a separate clipboard-paste attestation.

The site now documents independent npm/Go updates, `security_assessment` and `--require-metadata-baseline`. Dated engineering articles retain their original failure/preparation discussion and display explicit 27 October publication updates.

## Limits remain part of the release

MIT is unchanged. npm requires Node.js 22+ and no Go compiler; Go installation is independent of Node/npm. Optional native Windows archives remain unsigned and subject to device policy. This release is not a signing change or a universal warning-free claim.

Inspection remains bounded. Runtime authorization, tool results, unknown metadata extensions, initial baseline review/protection and arbitrary unseen hostile wording are not guaranteed by the CLI. The indirect x/sys advisory and its non-reachable-symbol triage remain documented in [dependency audit](dependency-audit-2026-10-26.md); both final CI and publication refreshed the audit. A zero-finding score is not a safety verdict.

Raw local receipts and synthetic test outputs are retained under ignored `bin/`: `release-042-public-artifacts.log`, `release-042-public-npm-test.log`, `public-npm-042-vetLKz/result.json`, `release-042-public-go-test.log`, `release-042-site-public-receipt.json`, `release-042-publish/website-manifest.json` and `mcpsense-042-live-release.jpg`. Earlier failed propagation observations are preserved separately. Generated packages/tools, credentials and user-owned `mission-progress.md` are not committed.
