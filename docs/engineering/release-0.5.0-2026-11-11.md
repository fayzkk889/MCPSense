# MCPSense 0.5.0 release record

The maintainer authorized local end-to-end tests, merge and publication of the
CLI/MCP release and the corresponding existing Cloudflare website update.
This record is staged during preparation; publication receipts are appended
only after actual verification. Local date: 11 November 2026, Asia/Calcutta.

## Reviewed source and local user tests

[PR #32](https://github.com/fayzkk889/MCPSense/pull/32) merged on
2026-11-10T18:36:55Z as `eeabdc8bb82d02e640fb02dc6957ffc091fa0ec0` after all
15 checks passed for reviewed head `d4f2fbaa647c48f901cac90ec958f24ab731104a`.
The merged tree matches that head. Its tests were refreshed locally before
merging, rather than relying only on the previous research run.

- The complete npm product suite passed on the rebuilt 0.5.0 candidate:
  beginner/expert workflows, frozen descriptions, live discovery, baselines,
  report verification, dependencies, permissions and the new security cases.
- An actual locally packed npm installation passed without Go or archive tools.
- The installed assistant journey preserved existing settings, connected using
  the official modern client, exercised every registered scanner check against
  CLI output, required reviewed baseline acceptance, detected changed metadata,
  verified remediation and recovered from malformed inputs.
- A private synthetic 0.5.0 → 0.5.1 upgrade proved restart continuity with the
  same client config. It was confined to a disposable installation and was
  never published as 0.5.1.
- Go 1.22 tests, race checks and vet passed in the existing Linux toolchain;
  native security/advisory/MCP user tests passed independently of npm.
- Website build/link/security/motion tests and desktop/390px onboarding checks
  passed. Copying the setup command and pasting it into the browser matched its
  intended bytes. Public publication remains a separate verification step.

Local evidence: `bin/release-050-local-product.log`,
`bin/release-050-local-install.log`, `bin/release-050-local-mcp.log`,
`bin/release-050-local-go.log` and `bin/premerge-user-2026-11-10-Ztrye6/results.json`.
The [research results](security-research-2026-11-10-results.md) retain the earlier
reproduction and fuzz evidence. These fixtures do not measure universal accuracy.

## Release and website checkpoints

Canonical package bytes must come from the approved tagged release workflow and
be verified before npm upload. Public npm/GitHub/Go availability, archive
checksums, actual public installation and website responses are not inferred
from a source merge or a successful upload attempt.

The existing assets-only Cloudflare Worker is `mcpsense`, with custom domain
`mcpsense.site`. Pre-update production is `e772d2e1`, observed 100% Ready;
`80226ef7` and earlier versions remain available for rollback. No project,
audience, domain or security-policy change is required. Only built static files
will be uploaded after public package channels agree.

MIT and the two independent install routes are preserved. npm has no Go
requirement or MCPSense executable. Optional native Windows archives retain
their existing unsigned status. User-owned untracked notes are preserved.

## Verified tagged artifacts

[PR #33](https://github.com/fayzkk889/MCPSense/pull/33) passed all 17 checks and
merged as `490049e8d13fcb77e7b4b788a35d26375fc42112`, with the same tree as its
reviewed head `24729a4e61a7340c15a9e20d0f2d475401899c69`. Annotated tag `v0.5.0`
points to that source. [Release run 42879788356](https://github.com/fayzkk889/MCPSense/actions/runs/42879788356)
passed the refreshed vulnerability audit, package checks and product tests.
The stable [GitHub release](https://github.com/fayzkk889/MCPSense/releases/tag/v0.5.0)
was published at `2026-11-10T19:03:46Z` (11 November locally) with five native
archives and checksums. Its public Linux archive checksum and seven actual
archive-binary MCP/security user journeys passed.

Canonical npm artifact `npm-candidate-490049e8d13fcb77e7b4b788a35d26375fc42112`,
ID `13795190210`, contains 12 approved files. The artifact was downloaded
unchanged from the tagged workflow and passed local Windows installation
without Go on PATH, normal installation hooks, offline example scanning,
repeat installation and both official MCP client generations. A copied old
Go 0.3.0 command earlier on PATH was preserved as one byte-identical backup;
plain PowerShell then selected 0.5.0. An unrelated tool remained unchanged.
The full installed canonical npm acceptance suite passed before upload.

```text
Tarball SHA256 6baf06d0439e4771fbc03781aeee844e868c8c013a06f86705b902016aa831a1
Integrity sha512-4c0Aez6To6CHySCM899lCN3H1lN4SU+GDXseyBYgq2jv8TFsQnefqAF+kTvGkJwiHexGlqMxoFYaFiXutv/geQ==
WASM SHA256 1eb9f97ef0e63fa002b076247e36bd350b36ad75f881d056a6cd365bbcc7c0f7
```

Fresh public Linux Go `@latest`, with isolated caches and no Node/npm on PATH,
resolved 0.5.0 and passed first use. Setup was verified with an explicit
disposable client configuration path. The initial harness accidentally created
a default Cursor test config where none existed; that exact test-only file
was verified and removed before repeating setup. No existing configuration was
overwritten. The actual Go-installed executable passed the MCP and frozen
security journeys, including live metadata without peer tool calls.

The initial npm upload required a separate interactive security confirmation.
Expired challenges were rejected by npm; they did not change the registry tag
or publish the package. Canonical hashes and passed tests remained unchanged.

## Public delivery

The publisher completed npm's security confirmation on 11 November. The
[public package](https://www.npmjs.com/package/mcpsense/v/0.5.0) is tagged
`latest`, and its downloaded tarball is byte-for-byte identical to the
canonical workflow artifact. The anonymous Windows install with no Go on PATH
switched the plain command from 0.3.0 to 0.5.0 and preserved one backup.
Version and update checks, an already-current update, example creation,
offline scanning and refusal to overwrite the example all passed.

The public release gate verified the local tag, agreement between npm and
GitHub, and the checksums of all five platform archives. A first attempt timed
out on the macOS ARM64 download. The complete retry passed.

The [public website](https://mcpsense.site/) serves Cloudflare deployment
`e0ccc374` at 100% traffic. Nine local website tests passed. The public check
verified ten HTML routes, eleven public assets, security and cache headers,
and the custom 404 response. The [changelog](https://mcpsense.site/changelog/)
lists 0.5.0 as released, and the [setup guide](https://mcpsense.site/docs/#mcp)
covers connecting the installed MCP interface.
