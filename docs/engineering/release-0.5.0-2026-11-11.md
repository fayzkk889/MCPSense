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
