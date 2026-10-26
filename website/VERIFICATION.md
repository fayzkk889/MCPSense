# Website verification — 26 October 2026

## Scope

The website uses the “Read the fine print” inspection-desk concept, with static HTML/CSS/JavaScript. It does not change the CLI, MIT license, npm package or release-candidate publication state.

## Completed before deployment

- Five automated checks pass: page semantics; every internal link, fragment and asset; release-channel validation; stable/candidate separation; and static-package/content-security constraints.
- All seven content routes render at desktop width 1280 and phone width 390 without horizontal overflow. The 320-pixel phone checks include the homepage, guide, blog, changelog and long-command article.
- The blog filters by topic, combines search with the topic filter, displays an empty state, and opens complete articles with sources.
- Mobile menu opens and dismisses with Escape. Headings and skip navigation remain available.
- npm/Go selection works. The Go install command was copied using the actual page button and pasted into another field: the text matched exactly.
- The live public-release badge successfully checks npm and GitHub and shows stable 0.4.1. Malformed, draft, prerelease and disagreeing channels receive dedicated automated checks; network outages retain a dated snapshot.
- Shared min-width rules and indented-link widths corrected the mobile overflow discovered during browser testing; the affected routes were rechecked.
- No browser script errors were reported in the local content-page checks.
- The upload folder contains 17 static files, approximately 131 KB uncompressed. No source repository, credentials, runtime binaries, test receipts or node_modules are uploaded.

## Deployment record

Existing Cloudflare assets-only Worker: **mcpsense**. Existing public domain: **mcpsense.site**. Prior production version shown in the dashboard: **6df46433**. Preserve it as the rollback point. No domain or audience migration is required.

Cloudflare Web Analytics is injected by the existing hosting setup. The redesign adds no analytics code; the security policy permits that existing integration, and the footer does not claim analytics are absent.

Production upload, real response-header verification and post-publication browser checks are pending. This record does not claim that a local preview is a deployment.
