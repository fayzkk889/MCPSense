# MCPSense — signal inspection

A static, MIT-licensed website for **mcpsense.site**. A wide metadata trace, finite scan sweep and interactive drift comparison make the product's trust boundary concrete. The graphite/orange identity, technical sans-serif type and full-width composition separate it from the earlier paper/serif design and Lore. See the [eight-site design study](DESIGN-RESEARCH-2026-10-26.md).

No custom cursor, framework, account or database is used. Motion can pause/resume/replay and respects reduced-motion preferences; essential content remains visible without animation. The source adds no analytics; the existing Cloudflare Web Analytics integration remains permitted by the content security policy.

## Build, test, preview

Requires Node.js 22+ on the **maintainer's build machine**. Website visitors need only a browser.

```sh
node website/build.mjs
node --test website/test/*.test.mjs
node website/server.mjs
# After deployment, compare actual public responses with the built upload
node website/verify-public.mjs
```

Open the printed loopback URL. The development server is not deployed. `website/dist/` contains the entire uploadable site: eight HTML pages, local CSS/JavaScript/SVG, RSS, a sitemap, robots and Cloudflare security headers. It is ignored by Git and rebuilt from tracked sources.

## Content and release truth

- `content.mjs`: articles, release records and the dated public-channel snapshot.
- `build.mjs`: shared layouts and generated HTML, feed and headers.
- `views/home.mjs`: the signal-inspection homepage and illustrative metadata trace.
- `src/`: presentation and browser interactions.
- `src/motion.js`: finite, pausable illustration; no scanner or submission endpoint.
- `src/fonts/`: self-hosted IBM Plex Sans Latin font and its original SIL Open Font License. The font retains that separate license; project code remains MIT. No visitor request goes to a font CDN.
- Blog articles are dated engineering notes. Their sources and historical limitations remain explicit.
- A browser shows “Latest stable” only after npm **and** GitHub agree on a valid public, non-prerelease version. A mismatch is visible. An outage retains a dated snapshot rather than claiming freshness.
- If both channels move beyond the saved snapshot, the changelog links to the newer public release and retires a superseded candidate entry. Update the detailed editorial release notes in `content.mjs` after an approved release.
- npm and Go are independent install routes. `@latest` refers to published releases, not a source branch. The 0.4.2 candidate must not be advertised as published until it is actually available.

## Existing Cloudflare hosting

The existing **mcpsense** Worker is an assets-only service, with **mcpsense.site** as its existing custom domain. Keep that project and audience. It uses the same direct static-upload approach as the Lore website; no Sites project, migration or extra Worker backend is needed.

After tests and browser review, use its **New deployment → Upload static files** workflow to upload the contents of `website/dist/`, keeping `index.html` at the upload root and preserving the subdirectories. `_headers` applies the content security policy and prevents stale HTML/asset caching. Verify real response headers after deployment; the local server is not proof of Cloudflare configuration.

Keep the prior production version available for Cloudflare rollback. Do not upload repository files, test evidence, credentials or this source folder. Verify `/`, `/docs/`, `/blog/`, each article, `/changelog/`, `/feed.xml`, mobile navigation, copy buttons, release status and a missing path on the actual domain after publication.

Cloudflare prepends its managed crawler policy to `robots.txt`. The public verifier checks that the site's original rules and sitemap remain intact, while comparing other non-HTML assets byte for byte. It also validates real security/cache headers, page headings and the custom 404. A local preview alone does not establish successful deployment.

Website publication does not merge or publish the separate CLI release candidate.
