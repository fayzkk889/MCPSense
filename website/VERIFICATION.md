# Website verification — 27 October 2026

## Revision and scope

The signal-inspection revision replaces the rejected paper/serif direction. Research covers eight first-party security sites and a direct Lore comparison. Static delivery, blog, changelog, independent npm/Go installation guidance and MIT project licensing remain. IBM Plex Sans is self-hosted with its original SIL Open Font License.

This is website work. CLI source, npm/Go packages and the 0.4.2 release approval state are unchanged. Public npm/GitHub stable 0.4.1 was rechecked on 27 October; 0.4.2 remains a candidate.

## Predeployment evidence

- Nine automated checks pass: page semantics; internal routes/fragments/assets; public release-channel validation; candidate separation; static content/security constraints; font/license integrity; finite motion; pause/resume/completion; reduced-motion changes; and queued-start cancellation.
- All eight HTML pages received 32 browser render checks at widths 1280, 768, 390 and 320. Every observation had one main heading and no horizontal page overflow. These are Chromium viewport checks, not physical-device or all-browser certification.
- Actual browser controls pause and resume the sweep; computed animation state changes between paused and running. Replay and metadata-reference/changed-description controls work.
- The phone menu opens and dismisses with Escape. Blog topic filtering and the empty search state work. Articles contain complete text and source links.
- npm/Go choices and copy-button feedback were checked. The npm button confirms a clipboard write with the correct command. The automation paste bridge reported an empty virtual clipboard on this retest, so a new paste result is not claimed. The unchanged copy handler passed a real copy/paste journey in the earlier design test.
- Local content-page checks reported no browser script errors. Essential content remains in the HTML, without hidden entrance reveals. CSS and the motion controller respect reduced-motion preference; no infinite animation is defined.
- RSS and sitemap parse as XML. The upload contains 20 static files, 199,945 bytes uncompressed. No source repository, credentials, tests, node_modules or CLI executable is included.

## Hosting and public verification

Existing assets-only Cloudflare Worker: **mcpsense**, serving **mcpsense.site**. The preceding paper-design deployment is **28d92e6e**; the older original deployment is **6df46433**. Preserve both for rollback. Domain, audience and existing Web Analytics settings stay intact.

Cloudflare prepends its managed crawler/content-signal policy to robots.txt. Inspection confirmed that the original Allow rule and sitemap remain at the end. This explains the earlier strict byte-comparison failure; the policy is preserved. Other assets still require exact-byte matches.

Run `node website/verify-public.mjs` after uploading the tested dist folder. It checks actual headings, resource bytes, real security/cache headers, the preserved crawler rules and the custom 404. The new signal-design production receipt is pending at this checkpoint; record its deployment version and results after publication.
