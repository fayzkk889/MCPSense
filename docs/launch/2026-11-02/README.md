# MCPSense: existing-product hardening update

Prepared 2 November 2026 for the already-published 0.4.5 release. This is distribution work, not another software release or a new-product launch.

## Positioning

**MCPSense's major hardening update is live: inspect the metadata and configuration your MCP integrations ask you to trust.**

Audience: developers using MCP clients, MCP server maintainers and teams reviewing agent integrations. Ask them to scan an existing configuration, review the evidence, and report redacted misses or false alarms. The first objective is 10 external completed inspections and three repeat inspections after a change; these are campaign goals, not existing usage figures.

The story spans the hardening since the earlier 0.3.0 product through current 0.4.5. Context/value analysis shipped in 0.4.4; installation handoff and the update command shipped in 0.4.5. “Major update” describes the work; 0.4.5 is not a semantic-versioning major release.

## Recovered history

- The current engineering chat and release records establish that MCPSense already existed, its npm/Go routes, actual failures and the published 0.4.5 bytes.
- The app's **Launch Strategy Advice** chat recommends demonstrations, first external use, repeat use and learning from actual user friction. Its retrieved content is general distribution advice, not a verified ledger of prior MCPSense submissions. Other security-startup chats concerned a separate outreach campaign; their contact lists are not reused here.
- [Earlier DEV 0.3.0 article](https://dev.to/tana_shahh/mcpsense-v030-catching-mcp-server-rug-pull-attacks-with-static-drift-detection-4o3j) establishes an existing product and an existing publishing channel. The public search index identifies it; full text was not retrievable through web lookup during preparation.
- [Earlier LinkedIn MCPSense post](https://www.linkedin.com/posts/faizan-ahamad-khan-32032825b_i-built-an-open-source-security-scanner-for-activity-7465048648415055873-xINv) establishes the existing LinkedIn audience.
- The user confirmed DEV/X **@tana_shahh** and LinkedIn **Faizan Ahamad Khan** as the current distribution accounts. No account access is inferred from public identity alone.

## Message and evidence

| Message | Evidence / boundary |
| --- | --- |
| Substantial hardening of the existing scanner | [0.4.4 changes](../../engineering/release-notes-0.4.4.md), [0.4.5 publication](../../engineering/release-0.4.5-2026-11-02.md) |
| Follow supported private-value flows rather than trusting variable names | Frozen value-identity cases; the four reproducible demo manifests in this folder |
| Compare a reviewed metadata reference | Supported required-reference workflow; reference needs an operator's initial review |
| Explain inspected and unassessed surfaces | JSON/SARIF coverage and security assessment; a clean result is not authorization |
| Easier npm/Go delivery | Public anonymous npm installation, public Go installs, actual old-Go handoff and update checks |
| 718 frozen observations per tested route passed | TP353/FN0/FP0/TN365, authored regression evidence, not measured field accuracy |
| Relevant after Black October | Context for reviewing developer-tool trust, not proof of preventing the reported incidents |

[Wiz's 30 October report](https://www.wiz.io/blog/black-october-for-ai-developer-platforms) describes multiple developer-platform incidents and no single shared vulnerability tying them together. MCPSense does not patch those platforms, attest downloaded software or enforce runtime authorization. Do not claim that the demo reproduces a Black October incident.

Avoid: “new product,” “100% accurate,” “blocks every attack,” “would have stopped Black October,” runtime firewall claims, fabricated adoption, or claiming all hardening originated in 0.4.5.

## Assets

- `owned-article.md`: substantive update for the project's own blog. It is not submitted as a generated promotional DEV article: [DEV's guidance](https://dev.to/guidelines-for-ai-assisted-articles-on-dev) disallows AI-assisted/generated articles promoting programs, including the author's own. Disclosure alone does not override that restriction.
- `linkedin.txt`: existing-product update and invitation to run a real inspection.
- `x-thread.json`: four posts, each within 280 raw characters.
- `demo/`: synthetic offline metadata inspection, with paired hostile/benign cases; no actual secret or server execution.
- `distribution.csv`: publication and feedback ledger. Draft/prepared is not published.

## Execution order

1. Publish the technical update on the project's own blog; retain its actual URL. DEV is reserved for a separately human-authored contribution that follows its rules; no generated promotional article/comment is submitted there.
2. Publish the LinkedIn update and X thread under the confirmed accounts. Where an earlier relevant post is available, add a concise update pointing to the new article instead of announcing a newly invented product.
3. Reply to genuine technical questions. Ask for version, selected checks and a redacted reproducer. Never request private configs, keys or unredacted reports.
4. Record completed inspections and repeat use from explicit user reports. Public visits, stars or impressions alone are not successful inspections.

No cold-email campaign, mass DMs, paid promotion, vote solicitation or extra product work is part of this batch. The previous unrelated outreach pause is not treated as permission for new emails.

## Hacker News / other channels

[HN's current rules](https://news.ycombinator.com/newsguidelines.html) prohibit generated text and automated posting. No generated HN submission or comment is supplied or posted. The maintainer can write independently from the linked evidence. [Show HN](https://news.ycombinator.com/showhn.html) usually excludes routine updates, while a substantial overhaul may qualify; the existing product history must be disclosed. Do not delete/repost or solicit votes.

Reddit and Product Hunt are deferred until a specific existing community/listing and its current rules are verified. This batch uses the three channels the maintainer confirmed.
