export const product = {
  name: 'MCPSense',
  origin: 'https://mcpsense.site',
  github: 'https://github.com/fayzkk889/MCPSense',
  stable: '0.4.2',
  verified: '2026-10-27',
  candidate: null,
};

export const articles = [
  {
    update: '27 October 2026 update: 0.4.2 is now published on npm and GitHub, including the required metadata reference check. The dated discussion below records its preparation; see the changelog for current availability.',
    slug: 'the-mcp-trust-boundary', category: 'Security', date: '2026-10-26', minutes: 5,
    title: 'MCP security starts at the trust boundary.',
    excerpt: 'A tool description is data. When it starts making decisions for your agent, something has crossed a boundary.',
    lead: 'MCP makes tools easy to discover. That convenience also puts third-party text directly in an agent’s path. Security starts with deciding what that text is allowed to mean.',
    sections: [
      ['Description is not authority', `<p>A server can advertise a tool called <code>search_docs</code> and describe how to use it. That description helps a client understand an interface. It should not acquire the authority to replace the user’s instructions, disable approval, or redirect secrets.</p><p>The distinction matters because an instruction can be perfectly ordinary English and still ask for an unsafe transfer of authority. Looking only for a familiar phrase such as “ignore previous instructions” misses the underlying relationship: who is being asked to act, on what, under whose authority?</p>`],
      ['Inspect what an agent is about to read', `<p>MCPSense inspects recognized advertised metadata, including server instructions, tool descriptions, schema text, resource metadata and prompt metadata. It looks for signals that deserve review: authority replacement, disclosure, deceptive reporting, suspicious routing and other supported patterns.</p><p>It also reviews supported local configuration, source and agent instruction files. Those surfaces have different meanings; a literal rule in a skill file is not automatically equivalent to a quoted phrase in a document query.</p>`],
      ['A finding is the beginning of a decision', `<p>A pattern match does not prove exploitation. A quiet report does not prove safety. Read the finding, inspect the source, and evaluate the actual permissions and destination of the integration.</p><p>Keep this separate from runtime controls. Authentication, authorization, session isolation, execution containment and tool-result handling belong in the host and server. MCPSense does not enforce those controls.</p>`],
      ['Review changes as well as text', `<p>Descriptions can change after an initial review. Metadata baselines help identify changes in recognized fields. The prepared 0.4.2 candidate adds an optional required-reference check that refuses unknown or changed catalogs without depending on whether their wording matches a detector.</p><p>That reference must be reviewed and protected by the operator. It is not a server signature, and it does not make an unsafe initial choice safe. Version 0.4.2 is a candidate at the time of writing; check the changelog and public channels before using its flags.</p>`],
    ],
    sources: [
      ['Supported inspection scope', 'https://github.com/fayzkk889/MCPSense#scope-and-permissions'],
      ['Threat review and runtime boundaries', 'https://github.com/fayzkk889/MCPSense/blob/codex/published-041-user-retest-2026-10-26/docs/research/2026-10-23-mcp-threat-review.md'],
    ],
  },
  {
    slug: 'npm-without-go', category: 'Guides', date: '2026-10-26', minutes: 4,
    title: 'One command. Your choice of toolchain.',
    excerpt: 'npm needs Node.js. Go needs Go. Here is how MCPSense keeps the two installation paths independent.',
    lead: 'Installing a security tool should not start with installing a second language toolchain. MCPSense offers two independent routes, so you can use the environment you already have.',
    sections: [
      ['The npm route', `<p>With Node.js 22 or newer installed, run:</p><pre><code>npm install -g mcpsense@latest</code></pre><p>The npm package bundles the Go inspection engine compiled to WebAssembly, together with its matching JavaScript runtime. You do not need a Go compiler, an archive utility, an npm account or an MCPSense native executable. There is no postinstall executable download.</p><p>This route supports Windows, Linux and macOS where a supported Node.js runtime is available. NVM is optional; it is a way to manage Node versions, not a requirement of MCPSense.</p>`],
      ['The Go route', `<p>If Go is your preferred environment, use:</p><pre><code>go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest</code></pre><p>This route needs Go, not Node.js or npm. Go 1.22 is the source compatibility floor; use a current patched Go compiler. Ensure Go’s binary installation directory is on your PATH.</p>`],
      ['Run an offline first inspection', `<p>In an empty working directory:</p><pre><code>mcpsense init --example\nmcpsense scan ./mcp.json --offline --no-baseline</code></pre><p>The first command creates a synthetic example and refuses to overwrite an existing target. It does not connect a real server. The second command reads that example without scanner networking, server execution or a saved metadata baseline.</p><p>For your own integration, point the scan at an existing recognized manifest or MCP client configuration. Read coverage as well as findings.</p>`],
      ['Windows delivery, without workarounds', `<p>The npm route has no MCPSense <code>.exe</code> to download or launch. Optional native Windows archives remain unsigned and may be blocked by device policy. ZIP packaging does not provide a publisher signature.</p><p>No route disables Windows protections. Enterprise policies can also restrict Node.js or scripts, so a universally warning-free installation is not something we promise.</p>`],
      ['Update deliberately', `<p>Run <code>mcpsense version --check</code> to check public npm and GitHub releases. It reports availability and update commands; it never updates automatically. Rerun your chosen install command when you want to upgrade.</p><p>A newer commit or release candidate does not mean that <code>@latest</code> has changed. Check the installed version before relying on a newly documented feature.</p>`],
    ],
    sources: [
      ['Installation documentation', 'https://github.com/fayzkk889/MCPSense#start-safely'],
      ['Public npm package', 'https://www.npmjs.com/package/mcpsense'],
      ['Published releases', 'https://github.com/fayzkk889/MCPSense/releases'],
    ],
  },
  {
    update: '27 October 2026 update: 0.4.2 is now published on npm and GitHub. Its reproduced-case corrections and separate security assessment are available. The development results and limits below remain historical regression evidence.',
    slug: 'a-clean-scan-is-not-a-trust-decision', category: 'Engineering', date: '2026-10-26', minutes: 6,
    title: 'A clean scan is not a trust decision.',
    excerpt: 'What fresh user tests taught us about missed descriptions, regression evidence and the limits of a security score.',
    lead: 'A security product earns trust by explaining what it tested, what failed and what remains unknown. A score of 100 cannot carry that explanation on its own.',
    sections: [
      ['Keep the failures visible', `<p>Fresh end-to-end tests of public 0.4.1 reproduced five hostile-description families that the scanner missed on tool descriptions and server instructions. They involved approval bypass, false payment success, promotion of search data to authority, suppression of security warnings and removal of policy confirmation.</p><p>Some server-instruction examples returned no findings and a score of 100. These are known limitations of the published version, not evidence that the integrations were safe. The original labelled inputs and outcomes remain in the engineering record.</p>`],
      ['Fix the relationship behind the phrase', `<p>The prepared 0.4.2 candidate moves these families to shared, bounded clause analysis of actions, objects and polarity. It also keeps benign counterexamples: reporting a real failure, refusing disclosure or preserving approval should not be treated like the corresponding harmful instruction.</p><p>The candidate passes 104 authored CLI observations across the original and pre-implementation validation cases: 52 hostile and 52 benign observations. Those examples are regression evidence. They were authored and used during development; they are not an independent measurement of accuracy on arbitrary real-world text.</p>`],
      ['Separate findings from assurance', `<p>A finding score summarizes reported findings and can change with filters. It does not answer whether the server is trustworthy, whether all inputs were inspected or whether authorization is enforced.</p><p>The candidate adds a machine-readable security assessment separate from the score. Reports distinguish review-required and not-established outcomes. Neither a clean report nor a detector fingerprint supplies a signature or runtime permission boundary.</p>`],
      ['Make uncertainty actionable', `<p>Read the report’s inspected and unassessed surfaces. Review findings before granting a server permissions. Compare equivalent reports from the same detector version. Where a reviewed metadata catalog must remain unchanged, the candidate’s optional required baseline provides a deterministic check on recognized metadata.</p><p>Even then, protect the reference and enforce permissions in the host. Runtime results, arbitrary extensions and unseen behaviors remain outside the inspection guarantee.</p>`],
      ['Check what is actually released', `<p>At publication of this article, 0.4.1 is the public stable version and 0.4.2 is under review. We distinguish that state throughout this site. A passing development test is not a package release, and a source push does not update an installed CLI.</p>`],
    ],
    sources: [
      ['Preserved public-version user tests', 'https://github.com/fayzkk889/MCPSense/blob/codex/published-041-user-retest-2026-10-26/docs/engineering/user-test-2026-10-26.md'],
      ['Root-cause investigation', 'https://github.com/fayzkk889/MCPSense/blob/codex/published-041-user-retest-2026-10-26/docs/engineering/detection-root-cause-2026-10-26.md'],
      ['0.4.2 candidate review', 'https://github.com/fayzkk889/MCPSense/pull/16'],
    ],
  },
];

export const releases = [
  {
    version: '0.4.2', status: 'Released', date: '2026-10-27', title: 'Stronger review boundaries.',
    intro: 'Available through npm and Go. Update with your preferred installation command.',
    items: [
      'Shared clause-scoped detection for five newly reproduced hostile-description families, with benign counterexamples.',
      'An optional required metadata baseline that rejects unreviewed catalog changes independently of wording.',
      'A separate machine-readable security assessment, so a finding score cannot stand in for a trust decision.',
      'Mandatory native/npm regression journeys and six-target Go vulnerability checks.',
    ],
    link: 'https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.2', label: 'Read the release notes',
  },
  {
    version: '0.4.1', status: 'Released', date: '2026-10-25', title: 'Corrections from real user journeys.',
    intro: 'A patch for hostile-description gaps reproduced while testing the published 0.4.0 package.',
    items: [
      'Improved signals for privileged retries, deceptive success reporting, authority promotion and signing-key disclosure.',
      'Benign counterexamples preserve defensive refusals, actual failure reporting and approval-preserving instructions.',
      'Independent npm WebAssembly and native Go installation paths remain supported.',
    ],
    note: 'Fresh testing later found five additional missed families in 0.4.1. Those reproduced cases are corrected in 0.4.2; a clean scan does not establish trust.',
    link: 'https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.1', label: 'Read the release notes',
  },
  {
    version: '0.4.0', status: 'Released', date: '2026-10-25', title: 'A simpler install. More explicit evidence.',
    intro: 'The npm package moves to WebAssembly, with modern metadata discovery and clearer inspection boundaries.',
    items: [
      'Node.js 22+ runs the bundled Go engine; no Go compiler, native executable download or install hook is required for npm.',
      'Modern metadata discovery, JSON/SARIF coverage, detector fingerprints and offline report comparison.',
      'Explicit execution/network permission controls, bounded discovery and a non-overwriting example walkthrough.',
    ],
    link: 'https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.0', label: 'Read the release notes',
  },
];
