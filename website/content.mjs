export const product = {
  name: 'MCPSense',
  origin: 'https://mcpsense.site',
  github: 'https://github.com/fayzkk889/MCPSense',
  stable: '0.4.5',
  verified: '2026-11-02',
  candidate: null,
};

export const articles = [
  {
    update: '27 October 2026 update: 0.4.2 is now published on npm and GitHub, including the required metadata reference check. 1 November update: 0.4.4 adds shared context and value-provenance analysis. The dated discussion below records earlier preparation; see the changelog for current availability.',
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
    update: '2 November 2026 update: 0.4.5 adds verified update commands, terminal notices and a guarded handoff when an older Go executable takes precedence over npm. The independent npm and Go installation routes remain available.',
    title: 'One command. Your choice of toolchain.',
    excerpt: 'npm needs Node.js. Go needs Go. Here is how MCPSense keeps the two installation paths independent.',
    lead: 'Installing a security tool should not start with installing a second language toolchain. MCPSense offers two independent routes, so you can use the environment you already have.',
    sections: [
      ['The npm route', `<p>With Node.js 22 or newer installed, run:</p><pre><code>npm install -g mcpsense@latest</code></pre><p>The npm package bundles the Go inspection engine compiled to WebAssembly, together with its matching JavaScript runtime. You do not need a Go compiler, an archive utility, an npm account or an MCPSense native executable. There is no postinstall executable download.</p><p>This route supports Windows, Linux and macOS where a supported Node.js runtime is available. NVM is optional; it is a way to manage Node versions, not a requirement of MCPSense.</p>`],
      ['The Go route', `<p>If Go is your preferred environment, use:</p><pre><code>go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest</code></pre><p>This route needs Go, not Node.js or npm. Go 1.22 is the source compatibility floor; use a current patched Go compiler. Ensure Go’s binary installation directory is on your PATH.</p>`],
      ['Run an offline first inspection', `<p>In an empty working directory:</p><pre><code>mcpsense init --example\nmcpsense scan ./mcp.json --offline --no-baseline</code></pre><p>The first command creates a synthetic example and refuses to overwrite an existing target. It does not connect a real server. The second command reads that example without scanner networking, server execution or a saved metadata baseline.</p><p>For your own integration, point the scan at an existing recognized manifest or MCP client configuration. Read coverage as well as findings.</p>`],
      ['Windows delivery, without workarounds', `<p>The npm route has no MCPSense <code>.exe</code> to download or launch. Optional native Windows archives remain unsigned and may be blocked by device policy. ZIP packaging does not provide a publisher signature.</p><p>No route disables Windows protections. Enterprise policies can also restrict Node.js or scripts, so a universally warning-free installation is not something we promise.</p>`],
      ['Update deliberately', `<p>Run <code>mcpsense update --check</code> to compare public npm and GitHub releases, then <code>mcpsense update</code> when you want to install. It verifies the selected installation and preserves an identified older executable as a backup. Rerunning your chosen installation command also remains supported.</p><p>Version 0.4.5 adds a Node-only global installation check for an older Go executable taking precedence over npm. It preserves that executable and routes the command to the verified npm runtime. Unknown, linked or newer commands are preserved and reported; PATH is unchanged.</p><p>Interactive scans and the version command can announce updates on stderr with a one-hour cache and a two-second lookup limit. Offline scans, JSON/SARIF, CI and pipes skip automatic checks. Use <code>--no-update-check</code> or <code>MCPSENSE_NO_UPDATE_CHECK=1</code> to opt out. A notice never installs an update.</p><p>A newer commit or release candidate does not mean that <code>@latest</code> has changed. Check the installed version before relying on a newly documented feature.</p>`],
    ],
    sources: [
      ['Installation documentation', 'https://github.com/fayzkk889/MCPSense#start-safely'],
      ['Public npm package', 'https://www.npmjs.com/package/mcpsense'],
      ['Published releases', 'https://github.com/fayzkk889/MCPSense/releases'],
    ],
  },
  {
    update: '27 October 2026 update: 0.4.2 is now published on npm and GitHub. 1 November update: the 0.4.4 release addresses subsequent 0.4.3 audit failures with shared metadata context and value provenance. The development results and limits below remain historical regression evidence.',
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
    version: '0.4.5', status: 'Released', date: '2026-11-02', title: 'Run the version you installed.',
    intro: 'Verified command selection, deliberate updates and clear terminal notices keep installations current.',
    items: [
      'A Node-only global npm check preserves an identified older Go executable in a backup and routes its command to the verified npm runtime.',
      'mcpsense update requires npm/GitHub agreement, keeps the owning installation location and verifies the resulting version.',
      'Cached interactive update notices stay on stderr; offline scans, JSON/SARIF, CI and pipes skip automatic checks.',
      'Actual fresh, repeated and mixed installations, native/npm self-updates and Windows/Linux/macOS product regressions passed.',
    ],
    note: 'npm requires Node.js 22+ without Go. The independent Go route and MIT license remain unchanged; notices never install automatically.',
    link: 'https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.5', label: 'Read the release notes',
  },
  {
    version: '0.4.4', status: 'Released', date: '2026-11-01', title: 'Follow the value. Preserve the boundary.',
    intro: 'Shared metadata context and value provenance address the reproduced misses and benign false alarms in 0.4.3.',
    items: [
      'Follow private values through renaming, encoding and reassignment without classifying harmless data by its variable name.',
      'Distinguish active instructions from prohibitions, observed predicates, quoted operands and fixed placeholders.',
      'Use shared exfiltration analysis across supported metadata fields and require manual review when analysis capacity is exceeded.',
      '718 frozen description observations per native/npm route, plus live discovery, required-reference and user workflows.',
    ],
    note: 'These authored regression results do not establish field accuracy, future zero misses or runtime authorization.',
    link: 'https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.4', label: 'Read the release notes',
  },
  {
    version: '0.4.3', status: 'Released', date: '2026-10-31', title: 'Trace the requested effect.',
    intro: 'Available through npm and Go. Stronger review of credential relays, monitoring changes and advisory applicability.',
    items: [
      'Bounded source, transform and destination analysis for credential transfers through notes and encoded bundles.',
      'Monitoring-state, escalation, reporting-integrity and downloaded-code signals, with benign and negation controls.',
      '232 frozen native/npm description observations and deterministic metadata-reference workflows.',
      'Explicit publisher/feed disagreement evidence without suppressing the advisory warning.',
    ],
    note: 'A subsequent 0.4.3 audit exposed additional misses and benign false alarms addressed in 0.4.4. Regression evidence does not establish universal detection or runtime authorization.',
    link: 'https://github.com/fayzkk889/MCPSense/releases/tag/v0.4.3', label: 'Read the release notes',
  },
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
