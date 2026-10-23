# MCP threat review and security invariants — 23 October 2026

This review uses current publisher advisories, the MCP specification, original security research, the actual MCPSense source and local synthetic probes. It is a bounded research pass, not a census of every incident. Advisory publication is not evidence of exploitation in the wild. No external server was attacked, no vulnerable package was installed, and no fixture tool was executed.

## Main finding

MCPSense is a scanner, not an enforcement boundary. Its existing checks and new metadata baselines help identify suspicious inputs and changes; they cannot establish runtime authorization, tenant isolation, database privileges, complete dependency inventory or safe tool results. Protecting against novel payloads requires enforceable properties at those boundaries, alongside scanning and patching. Adding enough suspicious phrases cannot establish protection against every possible attack.

The review reproduced seven package-identification/pinning defects and an advisory-source coverage gap. It also exercised three explicitly unassessed product boundaries. These are separate findings: a fixed parser does not fix a vulnerable server implementation, and a successful advisory lookup does not establish absence of vulnerabilities.

## Recent primary-source developments

Publication dates below are advisory dates, not inferred attack dates. Applicability requires the named package, affected version and deployment conditions. Fix versions are package-specific; a number from one package or release branch must not be applied to another.

| Publisher evidence | Verified failure and prerequisites | Remediation and relevance |
| --- | --- | --- |
| [TypeScript SDK GHSA-jm63-cq47-j5jp](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-jm63-cq47-j5jp), 15 Oct | Shared HTTP transport/server objects could deliver messages across clients when request IDs collide; server 2.0.0–2.2.0 | Patched server line 2.3.0; also follow per-request/session instance guidance. MCPSense does not exercise multiple authenticated clients or prove ownership isolation. |
| [SDK GHSA-f897-62hf-6gxq](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-f897-62hf-6gxq), 15 Oct | Unbounded HTTP bodies/batch length can exhaust memory or monopolize service; HTTP reachable by untrusted clients | Affected/fixed package branches differ (sdk 1.30.1, server/node 2.1.0, hono 2.0.1). Apply body and batch limits; stdio-only servers have different applicability. A byte limit alone does not bound every computational cost. |
| [SDK GHSA-46jr-4wx8-v453](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-46jr-4wx8-v453), 15 Oct | Numerous argument elements can exhaust validation memory even within a 4 MiB request; HTTP tools accepting arrays/records are especially relevant | sdk 1.32.0 / server 2.3.0 add `maxToolInputElements`, disabled by default. Enable it and constrain request/parser size. Merely upgrading is insufficient. |
| [SDK GHSA-rvq5-wwqv-78pq](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-rvq5-wwqv-78pq), publisher 5 Oct; database publication 20 Oct | Bearer validation can accept a token intended for another service when the custom verifier omits audience checks | sdk 1.32.0 / server 2.3.0, plus the appropriate express/server-legacy fixes, require configuring expected resource and returning the verified token audience. Upgrade alone does not activate the check. An `oauth2` declaration is not evidence this is enforced. |
| [SDK GHSA-22jm-h49p-29qw](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-22jm-h49p-29qw), 2 Oct | Experimental task stores shared across HTTP clients could allow cross-session listing, reading or cancellation; sdk 1.24.0–1.31.0 with `taskStore` | sdk 1.32.0 ties tasks to sessions; retire deprecated experimental tasks or isolate stores. The 2.x packages have different applicability. |
| [SDK GHSA-6prh-2h8m-c8cw](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6prh-2h8m-c8cw), 2 Oct | Cross-origin redirects can disclose custom headers/session IDs and, for 307/308, request bodies including OAuth credentials | sdk 1.32.0 / client 2.3.0 restrict redirects. MCPSense's own live client already disables redirects and environment proxies; this does not repair the target server/client. |
| [SDK GHSA-6qxp-vccf-f47h](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6qxp-vccf-f47h), 30 Sep | OAuth credentials could go to an authorization server selected by an untrusted MCP server | client 2.2.0 / sdk 1.31.0 bind credentials to the authorization server. MCPSense does not perform OAuth flows, so metadata inspection does not verify this property. |
| [AWS CVE-2026-97662](https://aws.amazon.com/security/security-bulletins/2026-121-aws/), 1 Oct | A crafted diff reference becomes a CLI option, permitting out-of-workspace file changes; security-agent-mcp-server >=0.1.1,<0.2.0 | Fix 0.2.0. Separate argv prevents shell interpretation but does not stop an invoked program from interpreting an argument as an option. |
| [AWS CVE-2026-87911 / GHSA-fph8-pg5w-78fv](https://github.com/awslabs/mcp/security/advisories/GHSA-fph8-pg5w-78fv), 9 Sep | PostgreSQL read-only SQL filtering can be bypassed before 1.1.7; requires self-managed PG_WIRE_PROTOCOL deployment and an overly privileged database role | Upgrade to 1.1.7 and use database-enforced least privilege. A read-only metadata hint/application blocklist is not an authorization boundary. A dated supplemental match for this advisory is implemented in this change. |
| [AWS CVE-2026-85654](https://aws.amazon.com/security/security-bulletins/2026-097-aws/), 4 Sep, updated 8 Sep | Untrusted DynamoDB model names can influence generated CDK code that is subsequently deployed; versions 2.0.10–2.1.5 | Fix 2.1.6 and review generated code/model provenance. Risk can appear at later interpretation/deployment rather than at the original tool call. |

The [current maintainer advisory index](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories) was checked rather than relying on search headlines alone. The [2026-07-28 MCP security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) covers deputy confusion, audience-bound tokens, OAuth metadata/SSRF, session ownership, local execution and scope minimization. These requirements cannot be verified by matching hostile descriptions alone.

## Historical attack classes that remain relevant

- [Invariant's original tool-poisoning research, 1 April 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) demonstrates metadata-driven instruction redirection, tool shadowing and later metadata changes. Current screening and digest baselines address parts of this surface, with explicit omissions.
- [Snyk/Invariant toxic-flow research, 29 July 2025](https://labs.snyk.io/resources/toxic-flow-analysis/) examines the composition of untrusted content, sensitive reads and external writes across tools. A single benign-looking tool definition cannot establish the safety of the whole permitted workflow.
- [The maintainer's Git argument-injection advisory, 17 December 2025](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-9xwc-hfwc-8w59) establishes that this command-option interpretation failure predates the new AWS report. The first-principles failure is data acquiring control over a downstream interpreter; a shell is only one such interpreter.
- [Original MSB research](https://arxiv.org/abs/2510.15994) evaluates planning, tool invocation and response handling through executable MCP tools, with both task success and security outcomes. Its results are research claims, not a benchmark score for MCPSense. It motivates evaluating tool responses, composed workflows and legitimate tasks alongside description detection.

## Reproductions and implemented corrections

### Package identity and pinning

Commit `ce7ec36` contains the failing reproduction. Six package identities were wrong or missing: uvx `==` requirements, uvx `--from`, npm exec `--package`, absolute Windows launcher paths, local Node scripts and Python modules. A seventh case let an unrelated later `example@1.2.3` argument suppress the warning for an unpinned npx launch package.

A shared, bounded launch parser now handles supported npx/npm exec, uvx/uv tool run and pipx run forms, distinguishes option values from package identities and respects npx's tool-argument boundary. Recognized moving npm tags/ranges do not count as exact pins. Local scripts/modules, URL/Git sources and unknown option grammars are not guessed into public registry identities. This remains primary-launch-package extraction, not a complete resolver, local environment inventory, lockfile/SBOM audit or transitive dependency graph. Explicit npm/npx shell-call modes also receive the existing execution-review finding.

The implementation follows the [npm exec grammar](https://docs.npmjs.com/cli/v11/commands/npm-exec/) and [uv tool documentation](https://docs.astral.sh/uv/guides/tools/). Additional dependencies, registry overrides, private provenance, arbitrary wrappers and unresolved versions still require separate verification. Exact version pins do not authenticate package publishers or immutable artifact contents.

### Advisory-source omission and remediation guidance

Direct HTTPS OSV queries on 23 October returned HTTP 200 with an empty object for `awslabs.postgres-mcp-server` 1.1.6 and 1.1.7; the normalized hyphen spelling was also empty for 1.1.6. The direct OSV lookup for GHSA-fph8-pg5w-78fv returned HTTP 404. A positive control (`lodash` 4.17.20) returned HTTP 200 with five advisory IDs, and the new SDK GHSA-46jr-4wx8-v453 record returned HTTP 200. The AWS publisher advisory independently identifies <1.1.7 as affected. The reason for OSV's omission was not established; it must not be asserted to be indexing delay.

This change adds one deliberately small vendor-reviewed supplemental record, dated 2026-10-23, for the AWS PostgreSQL advisory. Affected stable versions match, stable versions 1.1.7+ do not match, and unsupported/unresolved version ordering produces a clearly qualified candidate. Deployment prerequisites are retained in the finding. The source/date participate in scanner identity and reported advisory scope. It is not a general replacement for OSV or a complete historical feed. `--offline`/`--no-cve` still skip the advisory phase, and failed OSV coverage still fails the requested scan.

Unresolved launch versions are now described as advisory candidates. Remediation no longer blindly selects the first fixed event from a potentially multi-package/multi-branch advisory and promises that upgrading to it fixes the deployment. Findings require review of the correct package branch, prerequisites and configuration, as the new SDK advisories explicitly require.

### Actual CLI boundary observations

`scripts/threat-review.mjs` runs the scanner, never the fixture server/tool code. Its local run made ten invocations: five pinning/benign controls, three boundary probes and two live advisory queries for public affected/fixed versions. Affected 1.1.6 now yields the vendor finding; fixed 1.1.7 does not. The probes below remain open boundaries, not newly verified exploits or a false-negative-rate estimate:

| Probe | Observed report | Meaning |
| --- | --- | --- |
| Directory with SDK 1.31.0 in ordinary package.json dependencies | No finding; advisory phase skipped | The current scanner does not inventory project dependencies. A source-project scan cannot promise these SDK advisories were evaluated. |
| Benign manifest plus an unrequested response file containing an injection | No finding; runtime outputs explicitly unassessed | MCPSense does not invoke tools or read runtime responses. The fixture was never delivered to an agent, so this is a scope demonstration rather than demonstrated exploitation. |
| Python direct argv to git diff with a variable revision | No finding | Existing shell heuristics do not prove safe option/data separation. This is a review hypothesis requiring contextual dataflow/argument testing, not a verified host compromise. |

The last three observations do not freeze expected misses into passing security tests. The harness records them for review. JSON/SARIF now explicitly list project/transitive inventory, authorization/session enforcement and runtime resource limits as unassessed. Requested advisory coverage is labelled as recognized launch packages plus the dated vendor supplement.

## First-principles security model

The asset is the user's authority and data, not merely the description text. For each proposed operation, determine the initiating principal, delegated capability, target resource, permitted effects and current policy. Untrusted text may propose an operation but must not grant a capability. All effects must pass a policy boundary outside the model's text interpretation.

The placement matters: an untrusted server can attack its client/agent, and an untrusted client can attack the server. Upstream documents and package publishers introduce further inputs. A proxy on the client side cannot constrain filesystem, database or network effects inside a remote server; the server operator must enforce those boundaries in the server's own execution environment. Protection must be designed for both directions and for the infrastructure performing the actual effect.

| Invariant | Derived failure class, including novel compositions | Testable enforcement requirement |
| --- | --- | --- |
| Authority originates in authenticated policy | Prompt injection, forged user messages, poisoned metadata/results, false-error escalation | Substitute arbitrary untrusted instructions; sensitive actions still require an independent grant. A quoted benign document remains usable. |
| Identity and state belong to a principal | Cross-tenant responses, shared session/task/cache leakage, replay | Two authenticated principals use colliding request IDs and guess each other's task/session IDs; neither receives or mutates the other's state. |
| Tokens authorize this resource and action | Token passthrough, confused deputy, scope inflation | Validly signed tokens for another issuer/audience/resource fail; privileged operations require the caller's explicit scope and consent. |
| Data cannot choose an unintended interpreter operation | Shell/argument/SQL/template/path injection | Normalize and validate at the actual interpreter boundary. Use parameterized APIs and constrained arguments; explicit argv alone is insufficient. |
| Reads and writes stay within delegated resources | Path traversal/symlinks/TOCTOU, SSRF/rebinding, metadata access, exfiltration | Filesystem and network enforcement must constrain the executed effect; validating a string before a later open/connect is not sufficient isolation. |
| Privilege remains bounded under component failure | Malicious server/publisher, SQL read-only bypass, composed toxic flows | OS/container, database and cloud IAM permissions deny unauthorized effects even when application checks fail. Metadata hints confer no privilege. |
| Cost remains bounded before expensive work | Body/batch/element/depth/stream/regex amplification and resource exhaustion | Bound bytes, elements, depth, time, concurrency, process memory and per-principal rates; test legitimate maximum workloads and cancellation. |
| Approved code and behavior cannot change unnoticed | Rug pulls, moving tags, registry takeover, changed generated code | Bind approvals to artifact identity and policy, verify provenance/signatures, re-review meaningful changes and compare repeated scans under equivalent scope. |
| Evidence describes what actually ran | Forged reports, incomplete scans, source/runtime mismatch, misleading safety scores | Record implementation identity, scope, source and collection state; sign/attest evidence where authenticity is required. Missing evidence never establishes safety. |

These are design deductions, not a proof that MCPSense presently enforces them. Even a well-designed guard depends on a trusted operating system, correct implementation and complete mediation of every relevant effect. Unknown implementation flaws can violate those assumptions. The useful objective is to reduce reachable authority and verify explicit properties, not to promise prediction of every future attack.

## Prioritized product work

1. **Implemented in this change:** package-identity/pinning fixes, explicit package/advisory scope, the dated vendor supplement, qualified applicability and configuration-aware remediation. Preserve existing metadata, installer and baseline workflows and verify all current user suites.
2. **Highest next scanner gap:** resolved dependency inventory (lockfiles/SBOMs and actual environments), including SDK/transitive packages, with file provenance, unknown/unresolved states and bounded query budgets. Add version-and-configuration checks for the recent SDK issues. Test vulnerable and fixed branches, opt-in settings absent/present, and unsupported formats. A dependency range must not be treated as an installed version.
3. **Deployment verification:** optional controlled checks using operator-supplied principals/endpoints to exercise audience rejection, per-session ownership and configured resource limits. Avoid destructive/public stress probes; use disposable local test deployments and explicitly scoped fixtures. No such tests were run against third-party services here.
4. **Prevention architecture:** a separate opt-in runtime guard with per-principal capabilities, effect-level allowlists, constrained filesystem/network access, independent approvals for sensitive writes and resource budgets. Back it with OS/container/database/cloud permission boundaries. This is a substantial new product surface, not implemented by adding scanning rules in this change.
5. **Independent evaluation:** rotate withheld attacks and benign workflows, include responses/skills/metadata/argument boundaries and multi-step flows, measure unauthorized effects and useful-task success, and publish reproducible versioned results. The existing authored description suites remain regressions rather than field-accuracy estimates.

Windows signing/protected-device validation remains a separate release gate. This research does not alter protection settings, publish a package, or establish SignPath acceptance. The existing MIT license and user-owned checkpoint file are preserved.

## Validation checkpoint

Local Linux Go 1.22 full tests and vet pass, including the seven original reproductions, option-boundary/exact-pin tests, affected/fixed/unknown vendor versions, empty successful OSV lookups, source/date preservation and explicit advisory disable. The actual CLI passes the ten-invocation research audit, all 24 existing product assertions, all 14 baseline assertions, and beginner/experienced-user acceptance. The existing 164-description and 16-description persona regressions retain their prior outcomes with no observed misses or false alarms in these authored examples; they do not estimate field accuracy. Local packaging/Action tests pass (14 tests, one native wrapper test deferred to CI). Hosted Windows/Linux Go 1.22/1.27 full/race/vet, no-Go npm installation, live/product/baseline/threat-audit scenarios and publication-disabled snapshots remain required before merging. Raw local receipts stay under ignored `bin/` paths.
