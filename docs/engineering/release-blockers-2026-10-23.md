# Release-blocker fixes — 23 October 2026

This follows the [failing persona retest](persona-retest-2026-10-23.md). Its original failures and labels remain available. PR8 contains the fixes; publication is a separate approval boundary. Nothing here establishes universal detection, field accuracy or warning-free Windows installation.

**Superseding Windows installation result:** all seven jobs passed for implementation commit `eda1d70`, including both native hosted Windows matrices and real archive installation without Go. However, the exact verified CI Windows snapshot failed startup on the local machine during installation. Event3077 identifies Smart App Control policy `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`; its executable is unsigned. This is a remaining public-release blocker for the requested Windows experience. See the [confirmed cause and signing prerequisites](windows-signing-readiness-2026-10-23.md). Passing hosted CI does not clear it.

## Installation and first use

The 0.4.0 npm installer already downloads a prebuilt platform executable, verifies the archive checksum and tests startup/version before replacing an installation. It does not invoke or install Go. Automatically installing a compiler would add downloads, platform changes and failure modes without helping this route. The separate Go installation remains available without npm. The public 0.3.0 npm package has the old Windows Go dependency; pushing source does not change that package. A successful public 0.4.0 installation can only be verified after approved publication.

`mcpsense --version` now works. `mcpsense init --example` creates a synthetic offline target without overwriting an existing file, then prints a working scan command. Plain `init` explains that scanner settings are different from the server being inspected. Both READMEs use this reproducible first-run path and explain how to select a real configuration.

## Why descriptions were missed

The scanner previously inspected primarily tool descriptions. Attack text placed in schema strings, server instructions, resource descriptions or prompt descriptions could escape inspection entirely. Text that reached the detector could still avoid literal patterns by expressing the same authority transfer with different words. Conversely, negated safety guidance and permitted audit retention could trigger rules whose evidence did not establish hostile behavior.

The metadata check now enumerates server description/instructions; tool names, titles and descriptions; input/output schema strings and keys; annotation titles; resource names, URIs and descriptions; and prompt names, descriptions and arguments. Malformed nested JSON or inspection limits fail the scan. Reports disclose these fields and explicitly list unassessed runtime outputs, resource contents, prompt bodies and unknown extensions. Enumeration never invokes an advertised tool or follows a schema reference.

Six additional families combine lexical action, object and scope signals: server authority over the operator, session-wide routing, disclosure of sensitive material, deceptive answers, alternative capabilities after permission refusal, and persistent policy changes granting future authority. Existing literal rules remain. Constrained negation/document-query handling reduces false alarms; a defensive first verb cannot exempt an appended relational directive. Evidence uses original input bytes and bounded excerpts for relational matches. These are still heuristics, not semantic understanding: distant unrelated terms can combine, authorized tasks can resemble attacks, and novel wording can escape them.

The underlying security issue is promotion of untrusted server text into authority over the user's task. A standalone metadata scanner cannot observe the user's complete authorization or enforce a host's tool permissions. [NCSC's analysis](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection) explains why treating this as ordinary input sanitization is insufficient. [OWASP's guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) supports layered screening, separate controls and adversarial evaluation. [CaMeL](https://arxiv.org/abs/2503.18813) instead investigates host-level control/data separation and capability enforcement. These motivate honest scope reporting and host authorization; they do not justify advertising a regex scanner as a prevention boundary.

[Anthropic's adaptive-attack research](https://www.anthropic.com/research/prompt-injection-defenses) further supports testing evolving attacks rather than treating one passing benchmark as proof. The [MCP schema](https://modelcontextprotocol.io/specification/2025-11-25/schema) identifies the additional instruction and schema surfaces. Research was consulted on 23 October 2026; no third-party performance numbers are attributed to MCPSense. No cloud service, model account or extra user dependency was added.

## Source evidence

Formatted arguments passed directly to an executable are no longer called critical shell injection merely because they use formatting. Recognized Go calls use syntax-tree inspection to identify an explicit shell and command flag; malformed source does not crash that check. Python subprocess screening masks comments and single/triple-quoted literals and distinguishes `shell=True`/explicit shell command lists from direct argv. This is lexical Python analysis, not complete parsing, taint analysis, alias tracking or exploit verification. Other source checks remain heuristics. Findings ask for review of data reaching shell evaluation.

## Measured checkpoint

The first relational implementation evaluation caught all 82 hostile examples across the unchanged 40 + 60 + 40 + newly pre-labelled 24 description cases, with zero false alarms among their 82 benign cases. The separate persona rerun caught its eight prior misses with zero false alarms among eight benign descriptions. All 24 expanded product assertions and the enforced beginner/experienced-user checks passed. These small authored sets overlap in concepts and are development/regression evidence, not independent field validation. The new 24 cases were labelled before implementation, but their families reflect the prior persona investigation; this limits independence.

Focused regressions additionally cover defensive-prefix escapes, quoted research queries, approval-requiring policy edits, exact bounded Unicode evidence, invalid/deep/oversized metadata, safe argv, explicit shell formatting, multiline Go/Python, Python comments/docstrings, and malformed Go. Full Linux Go1.22 tests and vet pass. Local Action/npm tests pass (12 passed, one explicitly skipped without a native binary); hosted checks supply real binaries and exercise npm archive installation with Go absent.

Final exact-commit CI, native Windows runtime, packaging and live-server results must be read with the PR checks and subsequent delivery checkpoint. An initial sandboxed Node run failed archive renames with EPERM; the identical tests passed outside that sandbox. A blocked or skipped invocation is not counted as a pass.

## Remaining boundaries

- A clean scan is a bounded inspection result, not evidence that every description is safe. Unsupported paraphrases, languages, encodings and contextual attacks remain possible.
- Baseline drift coverage is narrower than metadata screening; not every newly inspected field has comprehensive drift analysis.
- Report fingerprints enforce scanner equivalence; unsigned JSON can still be edited and is not an attestation.
- Windows reputation/policy can change and cannot be guaranteed by packaging. No protections are disabled. macOS/arm64 archives are cross-built; native runtime remains unverified here.
- Public npm/GitHub/Go delivery remains on 0.3.0 until an approved 0.4.0 publication. Release preparation and passing candidate tests cannot substitute for a public install/update test.

## Reproduction

Use a reviewed compiled CLI as `MCPSENSE_TEST_BINARY`. Run `node scripts/persona-acceptance.mjs` with `MCPSENSE_ENFORCE_PRODUCT=1`, and `node scripts/product-acceptance.mjs` with `MCPSENSE_VALIDATION=1`, `MCPSENSE_INTENT_VALIDATION=1` and `MCPSENSE_ENFORCE_PRODUCT=1`. The scripts keep raw synthetic reports under their configured evidence directories. The live script uses harmless local peers, including poisoned instructions over legacy and modern discovery, and verifies that no advertised tool is called. CI enforces these scenarios on Windows/Linux Go1.22/1.27 together with race tests, vet, installers, real Action/SARIF and a publication-disabled release snapshot. MIT is preserved.
