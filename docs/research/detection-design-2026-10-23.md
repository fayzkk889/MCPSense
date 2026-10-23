# Detection and delivery design — 23 October 2026

## Principles and primary sources

The product inspects metadata and local files. It cannot establish what an agent will execute, whether a host enforces authorization, or whether a server's advertised behavior is truthful. Detection is evidence for review, not an execution barrier.

- [OWASP prompt-injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) distinguishes input screening from authorization controls, discusses false positives, indirect instructions, encodings and language variation, and calls for benign as well as hostile evaluation. This supports testing action/object/context combinations rather than treating security vocabulary as inherently hostile.
- [Anthropic's prompt-injection research, 24 November 2025](https://www.anthropic.com/research/prompt-injection-defenses) describes remaining risk and adaptive attacks. A finite successful corpus does not establish universal robustness.
- [MCP tool specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) describes host control and human oversight. Advertised metadata is insufficient to establish enforced permissions.
- [Node's execFile documentation](https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback) distinguishes direct executable/argv invocation from shell interpretation. A literal ampersand or JSON argument is not proof of injection. The same distinction informs the config review rule, without assuming all MCP hosts use Node.
- [npm distribution-tag documentation](https://docs.npmjs.com/cli/v11/commands/npm-dist-tag/) and [GitHub release documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/automatically-generated-release-notes) establish separate published-version channels. Pushing source does not move npm latest or publish a Go version tag. Release verification must check the delivered channels and archives.

These sources motivate the implementation; they do not validate MCPSense's measured accuracy or certify its safety.

## Implemented approach

Keep the local deterministic scanner and its two independent install choices. No cloud account, API key, model download or extra runtime is introduced. Add bounded directive families covering task/authority replacement, credential disclosure, false reporting/concealment, answer substitution, persistent instruction edits, permission bypass and cross-tool transfer. Small Spanish/French/Hindi pattern sets cover the tested wording; this is not general translation or language coverage.

Tool-metadata context recognizes constrained document queries, defensive negation and inert documentation clauses. It does not exempt arbitrary quotation, an “example” label, skills or source. A later directive is scanned even after a benign prefix. Additional action verbs, colon/dash continuations and appended attacks have regressions. Such lexical context can still misclassify natural language; no full parser or semantic understanding is claimed.

A second pass strips format controls, folds full-width ASCII and a limited confusable alphabet, and recognizes selected letter-spaced trigger words. Evidence retains original input spans, with Unicode regression and fuzz checks. This is not all-encoding normalization or a guarantee against obfuscation.

Config execution review examines actual interpreter names and code-evaluation flags. It reports explicit shell/inline-code use as high-severity review evidence, not critical proven command injection. Separate argv values and substrings in ordinary paths do not establish shell use. Config scans never execute their entries.

Terminal output retains the machine-compatible score and JSON format but labels the human score as a finding score, displays the full installed version, and explains that it is not a probability of safety. `version --check` explicitly queries public GitHub/npm version metadata with deadlines and bounded JSON. Ordinary version/startup/offline scans remain offline. Lookup failure and channel disagreement are visible, and no automatic upgrade occurs.

## Evaluation discipline

The original40 and earlier60 descriptions are now development/regression data. Their labels and text remain unchanged. A further40 descriptions were labelled before implementing this change and run only after the main detector was built. Their first-run results are retained separately. Improvements on reused data are regression progress, not independent evidence. All are agent-authored synthetic examples; external users and representative deployment traffic remain untested.

CI exercises real CLI journeys and all140 descriptions on Windows/Linux with both supported Go toolchain versions. The explicit regression budget requires no missed labelled hostile case, no false alarms on the development sets and at most two on the40-case validation set. This preserves the observed boundary; it is not a field-accuracy threshold. Public packaging has an additional read-only gate checking tag/package alignment, npm/GitHub latest, all five archive names and their checksums. Runtime installation remains a separate test.
