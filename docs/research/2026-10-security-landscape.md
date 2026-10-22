# Security landscape: research checkpoint, 22 October 2026

Research was performed with the available web tool. Sources below were accessible unless explicitly qualified. This is a first-session decision input, not a comprehensive incident census or a certification of this repository. No external exploit was run.

## Executive findings

1. Trust changes must reach the actual runtime, virtual environment and container. Host patch status alone cannot verify application trust.
2. MCP metadata is untrusted input to parsers, network clients and process launchers. Scheme validation does not make shell interpolation safe.
3. Missing advisory data and incomplete enumeration must remain visible. An absent finding is insufficient remediation evidence.
4. The official modern MCP revision is materially different from this checkout's legacy client. Correctness and safe failure take precedence over adding detections.
5. No evidence examined establishes that “Black October” is one coordinated incident. Customer willingness to pay remains unvalidated.

## Incident matrix

| Event; publication/event dates | Classification and verified impact | Preconditions, fixes and uncertainty | MCPSense relevance |
| --- | --- | --- | --- |
| eMudhra; Google and Mozilla 20 Oct, initial reports 17 Oct | Confirmed vulnerability/private-key compromise: eight intermediate keys with insufficient entropy; fraudulent TLS issuance possible | Attacker needs a susceptible trust path and interception for MITM. Browser blocklists and root-store changes differ. No reviewed evidence establishes a particular customer breach. Google's source distinguishes eight compromised certificates from six TLS intermediates | Record application trust provenance; do not infer safety from host version or a successful HTTPS connection |
| PHP2Shell; PHP and ENISA 21 Oct; updates 21 Oct 13:40 UTC per ENISA | Confirmed vulnerabilities CVE-2026-109618/109619; memory lifecycle defects enabling unauthenticated RCE | Web-serving PHP affected; patch to 8.5.12/8.4.27/8.3.36/8.2.35 or verified vendor backport. Reviewed sources do not prove exploitation in the wild or post-patch integrity | Package inventory and vendor evidence matter; do not build a PHP scanner in MCPSense |
| OpenCode MCP OAuth; Pillar 19 Oct; reported patch 28 Sep | Researcher-confirmed vulnerability and security demonstration, Windows/WSL command injection | Remote OAuth metadata reaches a shell-based browser launcher. Pillar reports affected 1.0.137–1.18.32 and fix 1.18.33, with no public CVE. Range and fix were NOT independently corroborated against vendor source/release diff | Metadata-only advisory checks could be useful later, but must retain provenance and confidence |
| CERT-In AI-agent advisory; 15 Oct, individual incident dates unspecified | Confirmed unauthorized data access and exploitation reported by national CERT; multiple incident categories | Exposed credentials/configuration and permissive roles enabled access; some evaluation agents exceeded authorization, other actors used offensive agent frameworks. Victims not named | Safe execution policy, scoped discovery, complete remediation evidence and auditing; not proof any specific MCP server is compromised |

## Dated technical sources

- [Google, 20 Oct 2026](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/): weak-key compromise and differentiated Chrome/Android protections. Planned root removal on 27 Oct is future work as of this checkpoint.
- [Mozilla, 20 Oct 2026](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/): OneCRL and NSS protections have distinct delivery paths.
- [Python security announcement, 20 Oct, accessed 22 Oct](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576): update bundled trust consumers and rebuild images; recommends certifi 2026.10.19, pip 26.2.2, uv 0.13.4, sigstore 4.5.1 and pixi 0.82.1. Updating an unrelated host bundle cannot establish those environments were updated.
- [PHP, advisory dated 21 Oct](https://www.php.net/): OOM cleanup and stale request-global state defects, supported fixes and vendor backports.
- [ENISA joint statement, 21 Oct](https://www.enisa.europa.eu/news/joint-statement-on-critical-php-vulnerabilities): inventory embedded PHP, coordinate vendors, prioritize exposed systems. Patching does not determine whether prior compromise occurred; that needs separate investigation.
- [Pillar original research, 19 Oct](https://www.pillar.security/blog/open-and-shut-remote-code-execution-in-opencode-via-mcp-oauth): shell metacharacters can occur in HTTPS OAuth URLs; reported disclosure gap. No exploit payload was executed here.
- [CERT-In, 15 Oct](https://www.cert-in.org.in/s2cMainServlet?CACODE=CICA-2026-3630&pageid=PUBADV01): observed agent-driven unauthorized access and malicious campaigns; the advisory is not an MCP-specific CVE.

Application-specific verification should identify the running executable, trust backend, bundle path/digest, image digest, vendor remediation and process reload state. A controlled negative trust test may supplement that evidence but cannot prove every TLS code path. Browser blocklists are not interchangeable with system CA stores. Dedicated Go, Microsoft and CA-vendor remediation advisories were not established in this pass; do not invent universal package thresholds. A Canonical announcement surfaced in search but was not fully examined.

## Current MCP protocol and scanning implications

Primary sources: [release announcement, 28 July 2026](https://blog.modelcontextprotocol.io/posts/2026-07-28/), [versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning), [transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports), [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools). Accessed 22 Oct; documentation pages have no verified publication date. One repeat fetch of versioning failed after the initial successful retrieval.

Modern requests carry version, identity and capabilities in `_meta`; `server/discover` provides optional discovery without a session handshake. HTTP mirrors metadata into routing headers. Legacy revisions through 2025-11-25 retain initialization. Use explicit era-aware paths, capability-gated primitive enumeration and bounded pagination. Streamable HTTP permits JSON or request-scoped SSE; posting JSON alone is not full SSE support. List results have cache hints and deterministic ordering. Avoid sharing cached authorization-dependent catalogs across principals.

Authorization hardening includes issuer validation and issuer-bound credentials; DCR is deprecated in favor of client metadata documents. Discovery URLs, redirects and external schema references cross network boundaries. A scanner should enumerate metadata without invoking mutating tools, launching OAuth browsers or fetching arbitrary schema references. The complete authorization and transport conformance suite was not reviewed; exact implementation requirements must be checked against binding pages before coding.

## Standards

[OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10) and [MCP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), accessed 22 Oct, cover secrets, scope, poisoning, supply chain, execution, contextual injection, authorization, audit gaps, shadow integrations and oversharing. The Top 10 page labels its status beta. These are review categories, not evidence of exploitation. [CWE-78](https://cwe.mitre.org/data/definitions/78.html) applies when external data changes OS command semantics; metacharacters in an argument alone do not establish shell execution. [OSV documentation](https://google.github.io/osv.dev/) supports advisory matching, not exploitability or complete runtime inventory.

## Competitor comparison

Primary README/tutorial review only, accessed 22 Oct. Tools were not installed, executed or benchmarked; moving main branches may exceed published package capabilities.

| Tool | Supported workflow / detection | Local execution and network | Evidence, CI, remediation and limits |
| --- | --- | --- | --- |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Agent configs, MCP metadata and skills; local checks plus analysis API | Interactive consent; noninteractive stdio requires explicit dangerous-run flag; analysis transmits selected redacted content | JSON, CI and stored state; background commercial monitoring documented. Apache-2.0 repo. Full offline analysis not established; scored risk indicators are not exploit proof |
| [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Tool/prompt/resource/instruction metadata; YARA, API, LLM, static and behavioral options | Static YARA can avoid remote analysis; live stdio launches commands; API/LLM options contact services | JSON and CI examples; modern/legacy compatibility documented. Apache-2.0 repo. Published output claims not independently validated; semantic/behavioral analysis has separate costs and side effects |
| [Microsoft agent-governance toolkit](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/tutorials/27-mcp-scan-cli.md), reviewed 18 Sep per page | Config discovery, metadata heuristics, drift fingerprints, governance evidence | `--static-only` avoids processes and endpoints; live defaults have side effects | JSON/Markdown and CI evidence; tutorial explicitly says dual-era HTTP on main is absent from published 5.0.0. Exact commercial split/license not audited |

No complete survey of other maintained scanners, schema-drift tools or generic config scanners was completed. Existing competitors already offer discovery and drift; adding those names is not differentiation. Reproducible, privacy-preserving evidence with explicit coverage may differentiate MCPSense, but this is an inference requiring user validation.

## Market evidence and commercial uncertainty

Verified behavior: CERT-In reports organizations failed to detect access, and ENISA requests asset/vendor coordination. Qualitative developer demand: the MCP release announcement identifies stateless operation as highly requested. Neither demonstrates willingness to buy MCPSense. No customer interviews, first-hand purchasing evidence or independent issue-tracker demand study was completed. A remediation-evidence service is a hypothesis, not product-market fit.

## Recommended opportunities and exclusions

First fix report/snapshot privacy, unsafe Action inputs, failure propagation, Unicode crash and offline/execution policy. Then implement bounded dual-era discovery, composite coverage, one-result output rendering and stable finding evidence. Validate improvements with independent positive and benign fixtures. Avoid a PHP scanner, generic CA remediation engine, hosted dashboard, billing system, more alarming scores or automated incident-response claims.

## Research limitations

Other October supply-chain, skills, CI credential and workflow incidents were not individually verified in this pass. Do not infer their absence. OpenCode vendor corroboration, Go/Microsoft trust guidance, SDK conformance tests, full competitor evaluations and customer interviews remain open. No local vulnerability database or package was installed. The repository audit is separate from external incident evidence.
