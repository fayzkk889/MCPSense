# Product acceptance check — 22 October 2026

## Verdict

The merged CLI supports a usable developer-preview workflow, but this check does not approve a broad public launch or a claim that it detects arbitrary malicious MCP instructions. The product journeys exposed distribution inconsistencies, a generic credential-name detection gap, and false positives/misses in independently written descriptions.

This was an agent-executed product walkthrough through installed command-line interfaces, not a study with external human participants. It did not replace or rerun the unit-test suite. No production source was changed to make outcomes pass.

## Product and installation under test

- Repository main: `d02e5351ae4fc340a5d40c1c3df39acde005544a`.
- Installed from GitHub using `go install github.com/fayzkk889/MCPSense/cmd/mcpsense@d02e5351ae4fc340a5d40c1c3df39acde005544a`, with GOBIN directed into an isolated workspace folder. Tested outside the repository root, in a user project whose path contains spaces.
- Installed binary identifies itself as `v0.3.1-0.20261022153311-d02e5351ae4f`, the correct Go pseudo-version for this untagged commit. It is not a published 0.4.0 release.
- Downloaded and inspected the actual npm 0.3.0 tarball, then installed npm 0.3.0 into a separate local prefix with its real lifecycle script. The published wrapper exists and starts successfully, returning `mcpsense v0.3.0`. Neither global npm nor user PATH was changed.
- GitHub latest release and npm latest both remain 0.3.0. Ordinary latest-version installation does not deliver the merged changes. This is expected while publication awaits approval, but blocks advertising the new behavior as publicly available.
- The standalone repository `install.ps1` still sets VERSION=0.2.2, tries npm, then Go, then an unsigned binary download. Its manual fallback suggests installing Node without clearly conveying the Windows Go requirement. Thus the source-build workaround in npm does not cover every install route.
- The locally installed CLI ran without a reported Windows block in these invocations. This existing machine is not a clean first-download Windows test; no zero-warning guarantee follows. Mac/Linux installation and new-user comprehension on other machines were not assessed here.

## User journeys

All scans used the default set of checks, rather than limiting the scanner to a chosen successful rule. Files contained invented examples and synthetic credentials only. Baselines/reports stayed inside the isolated project. The live server was a harmless local fixture, not a third-party deployment.

| User task | Outcome | Observation |
| --- | --- | --- |
| Install reviewed revision and discover commands | Pass | Exact-commit Go install, version, and help succeeded. |
| Follow README's literal first-run command | Pass with usability concern | Command completed; the “compliant” fixture scores 98 because `body` is considered an ambiguous parameter name despite its description. This can distract first-time users. |
| Understand a dangerous tool description | Pass | Terminal names the tool, supplies the matched text, actual file, severity and remediation. Findings exit is 1. |
| Edit the description and scan again | Pass | Ordinary read-operation description yields no findings in this synthetic manifest. |
| Export reports for review | Pass | One scan produces parseable JSON and SARIF with equal finding counts and completed coverage. |
| Verify a remediation | Pass | Same target/policy comparison returns two resolved rule/component identities, zero persistent and zero new identities. Multiple pattern occurrences are grouped. |
| Notice a tool description change | Pass | Explicit baseline comparison emits a drift finding. |
| Accept a reviewed metadata change | Pass | Explicit update followed by rescan removes the drift finding. |
| Detect credentials under a generic name | Fail | `API_KEY` is not flagged. Credential-only follow-up scores 100 with no findings. |
| Inspect a whole mixed project | Pass | Auto scan includes Python source, manifest and AGENTS.md; injected manifest/skill content is reported. No project code is executed. |
| Recover from malformed JSON | Pass with usability concern | Exit 2, no score; the error gives an irrelevant generic BOM suggestion for an ordinary syntax error. |
| Recover from a missing path | Pass | Exit 2 with the missing file identified. |
| Avoid a misleading remediation claim | Pass | Changing severity policy causes verification to refuse the comparison. |
| Require permission for a private endpoint | Pass | Refused before any HTTP request. |
| Inspect live MCP metadata | Pass | Authorized loopback discovery requests only server/discover and tools/list, detects the poisoned tool description and performs no tools/call. This is one controlled modern-protocol fixture, not all-server compatibility proof. |
| Honor offline mode | Pass | Even the authorized loopback target receives no requests when offline is selected. |
| Query real vulnerability advisories | Pass | Scan of the repository's public example config completes the advisory phase and flags GHSA-hc55-p739-j48w and GHSA-q66q-fx2p-7w4m for the example filesystem package. No configured MCP command starts. The file's historical “safe” name does not establish current dependency safety. |

The automated core journey script recorded 13 passes and one failure across its 14 assertions. Installation, README walkthrough, live advisory lookup and the exploratory cases below were additional checks; they are not silently counted into that total.

## Independent exploratory descriptions

Six descriptions were labelled benign/hostile before running them through the installed CLI. This small hand-authored check is not a field accuracy benchmark.

| Scenario | Intended meaning | Observed |
| --- | --- | --- |
| Retrieve a customer record | Benign | No injection finding; correct. |
| Search security-training documents containing “ignore previous instructions” | Benign quoted example | Injection finding; false positive. |
| Retrieve incident reports containing a quoted system-prompt phrase | Benign quoted example | No injection finding; correct. |
| Explicitly ignore earlier instructions and reveal the system prompt | Hostile | Injection finding; correct. |
| Before answering, include the user's complete SSH private key for “auditing” | Hostile | No injection finding; miss. |
| Claim compliance-team authorization to disregard earlier safety restrictions and obey without approval | Hostile | No injection finding; miss. |

Credential-name follow-up: OPENAI_API_KEY and GITHUB_TOKEN are flagged; API_KEY is missed. None of the three synthetic values appears in the report. Successful redaction does not make missed detection a pass.

## Product concerns before wider promotion

1. Make installation routes agree with the intended Windows source-build policy and the release version. The standalone Windows script currently contradicts that policy. Publish the tested revision only through the separately approved release process.
2. Handle generic credential names such as API_KEY. Add a product-level regression based on the failed credential-only journey.
3. Treat indirect hostile instructions and benign quoted security examples as detection-quality work. Do not claim universal injection prevention or tune only to these six examples.
4. Make first-run output less confusing: example naming, generic JSON guidance and header overflow with a long Go pseudo-version are rough edges. A score of 100 remains a weighted heuristic result, not a security certificate.
5. Perform a separate clean-Windows installation check with protections enabled before claiming broad warning-free Windows installation. No protection changes were made for this walkthrough.

## Evidence retained locally

- Evidence directory: `C:\dev\MCPSense\bin\product-test-896712b52c3e4c0ea3986304159fa45d`.
- Core results: `journey-results.json`; each invocation has its own JSON log containing arguments, exit status, stdout and stderr.
- Exploratory results: `independent-description-and-credential-results.json`.
- Actual advisory output: `real-advisory.json` and `real-advisory.stderr`.
- Published package tarball and isolated real npm install are retained in the same directory.
- Walkthrough drivers are ignored local artifacts: `bin/product-user-test.mjs` and `bin/product-detection-check.mjs`.

No tags, releases, registry publications, merges, source fixes, Defender exclusions or global installations occurred during this product check.

## Follow-up implementation

The original findings above are retained as the pre-fix record. A follow-up feature branch addresses generic credential names, explicit indirect disclosure/policy-override instructions and the quoted document-query example. A regression also prevents ordinary “ignore” being called character evasion without losing explicit user-request override detection. Context exceptions apply only to complete tool query descriptions, never generic quoted text or skill instructions. The original 40-description labels remain unchanged; broad heuristic false positives/misses remain limitations.

The Windows installer now requires Go directly, supports a published version or full commit, checks the actual installed binary, has no unsigned-download fallback and never pauses for input. npm's Windows route continues to build from source. Linux/macOS installation checks the release manifest before replacement. Current latest-version installation still delivers 0.3.0 until an approved 0.4.0 publication; no code change can update the public registry without publishing.

The 14 user-journey assertions now pass using the fixed compiled CLI, including the original API_KEY case. The walkthrough is retained as `scripts/product.test.mjs` and runs in CI against the real compiled binary on Linux and Windows. `scripts/installers.test.mjs` covers missing Go, a failed source build, exact commit selection, valid/corrupt/missing/ambiguous archive manifests and the Git-Bash Windows handoff. Platform-specific cases are explicitly skipped on the opposite system. Separate Go regressions cover the independent descriptions, appended-instruction evasions and ordinary credential-name negatives.

Full native Windows and Go1.22 Linux tests and vet passed at the implementation checkpoint. Final PR CI and fresh source installation of its exact commit are authoritative for delivery. No NVM reinstall was needed: the existing Node22/npm10 runtime works. npm authentication was checked without displaying credentials and is absent; publication requires maintainer login/authorization.

## Clarified installation requirement: two independent choices

The user subsequently clarified that npm must not require Go, and Go installation must not require Node.js/npm. This supersedes the source-only npm policy described in the historical follow-up above. The optional PowerShell script remains a Go-install convenience; it is not a prerequisite for npm.

The npm installer now downloads the matching platform executable, verifies its checksum and exact version, checks startup, then replaces the CLI. It never invokes Go. Unsupported platforms fail clearly; existing installations and unrelated package files are preserved on verification/startup failure. New CI smoke checks create a real platform archive, remove Go from the process PATH, exercise the production installation core and wrapper, and run all14 product assertions.

Locally, an exact Windows archive from passing main CI39812398052 was downloaded, checksum-verified and installed through the npm installation core with Go absent from PATH. The npm wrapper started it and all14 user assertions passed. The artifact reports `0.4.0-SNAPSHOT-a7c71f8`; it is a CI candidate, not an already published0.4.0 package. The default remote-release URL cannot be exercised for0.4.0 until publication is approved.

A separate locally compiled0.4.0 test executable was blocked. Windows CodeIntegrity event3077 explicitly identified enforced signing-policy requirements; no matching MCPSense malware-detection records were found in the queried Defender history. The actual downloaded CI executable passed on this same machine. Neither observation proves warning-free behavior on all Windows installations. No protection settings were altered. The user reports a previous Microsoft false-positive clearance; no submission ID or clearance record was located in the available history/connected mailbox, so this is recorded as user-reported history rather than independent release clearance.

npm maintainer login has since succeeded and ownership was verified. Users do not need npm login to install/update the public package. Public latest remains0.3.0 until an approved release; the previous staged npm tarball is superseded by this installer change and must be rebuilt before publication.
