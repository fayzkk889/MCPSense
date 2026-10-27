# MCPSense 0.4.2

## Security inspection changes

- Replace phrase-specific matching for five reproduced failure families with shared, clause-scoped action/object/polarity analysis: authority promotion, identity substitution after denial, false success reporting, security-warning suppression and weakened approval safeguards.
- Prevent literal metadata patterns from borrowing unrelated facts across sentences. Require ownership or privileged context when detecting requests for the model's own instructions.
- Enforce the original missed cases and broader frozen validation cases in native and installed npm product checks, retaining older expectations. Seven description datasets also run in fast detector tests with case and prefix variations. These are development regressions, not field-accuracy estimates.

## Optional metadata reference check

After inspecting the target through a trusted workflow, explicitly capture a protected local reference:

```sh
mcpsense scan ./manifest.json --offline --baseline ./operator-baseline.json --update-baseline
```

Require later recognized metadata to match that reference:

```sh
mcpsense scan ./manifest.json --offline --baseline ./operator-baseline.json --require-metadata-baseline
```

The check rejects missing/incomplete references and recognized-catalog additions, removals or changes with exit 2, independently of wording. It cannot simultaneously create/update/skip its reference, and severity/rule filters cannot bypass it. Older snapshots remain usable for ordinary drift comparison but need a separately reviewed recapture before this strict check can be used.

The reference is a trusted local input, not a signature or proof of human review. Unknown extensions, runtime results, fetched contents, process containment and host permissions remain outside this metadata check. Authorized local live discovery may start the selected process before metadata can be compared; this is not an execution sandbox.

## Reports and compatibility

JSON adds `security_assessment`; SARIF carries the equivalent `securityAssessment` property and the terminal displays the state. No findings means `not_established`; findings mean `review_required`. Host authorization is never claimed to be enforced by the scan. Existing finding scores, schema 2 and exit codes 0/1/2 remain compatible; a high score is not a safety verdict.

Detector identity changes. Generate both remediation reports with the same reviewed scanner version and equivalent coverage; upgrading the detector alone is not proof that a target was fixed.

## Installation and update

Choose one route:

```sh
npm install -g mcpsense@latest
```

Requires Node.js 22+; Go, archive tools and a MCPSense native executable are not required. Users do not need an npm account.

```sh
go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest
```

Requires Go 1.22+ for language compatibility, without Node/npm; use a current patched Go compiler. Native Windows archives remain unsigned and subject to device policy. No route disables security settings or guarantees universal absence of warnings. MIT and the bundled Go runtime license are preserved.

## Verification and limits

Final main `14a8b957d90fbd321c20f09fbcd7e3178df68031` passed all 14 [release CI jobs](https://github.com/fayzkk889/MCPSense/actions/runs/40452217107): native Windows/Linux tests and race checks, npm Windows/Linux/macOS on Node 22/24, lint, GitHub Action execution, five-target archive dry run, and fresh six-target Go vulnerability analysis. The complete installed npm product suite also passed locally, including 104 authored boundary observations and 12 required-reference journeys. The exact Ubuntu/Node 22 artifact passed 13 anonymous Windows installation/upgrade checks without Go or archive tools. The tag-triggered [publication workflow](https://github.com/fayzkk889/MCPSense/actions/runs/40452848413) repeats the audit and installed product suite before publishing native archives. These are bounded test results, not field-accuracy estimates.

The dependency audit retains a documented indirect advisory, GO-2026-5024, in golang.org/x/sys/windows. Source reachability and symbol-preserving binary checks found no call to the affected NewNTUnicodeString function; it is absent from the linked symbol inventory. The npm js/wasm target had no advisory finding. This is a triaged non-reachable dependency warning, not a claim that the dependency version contains no advisories. CI and publication gates repeat both checks. Details and the stripped-binary scanner limitation are recorded in release readiness.

Metadata inspection can miss hostile language and flag benign content. It does not provide universal attack prevention, authenticate servers or enforce runtime permissions. See the [root-cause investigation](https://github.com/fayzkk889/MCPSense/blob/v0.4.2/docs/engineering/detection-root-cause-2026-10-26.md) and preserved [public 0.4.1 test failures](https://github.com/fayzkk889/MCPSense/blob/v0.4.2/docs/engineering/user-test-2026-10-26.md).


## npm artifact identity

The public npm tarball is the tested final-main Ubuntu/Node 22 CI artifact:

- SHA256: `36271c978477042fd71669aee15fc5e4f9c2b0fe97fa36ce9bad752039d4db2e`
- Integrity: `sha512-b/4CAGizLAWdHYN7rcTBnmbUz4WvuHxQaH8jnJ7s5IgFrYnRljMzvtMzFetU/DF/3IdgDIHAg3MFh5Kj3JpA/A==`

Public download, installation and channel-verification results are recorded in the [release record](https://github.com/fayzkk889/MCPSense/blob/main/docs/engineering/release-0.4.2-2026-10-27.md). The tagged preparation documents retain their original pre-publication status.
