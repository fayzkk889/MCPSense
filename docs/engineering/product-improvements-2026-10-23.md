# Product improvement checkpoint — 23 October 2026

This follows the [failing acceptance evaluation](product-acceptance-2026-10-23.md). Historical results are preserved; production fixes address the observed causes rather than changing labels. Source and test evidence are pushed on `codex/product-acceptance-2026-10-23`.

## Changes

- Literal argv data no longer becomes a critical injection claim. Shell/interpreter flags are recognized on both OS path styles; explicit code evaluation is a review signal with an honest limitation.
- Added directive families and bounded metadata context; reduced bare credential-word false alarms; added Unicode/letter-spacing normalization with original evidence spans. This remains deterministic heuristic inspection, without new dependencies or user setup.
- Installed version and safety-score interpretation are clearer. `mcpsense version --check` compares public GitHub/npm channels only on explicit request.
- README exposes both live publication badges, latest-install/update commands and the distinction between source and public releases. Release tooling validates tags/package version and public archive/channel alignment. It never publishes by itself.
- Expanded user and live-server scenarios and description evaluation run in every Windows/Linux Go1.22/1.27 CI matrix.
- Review reproduced a further defect: an unchanged target looked remediated after replacing the scanner. Reports now include a rule-source/toolchain fingerprint, and verification refuses missing/different fingerprints. Unit tests and a real old/new-binary reproduction cover this guard. Older reports need both scans recreated with one detector.

## Local executed evidence

All Go tests and vet passed on Linux Go1.22.12. Detection/check suites passed again after conservative context-escape hardening. A15-second fuzz exercise made10,388 executions without an evidence-span failure. Windows Application Control blocked a generated native test executable during this work; that invocation is not a pass. Hosted matrix results are required for final Windows verification.

The real compiled CLI passed all24 expanded product assertions after the config fix. The13 Action/npm Node tests completed with12 pass and one explicit missing-binary skip; hosted tests additionally provide the actual binary and exercise the real archive/wrapper.

First evaluation after the main detection implementation, before final negation/escape hardening:

| Corpus | Injection TP / FN / FP / TN | Any-security TP / FN / FP / TN |
| --- | --- | --- |
| Original40 development | 20 / 0 / 0 / 20 | 20 / 0 / 0 / 20 |
| Earlier60 development | 30 / 0 / 0 / 30 | 30 / 0 / 1 / 29 |
| Frozen40 validation, first run | 20 / 0 / 2 / 18 | 20 / 0 / 2 / 18 |

The validation result is100% recall,90.9% precision and95% accuracy **on these40 synthetic examples only**. No general accuracy or “catches everything” guarantee follows. The two benign false alarms remain an explicitly allowed validation limitation; examples are not relabelled. First-run evidence is retained in `bin/product-improvement-validation-2026-10-23/`. The final CI/product rerun is authoritative for the final committed source.

The read-only public release gate correctly failed because public latest was0.3.0 while the candidate package is0.4.0. This is not cleared by a code push. Publication and a real public install/update walkthrough remain separate from source availability and require the user's previously specified publication approval.

## Remaining limits

Pattern screening can miss novel phrasing, encoded payloads and unsupported languages, or flag benign wording. Skills/source do not receive tool-data exemptions. This scanner is not a runtime authorization control, exploit verifier or general semantic classifier. Clean-Windows first-download behavior, macOS/arm runtime and external human usability remain unverified. MIT and independent npm/Go routes are preserved; protections are not changed.
