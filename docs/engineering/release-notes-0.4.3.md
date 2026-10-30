# MCPSense 0.4.3

This patch addresses the hostile-description misses and benign false alarms reproduced in the public 0.4.2 product audit. It also makes a reviewed advisory-source disagreement explicit instead of presenting uncertain applicability as an ordinary affected-version match.

- Track bounded credential source/transform/destination relationships, including explicitly referenced notes, bundles and encoded payloads.
- Inspect disabling monitoring settings, empty escalation destinations, no-op replacements, evidence downgrading, downloaded-code execution and contradictory safeguard claims.
- Preserve negation and literal-query context while retaining detection of subsequent active instructions and concealed hostile behavior.
- Require 232 frozen native/npm description observations, composition and benign controls, and deterministic metadata-reference workflows.
- Export advisory identity, applicability and source evidence in JSON and SARIF. The exact reviewed Tensorlake 0.5.143 disagreement retains its warning and severity as `conflicting_sources`; 0.5.144 remains flagged. No advisory is silently excluded. Other package/version/advisory identities do not inherit this review.

Install or update with either independent route:

```sh
npm install -g mcpsense@latest
# Or, for Go users:
go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest
mcpsense version --check
```

npm requires patched Node.js 22+ and no Go compiler, archive utility, MCPSense native executable or installation hook. Go remains independent of Node/npm. The MIT license is unchanged. Optional native Windows archives remain unsigned and may be restricted by device policy.

These are bounded inspection improvements, not semantic verification or universal attack prevention. Authored regression results are not field accuracy. Initial trust, runtime authorization, tool-result behavior and unsupported surfaces still require host/operator controls. A clean report does not authorize a server.

Primary advisory evidence: [publisher](https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2), [OSV record](https://osv.dev/vulnerability/MAL-2026-17650). A disagreement remains a review requirement, not confirmation of infection or proof of safety.
