# Reproduce the launch demonstration

These four synthetic tool descriptions come unchanged from the existing frozen value-identity corpus. The scanner reads their text; it does not perform the instructions, read a token, contact a collector or call a tool.

The verifier writes four manifests and their reports under ignored `bin/launch-045-demo/`. With the public npm 0.4.5 installation, run:

```powershell
node docs/launch/2026-11-02/demo/verify.cjs --runner "$env:APPDATA\npm\node_modules\mcpsense\bin\run.js"
```

For a different global prefix, pass its actual installed `bin/run.js` path. Node.js 22+ is the npm route's existing runtime, not an additional demo dependency. Native Go users can scan the generated JSON manifests directly.

Example after generating the files:

```sh
mcpsense scan ./bin/launch-045-demo/q7-flow-h.json --offline --no-baseline --checks SEC-001,SEC-011
mcpsense scan ./bin/launch-045-demo/q7-flow-b.json --offline --no-baseline --checks SEC-001,SEC-011
```

Expected: the token/cookie transfers produce findings and exit 1; the public-status/fixed-placeholder counterparts remain quiet on the selected security checks and exit 0. A finding reports a review signal. It does not prove runtime blocking or reproduce an observed Black October compromise.
