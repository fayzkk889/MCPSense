# Reproduce the launch demonstration

These four synthetic tool descriptions come unchanged from the existing frozen value-identity corpus. The scanner reads their text; it does not perform the instructions, read a token, contact a collector or call a tool.

The verifier writes four manifests and their reports under ignored `bin/launch-045-demo/`. With the public npm 0.4.5 installation, run:

```powershell
node docs/launch/2026-11-02/demo/verify.cjs --runner "$env:APPDATA\npm\node_modules\mcpsense\bin\run.js"
```

For a different global prefix, pass its actual installed `bin/run.js` path. Node.js 22+ is the npm route's existing runtime, not an additional demo dependency. The four JSON manifests are also committed in `cases/`, so native Go users can run the commands below without Node.js or generating files.

Inspect the committed manifests directly:

```sh
mcpsense scan ./docs/launch/2026-11-02/demo/cases/q7-flow-h.json --offline --no-baseline --checks SEC-001,SEC-011
mcpsense scan ./docs/launch/2026-11-02/demo/cases/q7-flow-b.json --offline --no-baseline --checks SEC-001,SEC-011
```

Expected: the token/cookie transfers produce findings and exit 1; the public-status/fixed-placeholder counterparts remain quiet on the selected security checks and exit 0. A finding reports a review signal. It does not prove runtime blocking or reproduce an observed Black October compromise.
