# Synthetic remediation verification

Build this reviewed branch. On Linux/macOS or WSL:

```sh
go build -o bin/mcpsense ./cmd/mcpsense
bash docs/engineering/remediation-demo.sh "$PWD/bin/mcpsense"
```

The script creates one temporary manifest, scans a synthetic instruction override, checks the findings exit status (1), replaces the description with an ordinary read operation, and scans the same target and policy again (exit 0). It writes JSON and SARIF from the same after-scan, then invokes offline verification. It contacts no MCP server and executes no MCP tool.

Expected result: state `completed`, one resolved rule/component identity, no persistent or new identities. The exact digest changes with the temporary target path. `resolved` means the selected heuristic no longer matched under equivalent complete coverage. It does not establish that the server implementation is safe, or that prompt injection is impossible.

For Windows without WSL, build `bin/mcpsense.exe`, create a synthetic manifest in a temporary directory, and use the same `scan` arguments twice against that same path. A high/critical finding intentionally returns 1; check `$LASTEXITCODE` before continuing. Then run `bin/mcpsense.exe verify before.json after.json`.

The verification tests also cover refused comparisons after input inventory, severity filter, advisory status, target or completion state changes. Unsigned report files are not cryptographic attestations.
