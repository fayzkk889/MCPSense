# Independent npm runtime verification — 25 October 2026

The 0.4.0 candidate changes npm delivery to the existing Go engine compiled to `js/wasm`, bundled with its matching Go bootstrap, Node host adapters and Go BSD license. Users need Node.js 22+ and npm; they do not need Go, native archive tools, postinstall downloads or an unsigned MCPSense Windows executable. The independent Go 1.22+ native source installation remains available. MIT is unchanged.

This is a distribution change, not an evasion of machine protection or a runtime security sandbox. Node.js/scripts may still be restricted by a device policy. Native Windows archives remain unsigned, and the existing signing inquiry remains relevant to that route. Nothing has been tagged, published to npm or released publicly during this work.

## Design and review boundaries

- Detection, limits, protocol parsing, reporting, baseline logic and permission decisions run in the same Go code as native builds.
- The Node adapter supplies filesystem operations, cancellable streaming reads, DNS resolution, pinned HTTP connections and explicitly permitted process execution. All DNS results pass the existing Go address policy. Node core does not follow redirects; Go retains that decision. HTTPS retains certificate validation. Environment proxies are not inherited by the private connection agent.
- Local MCP startup still requires `--allow-exec`; `--offline` prohibits it. Arguments are arrays with `shell:false`. Metadata discovery lists tools without invoking them. Process cleanup is best effort, not an OS sandbox.
- Runtime hashes reject accidental corruption/mixing; the Go engine additionally checks the exact embedded host-source hash. These checks do not authenticate a publisher or resist an attacker who can replace the whole package. npm provides normal registry integrity checks.
- Baseline detector profiles include runtime/platform/adapter identity, conservatively refusing comparisons across different evaluation environments.
- Node.js 14–21 are no longer supported by the npm candidate. NVM is optional; no compiler is installed on the user's behalf.

## Reproduced defects during packaging

1. A bounded Node stream read could drain its buffer before Node emitted EOF, leaving an advisory request waiting until timeout. Driving the empty-buffer read transition fixes completion; streaming and cancellation tests preserve the original limits.
2. Go 1.27 directory walks request `O_DIRECTORY`, which Node omits on Windows. Clean installed whole-project scanning failed visibly. A Windows filesystem adapter now validates the opened descriptor as a directory and rejects ordinary files with `ENOTDIR`; it does not silently weaken the directory-only check.
3. Go's WebAssembly target reports `js` rather than its host OS. Windows path basenames, executable detection, nested skill paths, recursive directory creation and output/baseline path checks now use the Node host where platform semantics matter. Native builds retain their original OS implementations.

## Local observed results

Windows 11, Node.js 22.23.4, Go builder 1.27.3:

| Check | Observed result |
| --- | --- |
| Actual packed tarball contents | Exactly 10 expected files; no `.exe`, installer or native binary |
| Isolated global npm installation | Passed offline with installation scripts disabled, Go and tar unavailable, fresh npm cache, prefix containing spaces |
| npm-created Windows command shim | Started and reported `mcpsense v0.4.0` |
| Installed beginner/remediation/live workflows | All 14 assertions passed |
| Shared expanded product workflows | 24 passed, 0 failed |
| Existing authored description corpus | 164 observations: 82 hostile detected, 82 benign quiet |
| Beginner/expert persona journeys | 44 invocations; 8 hostile detected, 8 benign quiet |
| Latest authored description regression | 48 observations: 24 hostile detected, 24 benign quiet |
| Expanded live HTTP scenarios | Passed, including SSE streaming, legacy fallback, auth failure, pagination, redirect refusal, malformed/oversized responses |
| Saved baseline metadata journeys | All 14 passed |
| Dependency journeys | 18 deterministic wiring/error cases plus 4 real OSV affected/patched controls passed |
| Node host capability tests | Six passed: directory-only opens, bounded reads/EOF, SSE/cancel, redirects/proxies, invalid capabilities, literal process argv |
| Authorized local MCP subprocess | Permission/offline refusal, literal argv, poisoned metadata detection, no tool invocation, process termination passed |
| Native Windows Go tests and vet | Passed for all packages |
| Local Linux race attempt | Not executable here: WSL lacks gcc/cgo prerequisites; hosted Linux/Windows race jobs remain required |

Description datasets have already informed detector fixes. Their perfect regression results are not independent field accuracy or a guarantee that no future hostility can pass. Existing unassessed boundaries remain visible in reports.

An earlier 96-entry real-inventory prototype run encountered an advisory network failure and correctly failed closed; a cached retry completed. A proposed fresh-home rerun was rejected by automatic approval review because it changed standard process environment settings. No home settings or protection controls were changed by that rejected action. The 4-version public OSV controls and ordinary networking tests above passed; a fully cold 96-entry rerun is not claimed here.

## Repeatable gates and publication

Maintainers build generated assets with `node scripts/build-npm-runtime.cjs`, verify them with `node scripts/release-verify.mjs --npm`, install the actual tarball with `node scripts/npm-wasm-smoke.cjs`, and run unchanged native-product expectations through `node scripts/npm-product-suite.cjs`. Generated assets remain outside Git. The npm `prepublishOnly` check refuses missing/mixed assets; published packages have no installation hooks.

CI adds Windows/Linux/macOS × Node.js 22/24 npm installation and complete shared-product jobs, alongside the existing native Go 1.22/1.27 tests, race checks, lint, Action and five-platform snapshot. Hosted results must be checked at the exact PR revision before merging. The tag workflow prepares a verified npm artifact but does not publish it to npm automatically. Public tagging/release/npm publication still require the user's explicit approval. Source pushes do not update `@latest`.

Primary references: [Go WebAssembly](https://go.dev/wiki/WebAssembly), [Node.js WebAssembly](https://nodejs.org/en/learn/getting-started/nodejs-with-webassembly), [Node filesystem open constants](https://nodejs.org/api/fs.html#file-open-constants), [Microsoft Smart App Control signing](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control). The Go 1.27.3 standard-library `syscall/fs_js.go` explicitly documents Node's missing Windows `O_DIRECTORY` support; the failure above was reproduced against that installed toolchain.
