# Windows installation: confirmed remaining blocker

On 23 October 2026, the production npm installation core verified the CI archive but failed when it checked executable startup. Go was absent from PATH. The same code's hosted Windows Go1.22 and Go1.27 tests passed real archive installation, the wrapper, product journeys and live metadata scenarios. The local failure is retained rather than counted as a pass.

## Evidence

- Implementation: `eda1d703eb38eeaaa190b7c2de210be50632d14e`, CI [39953216696](https://github.com/fayzkk889/MCPSense/actions/runs/39953216696), all seven jobs successful.
- Snapshot build commit: `8ffc9fe0d7de0b198758806c13e7b27a2ddc70da`, synthetic PR merge; version `0.4.0-SNAPSHOT-8ffc9fe`.
- Windows archive SHA256: `3233579b1b3cc97065c82b8dc55a80ed7dd219d368dbcca82234a001928dbe55`. All five archive checksums verified before the local install attempt.
- Installer startup check: child process creation failed with Node `UNKNOWN`/errno `-4094`. No successful native startup or replacement is claimed.
- Windows Code Integrity Event3077 at18:01:28 local time identifies the staged `mcpsense.exe` and policy `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`. Signature inspection returns `NotSigned`. The same policy also blocked the installed Go compiler earlier that afternoon.
- The read-only Defender threat-history query returned no matching MCPSense records. This does not establish a malware classification or rule out other records; the positive evidence is the Code Integrity block.
- No code-signing private-key certificate was found in the current user's personal certificate store, no signing command/cloud CLI resolved, and no repository secret or variable names were returned. Other stores/accounts may exist; no secret values or keys were read or exported.

Microsoft's [inbox policy documentation](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/inbox-appcontrol-policies) maps that exact GUID to `VerifiedAndReputableDesktop`, active with Smart App Control enabled. Its [Smart App Control overview](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview) explains the treatment of unknown unsigned code. Therefore this specific observation is a trust/signing enforcement block, rather than evidence of a CI outage or an npm compiler dependency.

## Concrete release path

1. Use a maintainer-controlled code-signing identity issued by a trusted provider, or an eligible Microsoft Artifact Signing account. Microsoft [documents trusted signing](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control) as the supported developer route. Identity verification/account access must be supplied by the maintainer; a self-signed certificate is not a public-distribution substitute.
2. Sign the final Windows executable and timestamp its signature **before** packaging and generating `checksums.txt`. Maintain the same publisher identity across releases. Pin any added signing tools/actions and use narrowly scoped credentials, preferably federated identity when supported. Never embed signing keys in the repository or npm package.
3. Validate the Windows signature and chain, then run the actual signed archive through the unchanged npm installer with Go absent on a protected device. Exercise both first install and update, wrapper argument/exit handling, first offline scan, hostile metadata, remediation verification and live discovery. Retain the exact signed executable/archive hashes and signature evidence.
4. Only after explicit publication approval publish the approved artifacts, then run the public-channel gate and real public npm/Go installation/update tests. A checksum calculated before signing must not be reused after signing changes the executable.

The missing input is an available maintainer signing identity/account. No service was purchased, signing identity fabricated, sample submitted externally, protection disabled, local allowlist installed, or public release published. ZIP packaging and automatically installing Go do not add a trusted signature. Microsoft's separate [SmartScreen guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation) also distinguishes publisher identity/reputation; signing is not a promise that every Windows policy or reputation check will always accept every release.

The user recalls a past Microsoft false-positive clearance. No verified submission/clearance evidence was found in the available history; this record does not contradict that recollection or assume it covers a new executable. The present policy ID and unsigned snapshot provide direct evidence for the current block.
