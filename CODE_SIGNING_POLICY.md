# Code signing and privacy

The historical project policy names SignPath.io and the SignPath Foundation as signing providers, with Faizan as author, reviewer and approver. The checked-in release workflow does not currently contain a signing step, and this mission has not verified a signed release artifact. Do not describe candidate binaries as signed or reproducible bit-for-bit without separate evidence.

GoReleaser builds from source and produces SHA-256 checksums. Checksums detect mismatches with a downloaded manifest; they are not proof of signing or independent provenance. npm installation downloads and verifies the platform executable on all supported systems without requiring Go. The independent Go installation route compiles source without requiring Node.js/npm. Neither route changes machine protection settings or guarantees acceptance under Windows policy.

Static/config scans can send recognized package names and versions to OSV.dev by default. --no-cve disables advisory access. --offline prohibits scanner networking and local server execution. Explicit live scans contact the authorized target subject to destination policy. Installation and source builds may separately require network access.

`mcpsense version --check` explicitly contacts GitHub and npm for public version metadata; no project files or target configuration are sent. Ordinary version/startup and offline scanning do not perform this lookup. It does not automatically install or change protection settings.

Format-2 snapshots minimize retained metadata; report redaction is best effort. Read the README privacy section before sharing baselines, reports or CI artifacts. MIT licensing is unchanged.
