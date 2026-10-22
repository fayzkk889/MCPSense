# Code signing and privacy

The historical project policy names SignPath.io and the SignPath Foundation as signing providers, with Faizan as author, reviewer and approver. The checked-in release workflow does not currently contain a signing step, and this mission has not verified a signed release artifact. Do not describe candidate binaries as signed or reproducible bit-for-bit without separate evidence.

GoReleaser builds from source and produces SHA-256 checksums. Checksums detect mismatches with a downloaded manifest; they are not proof of signing or independent provenance. Windows npm installation continues to compile from source.

Static/config scans can send recognized package names and versions to OSV.dev by default. --no-cve disables advisory access. --offline prohibits scanner networking and local server execution. Explicit live scans contact the authorized target subject to destination policy. Installation and source builds may separately require network access.

Format-2 snapshots minimize retained metadata; report redaction is best effort. Read the README privacy section before sharing baselines, reports or CI artifacts. MIT licensing is unchanged.
