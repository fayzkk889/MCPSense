#!/bin/sh
# Maintainer/release gate only; never a user installation step. Match the
# production compiler so old compatibility-test toolchains do not create
# misleading standard-library results. The checker is intentionally pinned.
set -eu
export GOTOOLCHAIN=local
export CGO_ENABLED=0
if [ "$(go env GOVERSION)" != go1.27.3 ]; then
  printf '%s\n' 'Run this release audit with the pinned production Go 1.27.3 compiler.' >&2
  exit 2
fi
audit_tools=$(mktemp -d)
cleanup() { rm -f "$audit_tools/govulncheck" "$audit_tools/mcpsense-symbols.exe"; rmdir "$audit_tools"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
GOBIN="$audit_tools" go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
go version -m "$audit_tools/govulncheck"
failed=0
# Text output is deliberate: JSON mode exits 0 even for vulnerability findings.
for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 js_wasm; do
  target_os=${target%_*}
  target_arch=${target#*_}
  printf '\nKnown-vulnerability audit: %s/%s\n' "$target_os" "$target_arch"
  if ! GOOS="$target_os" GOARCH="$target_arch" "$audit_tools/govulncheck" -db https://vuln.go.dev ./...; then
    failed=1
  fi
done
# Retain symbols in this audit counterpart. Stripped PE files can force the
# checker to fall back to all dependency symbols and over-report unused code.
GOOS=windows GOARCH=amd64 go build -trimpath -o "$audit_tools/mcpsense-symbols.exe" ./cmd/mcpsense
if ! "$audit_tools/govulncheck" -db https://vuln.go.dev -mode binary "$audit_tools/mcpsense-symbols.exe"; then
  failed=1
fi
exit "$failed"
