#!/bin/sh
# Install a published Linux/macOS release. Windows uses install.ps1 (Go source).
# MCPSENSE_VERSION=0.4.0 MCPSENSE_INSTALL_DIR="$HOME/.local/bin" sh install.sh
set -eu
repo='fayzkk889/MCPSense'
install_dir=${MCPSENSE_INSTALL_DIR:-"$HOME/.local/bin"}
version=${MCPSENSE_VERSION:-latest}
fail() { printf 'MCPSense: %s\n' "$*" >&2; exit 1; }
case "$(uname -s)" in
  Linux*) os=linux ;;
  Darwin*) os=darwin ;;
  MINGW*|MSYS*|CYGWIN*) fail 'On Windows, use install.ps1 with Go installed. This installer does not download Windows executables.' ;;
  *) fail 'Supported systems are Linux, macOS, and Windows through install.ps1.' ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail 'Unsupported architecture.' ;;
esac
command -v curl >/dev/null 2>&1 || fail 'curl is required.'
download() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 "$1" -o "$2"; }
staging_dir=$(mktemp -d)
cleanup() { rm -f "$staging_dir/release.json" "$staging_dir/archive.tar.gz" "$staging_dir/checksums.txt" "$staging_dir/mcpsense"; rmdir "$staging_dir"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
if [ "$version" = latest ]; then
  download "https://api.github.com/repos/$repo/releases/latest" "$staging_dir/release.json" || fail 'Cannot read the latest published release.'
  version=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\([^"]*\)".*/\1/p' "$staging_dir/release.json" | head -n 1)
fi
version=${version#v}
printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || fail 'Invalid release version; use a published version such as 0.4.0.'
archive="MCPSense_${version}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/v$version"
printf 'Installing published MCPSense %s for %s/%s\n' "$version" "$os" "$arch"
download "$base/$archive" "$staging_dir/archive.tar.gz" || fail 'Release archive unavailable; check that this version is published.'
download "$base/checksums.txt" "$staging_dir/checksums.txt" || fail 'Release checksum manifest unavailable.'
expected=$(awk -v name="$archive" '$2 == name {print $1}' "$staging_dir/checksums.txt")
printf '%s\n' "$expected" | grep -Eq '^[a-fA-F0-9]{64}$' || fail 'Missing or ambiguous archive checksum.'
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$staging_dir/archive.tar.gz" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$staging_dir/archive.tar.gz" | awk '{print $1}')
else
  fail 'sha256sum or shasum is required to verify the archive.'
fi
[ "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" = "$actual" ] || fail 'Archive checksum mismatch; nothing was installed.'
tar -xzf "$staging_dir/archive.tar.gz" -C "$staging_dir" mcpsense || fail 'Cannot extract the CLI.'
chmod 755 "$staging_dir/mcpsense"
"$staging_dir/mcpsense" version || fail 'Downloaded CLI cannot start.'
mkdir -p "$install_dir" || fail 'Cannot create install directory. Choose a writable MCPSENSE_INSTALL_DIR.'
mv "$staging_dir/mcpsense" "$install_dir/mcpsense" || fail 'Cannot install the CLI.'
printf 'Installed to %s/mcpsense\n' "$install_dir"
case ":$PATH:" in *":$install_dir:"*) ;; *) printf 'Add %s to PATH, or invoke the executable using that path.\n' "$install_dir" ;; esac
