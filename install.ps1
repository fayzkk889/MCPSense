# MCPSense Installer for Windows
# Usage: irm https://mcpsense.site/install.ps1 | iex

$ErrorActionPreference = "Stop"
$repo = "fayzkk889/MCPSense"
$binaryName = "mcpsense.exe"

Write-Host "[mcpsense] " -ForegroundColor Cyan -NoNewline
Write-Host "Detecting platform..."

$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

Write-Host "[mcpsense] " -ForegroundColor Cyan -NoNewline
Write-Host "Detected: windows/$arch"

# Get latest version
Write-Host "[mcpsense] " -ForegroundColor Cyan -NoNewline
Write-Host "Fetching latest release..."

try {
    $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
    $version = $release.tag_name -replace '^v', ''
} catch {
    Write-Host "[mcpsense] " -ForegroundColor Red -NoNewline
    Write-Host "Failed to fetch latest release. Check https://github.com/$repo/releases"
    exit 1
}

Write-Host "[mcpsense] " -ForegroundColor Cyan -NoNewline
Write-Host "Latest version: v$version"

Write-Host ""
Write-Host "[mcpsense] " -ForegroundColor Yellow -NoNewline
Write-Host "IMPORTANT: Windows Defender may flag Go binaries as false positives."
Write-Host "[mcpsense] " -ForegroundColor Yellow -NoNewline
Write-Host "This is a known Go issue: https://go.dev/doc/faq#virus"
Write-Host ""

# Download
$filename = "MCPSense_${version}_windows_${arch}.zip"
$url = "https://github.com/$repo/releases/download/v$version/$filename"
$tmpDir = Join-Path $env:TEMP "mcpsense-install"
$zipPath = Join-Path $tmpDir $filename

if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
New-Item -ItemType Directory -Path $tmpDir | Out-Null

Write-Host "[mcpsense] " -ForegroundColor Cyan -NoNewline
Write-Host "Downloading $filename..."

try {
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
} catch {
    Write-Host "[mcpsense] " -ForegroundColor Red -NoNewline
    Write-Host "Download failed. URL: $url"
    exit 1
}

# Extract
Write-Host "[mcpsense] " -ForegroundColor Cyan -NoNewline
Write-Host "Extracting..."

Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force

$binaryPath = Join-Path $tmpDir $binaryName
if (-not (Test-Path $binaryPath)) {
    Write-Host "[mcpsense] " -ForegroundColor Red -NoNewline
    Write-Host "Binary not found after extraction."
    exit 1
}

# Install to user's local bin
$installDir = Join-Path $env:LOCALAPPDATA "mcpsense"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
}

# Try to add Windows Defender exclusion (requires admin, may fail silently)
try {
    Add-MpPreference -ExclusionPath $installDir -ErrorAction Stop
    Write-Host "[mcpsense] " -ForegroundColor Green -NoNewline
    Write-Host "Added Windows Defender exclusion for $installDir"
} catch {
    Write-Host "[mcpsense] " -ForegroundColor Yellow -NoNewline
    Write-Host "Could not add Defender exclusion (needs admin). If the binary disappears:"
    Write-Host "  1. Open Windows Security > Virus & threat protection > Protection history" -ForegroundColor DarkGray
    Write-Host "  2. Find the MCPSense quarantine entry and click 'Allow'" -ForegroundColor DarkGray
    Write-Host "  3. Or run this script as Administrator" -ForegroundColor DarkGray
}

Copy-Item $binaryPath (Join-Path $installDir $binaryName) -Force

# Add to PATH if not already there
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$installDir", "User")
    Write-Host "[mcpsense] " -ForegroundColor Cyan -NoNewline
    Write-Host "Added $installDir to your PATH. Restart your terminal for it to take effect."
}

# Cleanup
Remove-Item -Recurse -Force $tmpDir

# Verify binary actually exists (Defender may have quarantined it)
Start-Sleep -Seconds 2  # Give Defender a moment to act
$finalPath = Join-Path $installDir $binaryName
if (-not (Test-Path $finalPath)) {
    Write-Host ""
    Write-Host "[mcpsense] " -ForegroundColor Red -NoNewline
    Write-Host "ERROR: Binary was deleted (likely by Windows Defender)."
    Write-Host ""
    Write-Host "  To fix this:" -ForegroundColor Yellow
    Write-Host "  1. Open Windows Security" -ForegroundColor DarkGray
    Write-Host "  2. Go to Virus & threat protection > Protection history" -ForegroundColor DarkGray
    Write-Host "  3. Find 'mcpsense.exe' and click 'Allow on device'" -ForegroundColor DarkGray
    Write-Host "  4. Run this installer again" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Alternative: install via Go instead:" -ForegroundColor Yellow
    Write-Host "  go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

$versionOutput = & $finalPath version 2>&1

Write-Host "[mcpsense] " -ForegroundColor Green -NoNewline
Write-Host "Installed successfully: $versionOutput"
Write-Host ""
Write-Host "  Quick start:" -ForegroundColor DarkGray
Write-Host "    mcpsense scan .\my-mcp-server" -ForegroundColor DarkGray
Write-Host "    mcpsense scan .\mcp.json" -ForegroundColor DarkGray
Write-Host "    mcpsense --help" -ForegroundColor DarkGray
Write-Host ""
Write-Host "[mcpsense] " -ForegroundColor Green -NoNewline
Write-Host "Docs: https://github.com/$repo"
