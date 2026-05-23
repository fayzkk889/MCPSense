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

# Verify
$installedBinary = Join-Path $installDir $binaryName
$versionOutput = & $installedBinary version 2>&1

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
