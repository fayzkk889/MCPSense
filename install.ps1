#Requires -Version 5.1
<#
.SYNOPSIS
    Install MCPSense - MCP Server Security Scanner
.DESCRIPTION
    Tries multiple install methods in order:
    1. npm install -g mcpsense (if npm available)
    2. go install (if Go available)
    3. Direct binary download from GitHub Releases
    If binary download triggers antivirus, guides user to install Node.js.
#>

$ErrorActionPreference = "Stop"
$REPO = "fayzkk889/MCPSense"
$VERSION = "0.2.2"
$BINARY_NAME = "mcpsense.exe"

function Write-Step($msg) {
    Write-Host ""
    Write-Host "  >> $msg" -ForegroundColor Cyan
}

function Write-Ok($msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
    Write-Host "  [SKIP] $msg" -ForegroundColor Yellow
}

function Write-Err($msg) {
    Write-Host ""
    Write-Host "  [ERROR] $msg" -ForegroundColor Red
}

function Test-Command($cmd) {
    try {
        Get-Command $cmd -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Install-ViaNpm {
    Write-Step "Trying npm install..."

    if (-not (Test-Command "npm")) {
        Write-Fail "npm not found, skipping"
        return $false
    }

    try {
        npm install -g mcpsense 2>&1 | Out-Host
        if (Test-Command "mcpsense") {
            Write-Ok "Installed via npm"
            return $true
        }
    } catch {}

    Write-Fail "npm install did not complete successfully"
    return $false
}

function Install-ViaGo {
    Write-Step "Trying go install..."

    if (-not (Test-Command "go")) {
        Write-Fail "Go not found, skipping"
        return $false
    }

    try {
        $goPackage = "github.com/$REPO/cmd/mcpsense@v$VERSION"
        go install $goPackage 2>&1 | Out-Host

        # Check GOPATH/bin for the binary
        $gopath = (go env GOPATH 2>$null).Trim()
        $goBinary = Join-Path $gopath "bin\$BINARY_NAME"

        if (Test-Path $goBinary) {
            # Verify it's on PATH
            if (Test-Command "mcpsense") {
                Write-Ok "Installed via go install"
                return $true
            } else {
                Write-Host ""
                Write-Host "  mcpsense was compiled but is not on your PATH." -ForegroundColor Yellow
                Write-Host "  Binary location: $goBinary" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  To fix, add Go's bin directory to your PATH:" -ForegroundColor White
                Write-Host "    [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$gopath\bin', 'User')" -ForegroundColor White
                Write-Host "  Then restart your terminal." -ForegroundColor White
                Write-Host ""
                Write-Ok "Installed via go install (PATH update needed)"
                return $true
            }
        }
    } catch {}

    Write-Fail "go install did not complete successfully"
    return $false
}

function Install-ViaBinaryDownload {
    Write-Step "Trying direct binary download..."

    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $archiveName = "MCPSense_${VERSION}_windows_${arch}.zip"
    $url = "https://github.com/$REPO/releases/download/v$VERSION/$archiveName"

    $installDir = Join-Path $env:LOCALAPPDATA "MCPSense"
    $binaryPath = Join-Path $installDir $BINARY_NAME
    $tempZip = Join-Path $env:TEMP "mcpsense_download.zip"
    $tempExtract = Join-Path $env:TEMP "mcpsense_extract"

    Write-Host "  Downloading from: $url"

    try {
        # Download
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $tempZip)

        if (-not (Test-Path $tempZip)) {
            Write-Fail "Download failed"
            return $false
        }

        # Extract
        if (Test-Path $tempExtract) {
            Remove-Item $tempExtract -Recurse -Force
        }
        Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force

        # Find the binary in extracted files
        $foundBinary = Get-ChildItem -Path $tempExtract -Recurse -Filter $BINARY_NAME | Select-Object -First 1

        if (-not $foundBinary) {
            Write-Fail "Binary not found in archive"
            return $false
        }

        # Create install directory
        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        # Copy binary
        Copy-Item $foundBinary.FullName $binaryPath -Force

        # Wait a moment for antivirus to scan
        Start-Sleep -Seconds 3

        # Check if antivirus deleted it
        if (-not (Test-Path $binaryPath)) {
            Write-Fail "Binary was removed by antivirus (false positive for unsigned Go binaries)"
            return $false
        }

        # Add to PATH if not already there
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentPath -notlike "*$installDir*") {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installDir", "User")
            $env:Path = "$env:Path;$installDir"
            Write-Host "  Added $installDir to your PATH"
        }

        Write-Ok "Installed via binary download to $installDir"
        return $true
    } catch {
        Write-Fail "Download failed: $($_.Exception.Message)"
        return $false
    } finally {
        # Cleanup temp files
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Show-ManualInstructions {
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Red
    Write-Host "  All automatic install methods failed." -ForegroundColor Red
    Write-Host "  ========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  The easiest way to install MCPSense:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Install Node.js from https://nodejs.org" -ForegroundColor White
    Write-Host "     (Download the LTS version, run the installer)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. Restart your terminal" -ForegroundColor White
    Write-Host ""
    Write-Host "  3. Run:" -ForegroundColor White
    Write-Host "     npm install -g mcpsense" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  After that, you can use:" -ForegroundColor White
    Write-Host "     mcpsense scan ./mcp.json" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Other options:" -ForegroundColor Gray
    Write-Host "    - Install Go from https://go.dev/dl/ then run:" -ForegroundColor Gray
    Write-Host "      go install github.com/$REPO/cmd/mcpsense@latest" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================
# Main
# ============================================================

Write-Host ""
Write-Host "  MCPSense Installer v$VERSION" -ForegroundColor White
Write-Host "  =========================" -ForegroundColor White

# Check if already installed
if (Test-Command "mcpsense") {
    $currentVersion = (mcpsense version 2>$null) -replace '[^0-9.]', ''
    Write-Host ""
    Write-Host "  mcpsense is already installed (version: $currentVersion)" -ForegroundColor Green
    Write-Host "  To update, run: npm install -g mcpsense@latest" -ForegroundColor Gray
    Write-Host ""
    Read-Host "  Press Enter to close"
    exit 0
}

# Try each method in order
$installed = $false

if (-not $installed) { $installed = Install-ViaNpm }
if (-not $installed) { $installed = Install-ViaGo }
if (-not $installed) { $installed = Install-ViaBinaryDownload }

if ($installed) {
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Green
    Write-Host "  MCPSense installed successfully!" -ForegroundColor Green
    Write-Host "  ========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Try it:" -ForegroundColor White
    Write-Host "    mcpsense scan ./mcp.json" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Full docs: https://mcpsense.site" -ForegroundColor Gray
    Write-Host ""
} else {
    Show-ManualInstructions
}

# NEVER close the terminal without letting the user read the output
Read-Host "  Press Enter to close"
