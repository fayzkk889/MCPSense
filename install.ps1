# MCPSense Installer for Windows
# Usage: irm https://raw.githubusercontent.com/fayzkk889/MCPSense/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
$repo = "fayzkk889/MCPSense"

if (Get-Command go -ErrorAction SilentlyContinue) {
    Write-Host "[mcpsense] Go detected. Installing from source..." -ForegroundColor Cyan

    go install github.com/$repo/cmd/mcpsense@latest

    $versionOutput = mcpsense version 2>&1
    Write-Host "[mcpsense] Installed successfully: $versionOutput" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Quick start:" -ForegroundColor DarkGray
    Write-Host "    mcpsense scan .\my-mcp-server" -ForegroundColor DarkGray
    Write-Host "    mcpsense scan .\mcp.json" -ForegroundColor DarkGray
    Write-Host "    mcpsense --help" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "[mcpsense] Docs: https://github.com/$repo" -ForegroundColor Green
} else {
    Write-Host "[mcpsense] Windows installation requires Go." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Install Go from: https://go.dev/dl/"
    Write-Host "  Then run: go install github.com/$repo/cmd/mcpsense@latest"
    Write-Host ""
    Write-Host "  Alternative: use WSL (Windows Subsystem for Linux) and run:"
    Write-Host "  curl -sSL https://raw.githubusercontent.com/fayzkk889/MCPSense/main/install.sh | sh"
    Write-Host ""
    exit 1
}
