#Requires -Version 5.1
<#
.SYNOPSIS
    Install MCPSense on Windows by compiling its public Go source.
.DESCRIPTION
    Requires Go 1.22 or newer. No Node.js, npm, administrator privileges,
    unsigned binary download, or security-setting changes are required.
    Latest selects the latest published Go version, not unreleased main.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^(latest|v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?|[0-9a-fA-F]{40})$')]
    [string]$Version = 'latest',
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'MCPSense'),
    [switch]$NoPathUpdate
)
$ErrorActionPreference = 'Stop'
function Install-MCPSense {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw 'Go 1.22 or newer is required on Windows. Install Go from https://go.dev/dl/, reopen the terminal, and run this installer again. Node.js alone is not sufficient.'
    }
    if ($Version -match '^\d+\.\d+\.') { $Version = 'v' + $Version }
    $destination = [IO.Path]::GetFullPath($InstallDir)
    if (Test-Path -LiteralPath $destination -PathType Leaf) { throw 'InstallDir must be a directory.' }
    $null = New-Item -ItemType Directory -Path $destination -Force
    $previousBin = $env:GOBIN
    try {
        $env:GOBIN = $destination
        Write-Host "Building MCPSense from source ($Version). The initial download may take a moment."
        & go install "github.com/fayzkk889/MCPSense/cmd/mcpsense@$Version"
        if ($LASTEXITCODE -ne 0) { throw "Source installation failed (exit $LASTEXITCODE). Verify that the requested version exists and that Go can access the network." }
    } finally {
        if ($null -eq $previousBin) { Remove-Item Env:GOBIN -ErrorAction SilentlyContinue } else { $env:GOBIN = $previousBin }
    }
    $installedBinary = Join-Path $destination 'mcpsense.exe'
    if (-not (Test-Path -LiteralPath $installedBinary -PathType Leaf)) { throw "Installation did not produce $installedBinary" }
    $installedVersion = & $installedBinary version 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'The installed CLI could not start. Review Windows protection history or your organization policy; this installer does not change security settings.' }
    if (-not $NoPathUpdate) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $entries = @($userPath -split ';' | Where-Object { $_ })
        if ($entries -notcontains $destination) { [Environment]::SetEnvironmentVariable('Path', (($entries + $destination) -join ';'), 'User') }
        if (($env:Path -split ';') -notcontains $destination) { $env:Path = "$destination;$env:Path" }
    }
    Write-Host "Installed: $installedVersion"
    Write-Host "Executable: $installedBinary"
    Write-Host 'Quick start: mcpsense scan .\mcp.json --offline --no-baseline'
    if ($NoPathUpdate) { Write-Host 'PATH was not changed. Invoke the executable at the path above.' }
}
try { Install-MCPSense } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
