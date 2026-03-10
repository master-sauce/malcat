#Requires -Version 5.1
<#
.SYNOPSIS
    malcat installer/uninstaller for Windows
.DESCRIPTION
    Downloads malcat.exe from GitHub and adds it to your user PATH.
    Run again to uninstall.
.EXAMPLE
    irm https://raw.githubusercontent.com/master-sauce/malcat/main/malcat/install.ps1 | iex
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Repo        = "master-sauce/malcat"
$BinaryName  = "malcat"
$ExeName     = "malcat.exe"
$RawBase     = "https://raw.githubusercontent.com/$Repo/main/malcat"
$InstallDir  = Join-Path $env:USERPROFILE ".local\bin\malcat"
$Destination = Join-Path $InstallDir "$BinaryName.exe"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Info    { param($msg) Write-Host "[malcat] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[malcat] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[malcat] $msg" -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "[malcat] ERROR: $msg" -ForegroundColor Red; exit 1 }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  malcat Installer" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ── Uninstall function ────────────────────────────────────────────────────────
function Uninstall-Malcat {
    Write-Host ""
    Write-Info "Uninstalling malcat..."

    if (Test-Path $Destination) {
        Remove-Item -Force $Destination
        Write-Success "Removed binary: $Destination"
    } else {
        $GoCmd = Get-Command go -ErrorAction SilentlyContinue
        if ($GoCmd) {
            $GoPath = (go env GOPATH)
            $GoBin = Join-Path $GoPath "bin\$BinaryName.exe"
            if (Test-Path $GoBin) {
                Remove-Item -Force $GoBin
                Write-Success "Removed binary: $GoBin"
                $script:InstallDir = Join-Path $GoPath "bin"
            }
        } else {
            Write-Warn "Binary not found — nothing to remove."
        }
    }

    # Remove empty install directory
    if ((Test-Path $InstallDir) -and (-not (Get-ChildItem $InstallDir))) {
        Remove-Item -Force -Recurse $InstallDir
        Write-Info "Removed empty install directory: $InstallDir"
    }

    # Remove from user PATH
    $CurrentPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $PathEntries = $CurrentPath -split ";" | Where-Object { $_ -ne "" -and $_ -ne $InstallDir }
    $NewPath = $PathEntries -join ";"
    [System.Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Success "Removed $InstallDir from user PATH."

    $env:Path = ($env:Path -split ";" | Where-Object { $_ -ne $InstallDir }) -join ";"

    Write-Host ""
    Write-Success "✓ malcat has been uninstalled. Open a new terminal to clear your PATH."
    Write-Host ""
    exit 0
}

# ── Toggle: if already installed, prompt to uninstall ────────────────────────
if (Test-Path $Destination) {
    Write-Host ""
    Write-Warn "malcat is already installed at: $Destination"
    $Confirm = Read-Host "  Uninstall it? [y/N]"
    if ($Confirm -match "^[Yy]$") {
        Uninstall-Malcat
    } else {
        Write-Info "Cancelled. No changes made."
        exit 0
    }
}

# ── Create install directory ──────────────────────────────────────────────────
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Info "Created install directory: $InstallDir"
}

# ── Download binary ───────────────────────────────────────────────────────────
$DownloadUrl = "$RawBase/$ExeName"

Write-Info "Downloading $ExeName from GitHub..."
Write-Info "URL: $DownloadUrl"

try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $Destination -UseBasicParsing
    Write-Success "Downloaded to: $Destination"
} catch {
    Write-Warn "Direct download failed. Trying 'go install' as fallback..."
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Info "Running: go install github.com/$Repo@latest"
        go install "github.com/${Repo}@latest"
        $GoPath = (go env GOPATH)
        $InstallDir = Join-Path $GoPath "bin"
        Write-Success "Installed via 'go install' to: $InstallDir"
    } else {
        Write-Fail "Download failed and Go is not installed.`nInstall Go from https://go.dev/dl/ and retry."
    }
}

# ── Add to user PATH ──────────────────────────────────────────────────────────
Write-Info "Checking PATH..."

$CurrentPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
$PathEntries = $CurrentPath -split ";" | Where-Object { $_ -ne "" }

if ($PathEntries -contains $InstallDir) {
    Write-Warn "$InstallDir is already in your PATH. Skipping."
} else {
    $NewPath = ($PathEntries + $InstallDir) -join ";"
    [System.Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Success "Added $InstallDir to your user PATH."
}

$env:Path = "$env:Path;$InstallDir"

# ── Verify ────────────────────────────────────────────────────────────────────
Write-Host ""
$Found = Get-Command "$BinaryName.exe" -ErrorAction SilentlyContinue
if ($Found) {
    Write-Success "✓ '$BinaryName' is ready to use!"
} else {
    Write-Warn "'$BinaryName' not found in current session PATH."
    Write-Host "  Restart your terminal, then try: $BinaryName --help" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Run:  $BinaryName --help" -ForegroundColor Cyan
Write-Host "  Tip:  Run this script again to uninstall." -ForegroundColor DarkGray
Write-Host ""