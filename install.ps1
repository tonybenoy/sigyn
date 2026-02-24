# Sigyn installer for Windows (PowerShell)
# Usage:
#   irm https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo       = "tonybenoy/sigyn"
$InstallDir = if ($env:SIGYN_INSTALL_DIR) { $env:SIGYN_INSTALL_DIR } else { "$env:USERPROFILE\.sigyn\bin" }
$Version    = if ($env:SIGYN_VERSION) { $env:SIGYN_VERSION } else { "latest" }

function Say($Tag, $Msg) {
    Write-Host "  $Tag" -ForegroundColor Green -NoNewline
    Write-Host " $Msg"
}

function Err($Msg) {
    Write-Host "  error:" -ForegroundColor Red -NoNewline
    Write-Host " $Msg"
    exit 1
}

# ---------- resolve version --------------------------------------------------

if ($Version -eq "latest") {
    try {
        $Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        $Version = $Release.tag_name
    } catch {
        Err "could not determine latest release: $_"
    }
}

# ---------- detect target ----------------------------------------------------

$Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($Arch) {
    "X64"   { $Target = "x86_64-pc-windows-msvc" }
    "Arm64" { $Target = "aarch64-pc-windows-msvc" }
    default { Err "unsupported architecture: $Arch" }
}

# ---------- download & install -----------------------------------------------

$Archive = "sigyn-$Version-$Target.zip"
$Url     = "https://github.com/$Repo/releases/download/$Version/$Archive"

Say "info" "installing sigyn $Version for $Target"
Say "info" "destination: $InstallDir"

$TmpDir = New-TemporaryFile | ForEach-Object {
    Remove-Item $_
    New-Item -ItemType Directory -Path "$($_.FullName)_sigyn"
}

try {
    Say "fetch" $Url
    Invoke-WebRequest -Uri $Url -OutFile "$TmpDir\$Archive" -UseBasicParsing
} catch {
    Say "warn" "pre-built binary not found -- falling back to cargo install"

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Err "cargo not found. Install Rust from https://rustup.rs then retry."
    }

    Say "build" "compiling from source (this may take a few minutes)..."
    cargo install --git "https://github.com/$Repo.git" --bin sigyn  sigyn-cli
    cargo install --git "https://github.com/$Repo.git" --bin sigyn-recovery sigyn-recovery
    Say "ok" "installed via cargo"
    Write-Host ""
    Write-Host "  Binaries are in $env:USERPROFILE\.cargo\bin"
    Remove-Item -Recurse -Force $TmpDir
    exit 0
}

Expand-Archive -Path "$TmpDir\$Archive" -DestinationPath $TmpDir -Force

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

foreach ($Bin in @("sigyn.exe", "sigyn-recovery.exe")) {
    $Src = Get-ChildItem -Path $TmpDir -Filter $Bin -Recurse | Select-Object -First 1
    if ($Src) {
        Copy-Item $Src.FullName "$InstallDir\$Bin" -Force
        Say "ok" "installed $Bin"
    }
}

Remove-Item -Recurse -Force $TmpDir

# ---------- PATH setup -------------------------------------------------------

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$InstallDir;$UserPath", "User")
    $env:Path = "$InstallDir;$env:Path"
    Say "path" "added $InstallDir to user PATH"
}

Write-Host ""
Write-Host "  Sigyn installed!" -ForegroundColor Green
Write-Host "  Run 'sigyn --version' to verify."
Write-Host ""
