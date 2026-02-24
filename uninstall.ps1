# Sigyn uninstaller for Windows (PowerShell)
# Usage:
#   irm https://raw.githubusercontent.com/tonybenoy/sigyn/main/uninstall.ps1 | iex

$ErrorActionPreference = "Stop"

$InstallDir = if ($env:SIGYN_INSTALL_DIR) { $env:SIGYN_INSTALL_DIR } else { "$env:USERPROFILE\.sigyn\bin" }
$DataDir    = "$env:USERPROFILE\.sigyn"

function Say($Tag, $Msg) {
    Write-Host "  $Tag" -ForegroundColor Green -NoNewline
    Write-Host " $Msg"
}

# ---------- remove binaries --------------------------------------------------

foreach ($Bin in @("sigyn.exe", "sigyn-recovery.exe")) {
    $Path = "$InstallDir\$Bin"
    if (Test-Path $Path) {
        Remove-Item $Path -Force
        Say "removed" $Path
    }

    $CargoPath = "$env:USERPROFILE\.cargo\bin\$Bin"
    if (Test-Path $CargoPath) {
        Remove-Item $CargoPath -Force
        Say "removed" $CargoPath
    }
}

# Remove bin dir if empty
if ((Test-Path $InstallDir) -and @(Get-ChildItem $InstallDir).Count -eq 0) {
    Remove-Item $InstallDir
}

# ---------- clean PATH -------------------------------------------------------

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -like "*$InstallDir*") {
    $NewPath = ($UserPath -split ";" | Where-Object { $_ -ne $InstallDir }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Say "cleaned" "removed $InstallDir from user PATH"
}

# ---------- optionally remove data -------------------------------------------

Write-Host ""
$Answer = Read-Host "  Remove all Sigyn data ($DataDir)? This deletes identities, vaults, and config. [y/N]"

if ($Answer -match "^[yY]") {
    Remove-Item -Recurse -Force $DataDir
    Say "removed" $DataDir
} else {
    Say "kept" $DataDir
}

Write-Host ""
Write-Host "  Sigyn uninstalled." -ForegroundColor Green
Write-Host ""
