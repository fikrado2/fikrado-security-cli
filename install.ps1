# Fikrado Security — installer for Windows (PowerShell)
#
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# Downloads the latest standalone fikrado-win-x64.exe into %LOCALAPPDATA%\Fikrado
# and prints the command to add it to PATH.
$ErrorActionPreference = 'Stop'

$repo = 'fikrado2/fikrado-security-cli'
$asset = 'fikrado-win-x64.exe'
$url = "https://github.com/$repo/releases/latest/download/$asset"
$destDir = Join-Path $env:LOCALAPPDATA 'Fikrado'
$dest = Join-Path $destDir 'fikrado.exe'

Write-Host "→ downloading $asset ..."
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing

Write-Host "✔ installed to $dest"
Write-Host ""
Write-Host "Add it to PATH (current user, permanent):"
Write-Host "  [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';$destDir', 'User')"
Write-Host ""
Write-Host "Then open a new terminal and run:  fikrado"
