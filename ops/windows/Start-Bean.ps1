param(
  [Parameter(Mandatory=$false)]
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
)
$ErrorActionPreference = "Stop"
$docker = Get-Command docker -ErrorAction Stop
Push-Location $RepoRoot
try {
  & $docker.Source compose up -d --build
  if ($LASTEXITCODE -ne 0) { throw "docker compose up failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}
