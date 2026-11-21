param(
  [Parameter(Mandatory=$false)]
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
)
$ErrorActionPreference = "Stop"
$docker = Get-Command docker -ErrorAction Stop
$js = @'
fetch("http://127.0.0.1:3000/api/maintenance/backup", {
  method: "POST",
  headers: { authorization: "Bearer " + process.env.ENTEC_API_TOKEN }
}).then(async response => {
  const body = await response.text();
  console.log(body);
  if (!response.ok) process.exitCode = 1;
}).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
'@
Push-Location $RepoRoot
try {
  & $docker.Source compose exec -T tagengine node -e $js
  if ($LASTEXITCODE -ne 0) { throw "TagEngine backup failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}
