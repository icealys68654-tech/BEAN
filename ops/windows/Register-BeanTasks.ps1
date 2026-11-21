param(
  [Parameter(Mandatory=$false)]
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
)
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path $RepoRoot).Path
$startScript = Join-Path $RepoRoot "ops\windows\Start-Bean.ps1"
$backupScript = Join-Path $RepoRoot "ops\windows\Backup-TagEngine.ps1"
$powerShell = Join-Path $PSHOME "powershell.exe"

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$startArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $startScript + '" -RepoRoot "' + $RepoRoot + '"'
$startAction = New-ScheduledTaskAction -Execute $powerShell -Argument $startArgs
$startTrigger = New-ScheduledTaskTrigger -AtStartup
$startTrigger.Delay = "PT90S"
Register-ScheduledTask -TaskName "BEAN Container Startup" -Action $startAction -Trigger $startTrigger -Principal $principal -Description "Start BEAN TagEngine and Entec dashboard containers after Windows boots." -Force | Out-Null

$backupArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $backupScript + '" -RepoRoot "' + $RepoRoot + '"'
$backupAction = New-ScheduledTaskAction -Execute $powerShell -Argument $backupArgs
$backupTrigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
Register-ScheduledTask -TaskName "BEAN TagEngine Daily Backup" -Action $backupAction -Trigger $backupTrigger -Principal $principal -Description "Create consistent SQLite and snapshot-artifact backups for BEAN." -Force | Out-Null

Write-Host "Registered BEAN startup and daily backup tasks."
Write-Host "Run Start-Bean.ps1 once now, then verify both tasks in Task Scheduler."
