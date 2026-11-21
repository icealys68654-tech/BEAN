# Windows production deployment

1. Install Docker Desktop (or a supported Docker Engine) and enable automatic engine startup.
2. Copy .env.example to .env; generate distinct high-entropy API/dashboard tokens and a Caddy basic-auth password hash. Never commit .env.
3. Point the two DNS names in .env to this host and allow inbound TCP 80/443 (and UDP 443 if HTTP/3 is desired).
4. Run docker compose up -d --build from the repository root.
5. Register reboot startup and daily backups from an elevated PowerShell prompt:
   powershell -ExecutionPolicy Bypass -File .\ops\windows\Register-BeanTasks.ps1
6. Confirm docker compose ps, https://<dashboard-domain>, and https://<api-domain>/api/health.

The TagEngine and dashboard containers are private on the Docker network. Caddy is the only service publishing public ports. Caddy enforces HTTP Basic authentication for the dashboard and injects ENTEC_DASHBOARD_TOKEN on that private hop. The API hostname forwards the caller's ENTEC_API_TOKEN bearer header unchanged so TagEngine can authenticate the IDS uploader itself. Do not expose container ports directly.

## Windows IDS scheduled task integration

The scanner must first write its completed JSONL output to a durable local path. Add this uploader as the final action in the existing SYSTEM scheduled task (or call it from the scanner's post-scan hook):

```powershell
$env:TAGENGINE_URL = "https://<api-domain>"
$env:ENTEC_API_TOKEN = (Get-Content "C:\ProgramData\BEAN\secrets\entec-api-token.txt" -Raw).Trim()
$env:BEAN_VOLUME_ID = $env:COMPUTERNAME
& py -3 "C:\BEAN\ops\windows\ids_ingest.py" --jsonl "C:\ProgramData\BEAN\out\latest.jsonl"
if ($LASTEXITCODE -ne 0) { throw "TagEngine ingestion failed" }
```

Grant the SYSTEM account read access to the token file and JSONL output directory; restrict the token file ACL to SYSTEM and Administrators. Do not put the token on the command line or in a checked-in script. For large scans, the uploader streams the file in 1 MiB chunks and retries transient failures.

## Backups and retention

The daily task calls the authenticated backup endpoint. Every non-dry-run retention request also creates a fresh backup first; if either SQLite backup or artifact copy fails, retention is not run. Backups are written to ./backups/<timestamp>, outside ENTEC_SNAPSHOT_DIR. Keep this directory on durable storage and copy it off-host according to your recovery policy.

Restore requires stopping the TagEngine service, restoring the SQLite databases, and copying each manifest artifact back to its recorded relative path under ENTEC_SNAPSHOT_DIR. Test restores before relying on backups.

The saved Windows IDS source currently available in this project history is truncated; use the complete scanner source from the host when wiring the final post-scan action. This uploader does not replace scanner functionality.
