# BEAN Windows IDS scanner

Passive filesystem inspection with version-compatible JSONL evidence for TagEngine.

## Run

\`\`\`powershell
python ops/windows/ids/scanner.py scan --root C:\Data --output evidence\scan.jsonl
python ops/windows/ids/scanner.py scan --root C:\Data --compare-baseline
python ops/windows/ids/scanner.py scan --root C:\Data --compare-baseline --promote-baseline
\`\`\`

Files and output are streamed in 1 MiB chunks. Baseline state is SQLite-backed. Promotion is explicit and refused when collection errors occur. Findings are separate from evidence JSONL, preserving the existing TagEngine ingestion contract.

## Upload

\`\`\`powershell
$env:ENTEC_API_TOKEN = "your-token"
$env:TAGENGINE_URL = "https://your-api.example.com"
python ops/windows/ids_ingest.py --jsonl evidence\scan.jsonl
\`\`\`

## Current scope

- SHA-256, Shannon entropy, conservative signature checks, additions/changes/removals.
- Symlinks skipped; directory symlinks are not followed.
- Files changing during collection are marked not content-hashed and excluded from baseline promotion.
- Collection errors appear in findings and return exit code 2.
- Signature checks are deliberately limited; high entropy is not a malware verdict.
- NTFS alternate data streams and ACL/owner metadata are not yet collected.
- Review findings before promoting a baseline.
