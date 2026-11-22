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

## Bounded-memory scan state

Scan inventory, baseline comparisons, and findings are staged in SQLite. The scanner does not retain a Python list/set of every file or finding. File bytes are read in 1 MiB chunks; the entropy histogram is a fixed 256-counter structure. Evidence JSONL and findings JSONL are written incrementally. Staging rows are removed after a successfully completed scan; if a process is interrupted, its staging rows remain available for diagnosis and are not promoted automatically.

Baseline replacement is performed in a SQLite transaction and only after the scan completes without collection errors. Use `--compare-baseline` to emit new/changed/removed findings. Use `--promote-baseline` only when the scan is trusted and reviewed. A promotion request with collection errors is rejected.
