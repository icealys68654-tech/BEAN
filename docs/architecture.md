# BEAN architecture

## Integration boundary

BEAN is a workspace monorepo, not a rewrite. Entec remains the contract/orchestration package and TagEngine remains a separately runnable HTTP service package.

```text
apps/
  web/                     retained dashboard source assets
packages/
  entec-core/
    src/abstract/           ports and interfaces
    src/vector/             local parser/vectorizer and tests
    src/umbrella/            baseline/target orchestration pipeline
    src/tagengine/           typed HTTP client and contract tests
    src/operations/          server-side operations dashboard
    public/                  Entec dashboard assets
  tagengine/
    src/server.ts            HTTP API
    src/snapshot-manifest-parser.ts
    src/snapshot-store.ts
    src/sqlite-snapshot-diff-comparator.ts
    src/cli.ts
    public/                  TagEngine parser UI
    tests/                   persistence, comparison, retention tests
```

## Data path

1. Submit Windows `dir /s` output to TagEngine.
2. Stream-parse entries and derive the twelve normalized features.
3. Persist source snapshots and JSONL vectors with SQLite metadata.
4. Compare stored snapshots for a volume using a shared timestamp anchor and a disk-backed SQLite comparator.
5. Persist comparison metadata and JSONL alerts; Entec reads the service through its typed client.
6. Review inventory, comparison history, alert details, and retention previews in the Entec dashboard.

## Service contract and trust

TagEngine listens on port 3000 by default. Entec's dashboard listens on 127.0.0.1:4173 by default and makes authenticated requests from the server, not the browser. The TagEngine bearer token is never embedded in the dashboard's JavaScript.

Production deployments must configure `ENTEC_API_TOKEN` and use TLS or a private network. Remote dashboard binding additionally requires `ENTEC_DASHBOARD_TOKEN`. Configure durable storage with `ENTEC_SNAPSHOT_DIR`.

## Feature vector

The twelve dimensions are executable, archive/image, script/config, recycle-bin path, system/program path, hidden/dot path, reparse point, directory, normalized path depth, normalized log size, recency, and timestamp anomaly.

## Data handling

The platform is passive. It reports changes and heuristic severity scores for operator review. It does not claim to prove malware, and it does not automatically block, quarantine, or remove observed files. Retention is operator-triggered and dry-run by default.


## Production operations

The Compose deployment runs TagEngine and the Entec dashboard as separate restartable services on a private Docker network. Caddy is the only published service and terminates TLS for both the dashboard and API domains. Edge HTTP Basic authentication protects the dashboard route; Caddy injects ENTEC_DASHBOARD_TOKEN only on the private dashboard hop. The API route forwards the caller's ENTEC_API_TOKEN bearer header unchanged for TagEngine to validate. Do not publish TagEngine or dashboard ports directly.

## IDS ingestion path

The Windows scanner writes its producer JSONL output to disk. The companion uploader in ops/windows/ids_ingest.py streams that file to POST /api/ids/ingest with ENTEC_API_TOKEN and volume/scan metadata. TagEngine validates each record and stores the original JSON evidence in ids-ingestion.sqlite. GET /api/ids/scans returns completed scan metadata. The ingestion store is separate from the dir /s snapshot/vector pipeline; it preserves the IDS producer records without conflating their schema with the directory parser's 12D vector model.

## Backup and retention ordering

POST /api/maintenance/backup backs up snapshots.sqlite and ids-ingestion.sqlite using SQLite's online backup API, then copies all snapshot source, vector, and comparison-alert artifacts referenced by the metadata database. A manifest records how to restore those artifacts. A non-dry-run retention request performs this backup first and aborts cleanup if the backup fails. The configured backup directory must be outside ENTEC_SNAPSHOT_DIR.
