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
