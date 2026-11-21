# BEAN — Entec + TagEngine monorepo

BEAN consolidates the Entec orchestration library and TagEngine service in one npm-workspaces repository. The original repositories remain unchanged.

## Repository map

- `packages/entec-core` — Entec contracts, Windows snapshot parser/vectorizer, local comparison pipeline, typed TagEngine HTTP client, and operations dashboard.
- `packages/tagengine` — TagEngine HTTP API, streaming Windows `dir /s` parser, 12-dimensional JSONL vectors, SQLite-backed snapshot store and disk-backed diff comparator, CLI, and web UI.
- `apps/web/public` — retained source dashboard assets from both upstream projects.
- `docs/architecture.md` — integration boundaries, workflow, and deployment notes.

## Requirements

- Node.js 20 or newer
- npm
- A platform/toolchain supported by `better-sqlite3` (prebuilt binaries are used where available)

## Install, build, and test

```sh
npm install
npm run build
npm test
```

## Run the TagEngine API

```sh
ENTEC_API_TOKEN='replace-with-a-long-random-secret' \
ENTEC_SNAPSHOT_DIR='./data/snapshots' \
npm run api
```

The API listens on port 3000 by default. Health check: `GET /api/health`. The interactive parser UI is served at `/`. The authenticated `POST /api/analyze`, snapshot inventory, comparison, and retention routes are documented in `packages/tagengine/UPSTREAM-README.md` (the upstream README is retained with the source package).

For local development only, TagEngine permits loopback API access without a token when `NODE_ENV` is not `production`. Production fails closed if `ENTEC_API_TOKEN` is absent.

## Run the Entec operations dashboard

Start TagEngine first, then:

```sh
TAGENGINE_URL='http://127.0.0.1:3000' \
TAGENGINE_API_TOKEN='replace-with-the-same-secret' \
npm run dashboard
```

The dashboard listens on `127.0.0.1:4173` by default. For non-loopback binding, configure `ENTEC_DASHBOARD_TOKEN`, TLS, and an authenticated reverse proxy. Keep API tokens server-side; never place them in browser assets.

## CLI

```sh
npm run cli --workspace @bean/tagengine -- parse --input snapshot.txt --output out/vectors.jsonl
npm run cli --workspace @bean/tagengine -- diff --baseline out/t0.jsonl --target out/t1.jsonl --output out/alerts.jsonl
```

## Workflow

`WINDOWS DIR /S → TAGENGINE PARSE → 12D JSONL → SQLITE SNAPSHOT INVENTORY → DISK-BACKED DIFF → ALERTS / DASHBOARD`

Entec provides reusable abstractions and a typed HTTP adapter. TagEngine remains the authoritative implementation of its streaming parser, SQLite persistence, and disk-backed comparator; those algorithms are not duplicated in the adapter.

## Safety and operations

- Findings and severity values are review signals, not malware verdicts.
- Analysis is passive; the system does not block, quarantine, or delete files.
- Retention defaults to a dry-run. Review candidates and backups before explicitly executing deletion.
- Use a private network or HTTPS between services, rotate tokens through a secret manager, and back up the complete TagEngine snapshot directory.
- Snapshot content and generated vectors are stored on the TagEngine host; the API does not return raw stored snapshot text or local paths.

## Upstream sources

- [Entec](https://github.com/icealys68654-tech/Entec)
- [TagEngine](https://github.com/icealys68654-tech/TagEngine)

Upstream source files and tests are retained under the corresponding package folders. See the package-level upstream README for source-specific details and licensing.
