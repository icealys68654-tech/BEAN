# BEAN engineering tooling

The Streamline tooling is integrated as first-party packages inside BEAN; it does not replace or fork Entec or TagEngine.

## Packages

- `@bean/c4-model`: validates C4 element IDs, types, and relationship endpoints; exports a PlantUML C4 container view.
- `packages/smoke-probe`: runs HTTP checks from a JSON suite. Header values and URLs support `${ENV_VAR}` expansion; expected status defaults to 200.
- `packages/env-guard`: checks .env assignment syntax, duplicate keys, empty values, and caller-specified required keys. It never prints secret values.

## Commands

```sh
npm install
npm run build
npm test
go test ./packages/...
go build -o ./dist/bin/smoke-probe ./packages/smoke-probe/cmd/smoke-probe
go build -o ./dist/bin/env-guard ./packages/env-guard/cmd/env-guard
```

Smoke suite example (`ops/smoke/bean-health.json`):

```json
{
  "checks": [
    {
      "name": "TagEngine health",
      "url": "${TAGENGINE_URL}/api/health",
      "expected_status": 200,
      "timeout_ms": 5000
    }
  ]
}
```

Run with `go run ./packages/smoke-probe/cmd/smoke-probe run --suite ops/smoke/bean-health.json`.

Run the environment guard with `go run ./packages/env-guard/cmd/env-guard --required ENTEC_API_TOKEN,TAGENGINE_URL .env`.

The smoke-probe suite format is JSON (also valid YAML 1.2), deliberately avoiding a YAML parser dependency. It limits response reads to 1 MiB and never logs response bodies or header values.
