# Web assets

This folder retains the original Entec and TagEngine browser assets in `public/entec` and `public/tagengine`. The production service assets are also placed alongside their owning packages so each existing HTTP server can serve its original UI without path changes.

- Entec operations dashboard: served by `packages/entec-core/src/operations/server.ts`
- TagEngine parser UI: served by `packages/tagengine/src/server.ts`
