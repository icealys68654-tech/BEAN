const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { IdsIngestionStore } = require("../dist/ids-ingestion-store.js");

const record = {
  path: "C:/Windows/System32/example.dll",
  hash: "a".repeat(64),
  is_content_hashed: true,
  entropy_bits: 6.25,
  entropy_norm: 0.78125,
  magic_mismatch: false,
  magic_info: "PE_EXECUTABLE"
};

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bean-ids-test-"));
}

test("streams validated IDS JSONL into a completed scan", async () => {
  const dir = tempDir();
  const store = new IdsIngestionStore(dir);
  try {
    const result = await store.ingest({
      scanId: "a8d4d45a-5d31-4e43-86f1-8e22ab1d1b18",
      volumeId: "C:",
      lines: (async function* () { yield JSON.stringify(record); yield ""; yield JSON.stringify({ ...record, path: "C:/two.txt" }); })()
    });
    assert.equal(result.status, "COMPLETE");
    assert.equal(result.recordCount, 2);
    assert.equal(store.list(10)[0].scanId, result.scanId);
  } finally {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("rejects malformed JSONL and removes the incomplete scan", async () => {
  const dir = tempDir();
  const store = new IdsIngestionStore(dir);
  try {
    await assert.rejects(() => store.ingest({
      scanId: "b8d4d45a-5d31-4e43-86f1-8e22ab1d1b18",
      volumeId: "C:",
      lines: (async function* () { yield JSON.stringify(record); yield "{bad json"; })()
    }), /invalid JSON/);
    assert.equal(store.list(10).length, 0);
  } finally {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("backs up the IDS SQLite database", async () => {
  const dir = tempDir();
  const store = new IdsIngestionStore(dir);
  try {
    const target = path.join(dir, "backup");
    const database = await store.backupTo(target);
    assert.equal(fs.existsSync(database), true);
    assert.ok(fs.statSync(database).size > 0);
  } finally {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
