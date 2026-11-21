const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { IdsIngestionStore } = require("../dist/ids-ingestion-store.js");
const { parseWindowsIdsRecord, parseWindowsIdsJsonlLine } = require("../dist/windows-ids-evidence.js");

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

test("a retried completed scan ID returns the original result without duplicate rows", async () => {
  const dir = tempDir();
  const store = new IdsIngestionStore(dir);
  try {
    const scanId = "c8d4d45a-5d31-4e43-86f1-8e22ab1d1b18";
    const first = await store.ingest({ scanId, volumeId: "C:", lines: (async function* () { yield JSON.stringify(record); })() });
    const retry = await store.ingest({ scanId, volumeId: "C:", lines: (async function* () { yield JSON.stringify(record); })() });
    assert.equal(retry.scanId, first.scanId);
    assert.equal(retry.recordCount, 1);
    assert.equal(store.list(10).length, 1);
  } finally {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test("canonical Windows IDS parser accepts the producer contract and boundary values", () => {
  assert.deepEqual(parseWindowsIdsRecord({ ...record, entropy_bits: 8, entropy_norm: 1 }, 4), {
    ...record, entropy_bits: 8, entropy_norm: 1
  });
  assert.equal(parseWindowsIdsJsonlLine(JSON.stringify(record), 7).path, record.path);
});

test("canonical Windows IDS parser rejects malformed and out-of-contract fields", () => {
  assert.throws(() => parseWindowsIdsJsonlLine("{bad", 9), /JSONL line 9: invalid JSON/);
  assert.throws(() => parseWindowsIdsRecord(null, 2), /expected a JSON object/);
  assert.throws(() => parseWindowsIdsRecord({ ...record, hash: "abc" }, 3), /64-character SHA-256/);
  assert.throws(() => parseWindowsIdsRecord({ ...record, entropy_bits: 8.01 }, 4), /entropy_bits/);
  assert.throws(() => parseWindowsIdsRecord({ ...record, entropy_norm: -0.01 }, 5), /entropy_norm/);
  assert.throws(() => parseWindowsIdsRecord({ ...record, path: "C:/bad\\0name" }, 6), /without NUL/);
  assert.throws(() => parseWindowsIdsRecord({ ...record, magic_mismatch: "false" }, 7), /magic_mismatch/);
});

test("streams a multi-thousand-record scan without collecting records in memory", async () => {
  const dir = tempDir();
  const store = new IdsIngestionStore(dir);
  const total = 5000;
  try {
    const lines = (async function* () {
      for (let i = 0; i < total; i += 1) {
        yield JSON.stringify({ ...record, path: `C:/bulk/file-${i}.bin` });
      }
    })();
    const result = await store.ingest({
      scanId: "d8d4d45a-5d31-4e43-86f1-8e22ab1d1b18",
      volumeId: "C:",
      lines
    });
    assert.equal(result.recordCount, total);
    assert.equal(result.status, "COMPLETE");
    assert.equal(store.list(1)[0].recordCount, total);
  } finally {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
