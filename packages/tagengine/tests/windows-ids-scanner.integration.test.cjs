const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const Database = require("better-sqlite3");
const { IdsIngestionStore } = require("../dist/ids-ingestion-store.js");

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bean-ids-e2e-"));
}

test("Python scanner JSONL is accepted and persisted by TagEngine ingestion", async (t) => {
  const dir = tempDir();
  const root = path.join(dir, "fixture");
  const evidence = path.join(dir, "evidence.jsonl");
  const baseline = path.join(dir, "baseline.sqlite");
  const findings = path.join(dir, "findings.jsonl");
  const storeDir = path.join(dir, "tagengine");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "plain.txt"), "BEAN scanner integration fixture\n");
  fs.writeFileSync(path.join(root, "sample.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]));

  try {
    const scanner = path.resolve(__dirname, "../../../ops/windows/ids/scanner.py");
    const python = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
    const run = spawnSync(python, [
      scanner, "scan", "--root", root, "--output", evidence,
      "--baseline", baseline, "--findings", findings,
      "--scan-id", "e2e00000-0000-4000-8000-000000000001"
    ], { encoding: "utf8" });

    if (run.error && run.error.code === "ENOENT") {
      t.skip(`Python interpreter '${python}' is not installed`);
      return;
    }
    assert.equal(run.status, 0, run.stderr || run.stdout);
    const records = fs.readFileSync(evidence, "utf8").trim().split(/\r?\n/).map(JSON.parse);
    assert.equal(records.length, 2);
    for (const record of records) {
      assert.equal(typeof record.path, "string");
      assert.match(record.hash, /^[a-f0-9]{64}$/);
      assert.equal(typeof record.is_content_hashed, "boolean");
      assert.ok(record.entropy_bits >= 0 && record.entropy_bits <= 8);
      assert.ok(record.entropy_norm >= 0 && record.entropy_norm <= 1);
      assert.equal(typeof record.magic_mismatch, "boolean");
      assert.equal(typeof record.magic_info, "string");
    }

    const store = new IdsIngestionStore(storeDir);
    try {
      const scan = await store.ingest({
        scanId: "e2e00000-0000-4000-8000-000000000001",
        volumeId: "fixture-volume",
        label: "scanner-to-TagEngine integration",
        lines: require("node:readline").createInterface({ input: fs.createReadStream(evidence, { encoding: "utf8" }), crlfDelay: Infinity })
      });
      assert.equal(scan.status, "COMPLETE");
      assert.equal(scan.recordCount, 2);
      const db = new Database(path.join(storeDir, "ids-ingestion.sqlite"), { readonly: true });
      try {
        assert.equal(db.prepare("SELECT COUNT(*) AS n FROM ids_events WHERE scan_id = ?")
          .get(scan.scanId).n, 2);
        assert.equal(db.prepare("SELECT COUNT(*) AS n FROM ids_scans WHERE scan_id = ? AND status = 'COMPLETE'")
          .get(scan.scanId).n, 1);
      } finally {
        db.close();
      }
    } finally {
      store.close();
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
