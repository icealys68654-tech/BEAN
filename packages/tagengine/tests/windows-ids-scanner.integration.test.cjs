const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const http = require("node:http");
const { spawn, spawnSync } = require("node:child_process");

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bean-ids-e2e-"));
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : 0;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function requestJson(url, token) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => {
        let parsed;
        try { parsed = JSON.parse(body); } catch { return reject(new Error(`Invalid JSON response: ${body}`)); }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.once("error", reject);
    req.setTimeout(3000, () => req.destroy(new Error("HTTP request timed out")));
  });
}

async function waitForServer(baseUrl, child) {
  const deadline = Date.now() + 15000;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`TagEngine exited early (${child.exitCode})`);
    try {
      const response = await requestJson(`${baseUrl}/api/health`);
      if (response.status === 200) return;
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`TagEngine did not become ready: ${lastError || "timeout"}`);
}

test("scanner evidence uploads through authenticated TagEngine HTTP API and retries idempotently", async (t) => {
  const dir = tempDir();
  const root = path.join(dir, "fixture");
  const evidence = path.join(dir, "evidence.jsonl");
  const baseline = path.join(dir, "baseline.sqlite");
  const findings = path.join(dir, "findings.jsonl");
  const dataDir = path.join(dir, "tagengine-data");
  const backupDir = path.join(dir, "backups");
  const token = "test-only-bean-ids-token";
  const scanId = "e2e00000-0000-4000-8000-000000000001";
  let server;
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "plain.txt"), "BEAN scanner integration fixture\n");
  fs.writeFileSync(path.join(root, "sample.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]));

  try {
    const scanner = path.resolve(__dirname, "../../../ops/windows/ids/scanner.py");
    const uploader = path.resolve(__dirname, "../../../ops/windows/ids_ingest.py");
    const python = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
    const scannerRun = spawnSync(python, [
      scanner, "scan", "--root", root, "--output", evidence,
      "--baseline", baseline, "--findings", findings, "--scan-id", scanId
    ], { encoding: "utf8" });
    if (scannerRun.error && scannerRun.error.code === "ENOENT") {
      t.skip(`Python interpreter '${python}' is not installed`);
      return;
    }
    assert.equal(scannerRun.status, 0, scannerRun.stderr || scannerRun.stdout);

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

    const port = await freePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    server = spawn(process.execPath, [path.resolve(__dirname, "../dist/server.js")], {
      cwd: path.resolve(__dirname, ".."),
      env: {
        ...process.env,
        NODE_ENV: "production",
        ENTEC_API_TOKEN: token,
        ENTEC_SNAPSHOT_DIR: dataDir,
        ENTEC_BACKUP_DIR: backupDir,
        PORT: String(port)
      },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let serverOutput = "";
    server.stdout.on("data", (chunk) => { serverOutput += chunk.toString(); });
    server.stderr.on("data", (chunk) => { serverOutput += chunk.toString(); });
    await waitForServer(baseUrl, server).catch((error) => {
      throw new Error(`${error.message}\n${serverOutput}`);
    });

    const unauthenticated = await requestJson(`${baseUrl}/api/ids/scans`);
    assert.equal(unauthenticated.status, 401);

    const uploadEnv = { ...process.env, ENTEC_API_TOKEN: token, TAGENGINE_URL: baseUrl };
    const uploadArgs = [
      uploader, "--jsonl", evidence, "--scan-id", scanId,
      "--volume-id", "fixture-volume", "--label", "scanner HTTP integration"
    ];
    const firstUpload = spawnSync(python, uploadArgs, { encoding: "utf8", env: uploadEnv, timeout: 30000 });
    assert.equal(firstUpload.status, 0, firstUpload.stderr || firstUpload.stdout);

    const listed = await requestJson(`${baseUrl}/api/ids/scans?limit=10`, token);
    assert.equal(listed.status, 200);
    assert.equal(listed.body.scans.length, 1);
    assert.equal(listed.body.scans[0].scanId, scanId);
    assert.equal(listed.body.scans[0].status, "COMPLETE");
    assert.equal(listed.body.scans[0].recordCount, records.length);

    const malformedEvidence = path.join(dir, "malformed.jsonl");
    fs.writeFileSync(malformedEvidence, fs.readFileSync(evidence, "utf8") + "{malformed-json\\n");
    const failedUpload = spawnSync(python, [
      uploader, "--jsonl", malformedEvidence,
      "--scan-id", "e2e00000-0000-4000-8000-000000000002",
      "--volume-id", "fixture-volume"
    ], { encoding: "utf8", env: uploadEnv, timeout: 30000 });
    assert.notEqual(failedUpload.status, 0, failedUpload.stdout);

    const afterFailure = await requestJson(`${baseUrl}/api/ids/scans?limit=10`, token);
    assert.equal(afterFailure.status, 200);
    assert.equal(afterFailure.body.scans.length, 1, "failed ingestion must not leave a partial scan");

    const retryUpload = spawnSync(python, uploadArgs, { encoding: "utf8", env: uploadEnv, timeout: 30000 });
    assert.equal(retryUpload.status, 0, retryUpload.stderr || retryUpload.stdout);
    const afterRetry = await requestJson(`${baseUrl}/api/ids/scans?limit=10`, token);
    assert.equal(afterRetry.status, 200);
    assert.equal(afterRetry.body.scans.length, 1);
    assert.equal(afterRetry.body.scans[0].recordCount, records.length);
  } finally {
    if (server && server.exitCode === null) {
      server.kill("SIGTERM");
      await new Promise((resolve) => {
        const timeout = setTimeout(resolve, 3000);
        server.once("exit", () => { clearTimeout(timeout); resolve(); });
      });
      if (server.exitCode === null) server.kill("SIGKILL");
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
