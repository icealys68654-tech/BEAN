import test from "node:test";
import assert from "node:assert/strict";
import {
  parseWindowsIdsJsonl,
  parseWindowsIdsLines,
  parseWindowsIdsRecord
} from "./windows-ids-jsonl";

const contentRecord = {
  path: "C:/Windows/System32/example.exe",
  hash: "A".repeat(64),
  is_content_hashed: true,
  entropy_bits: 7.25,
  entropy_norm: 0.9063,
  magic_mismatch: false,
  magic_info: "PE_EXECUTABLE"
};

test("normalizes content-hash records without losing producer evidence", () => {
  const evidence = parseWindowsIdsRecord(contentRecord, 4);
  assert.equal(evidence.schemaVersion, "bean.windows-ids.evidence.v1");
  assert.equal(evidence.hash, "a".repeat(64));
  assert.equal(evidence.hashKind, "CONTENT_SHA256");
  assert.equal(evidence.entropyBits, 7.25);
  assert.equal(evidence.detectedType, "PE_EXECUTABLE");
});

test("labels metadata-derived fingerprints distinctly", () => {
  const evidence = parseWindowsIdsRecord({
    ...contentRecord,
    is_content_hashed: false
  });
  assert.equal(evidence.hashKind, "METADATA_FINGERPRINT");
});

test("parses JSONL, ignores blank lines, and retains line numbers for errors", () => {
  const jsonl = [
    JSON.stringify(contentRecord),
    "",
    JSON.stringify({ ...contentRecord, magic_mismatch: true })
  ].join("\n");
  const records = parseWindowsIdsJsonl(jsonl);
  assert.equal(records.length, 2);
  assert.equal(records[1].magicMismatch, true);
  assert.throws(
    () => parseWindowsIdsJsonl('{"path":'),
    /line 1: invalid JSON/
  );
});

test("rejects malformed evidence and out-of-range entropy", () => {
  assert.throws(
    () => parseWindowsIdsRecord({ ...contentRecord, hash: "not-a-hash" }),
    /64-character hexadecimal/
  );
  assert.throws(
    () => parseWindowsIdsRecord({ ...contentRecord, entropy_bits: 8.1 }),
    /between 0 and 8/
  );
  assert.throws(
    () => parseWindowsIdsRecord({ ...contentRecord, entropy_norm: -0.1 }),
    /between 0 and 1/
  );
  assert.throws(
    () => parseWindowsIdsRecord({ ...contentRecord, is_content_hashed: "yes" }),
    /must be boolean/
  );
});

test("stream parser handles async line sources", async () => {
  async function* lines(): AsyncGenerator<string> {
    yield JSON.stringify(contentRecord);
    yield "";
    yield JSON.stringify({ ...contentRecord, is_content_hashed: false });
  }
  const output = [];
  for await (const record of parseWindowsIdsLines(lines())) output.push(record);
  assert.equal(output.length, 2);
  assert.equal(output[1].hashKind, "METADATA_FINGERPRINT");
});
