/**
 * Validates and normalizes JSONL evidence emitted by the Windows filesystem IDS.
 *
 * The producer's "hash" field is a content SHA-256 only when
 * is_content_hashed=true. Otherwise it is a metadata-derived fingerprint.
 * Keep that distinction explicit in every downstream consumer.
 */

export type WindowsIdsHashKind = "CONTENT_SHA256" | "METADATA_FINGERPRINT";

export interface WindowsIdsEvidence {
  schemaVersion: "bean.windows-ids.evidence.v1";
  source: "WINDOWS_FILESYSTEM_IDS";
  path: string;
  hash: string;
  hashKind: WindowsIdsHashKind;
  entropyBits: number;
  entropyNormalized: number;
  magicMismatch: boolean;
  detectedType: string;
}

export interface WindowsIdsProducerRecord {
  path: string;
  hash: string;
  is_content_hashed: boolean;
  entropy_bits: number;
  entropy_norm: number;
  magic_mismatch: boolean;
  magic_info: string;
}

function fail(lineNumber: number, message: string): never {
  throw new Error(`Windows IDS JSONL line ${lineNumber}: ${message}`);
}

export function parseWindowsIdsRecord(
  value: unknown,
  lineNumber = 1
): WindowsIdsEvidence {
  if (!Number.isInteger(lineNumber) || lineNumber < 1) {
    throw new Error("lineNumber must be a positive integer");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return fail(lineNumber, "expected a JSON object");
  }

  const record = value as Record<string, unknown>;
  if (typeof record.path !== "string" || !record.path.trim()) {
    return fail(lineNumber, "path must be a non-empty string");
  }
  if (record.path.includes("\\0")) {
    return fail(lineNumber, "path contains a null character");
  }
  if (typeof record.hash !== "string" || !/^[a-f0-9]{64}$/i.test(record.hash)) {
    return fail(lineNumber, "hash must be a 64-character hexadecimal digest");
  }
  if (typeof record.is_content_hashed !== "boolean") {
    return fail(lineNumber, "is_content_hashed must be boolean");
  }
  if (
    typeof record.entropy_bits !== "number" ||
    !Number.isFinite(record.entropy_bits) ||
    record.entropy_bits < 0 ||
    record.entropy_bits > 8
  ) {
    return fail(lineNumber, "entropy_bits must be between 0 and 8");
  }
  if (
    typeof record.entropy_norm !== "number" ||
    !Number.isFinite(record.entropy_norm) ||
    record.entropy_norm < 0 ||
    record.entropy_norm > 1
  ) {
    return fail(lineNumber, "entropy_norm must be between 0 and 1");
  }
  if (typeof record.magic_mismatch !== "boolean") {
    return fail(lineNumber, "magic_mismatch must be boolean");
  }
  if (typeof record.magic_info !== "string") {
    return fail(lineNumber, "magic_info must be a string");
  }

  return {
    schemaVersion: "bean.windows-ids.evidence.v1",
    source: "WINDOWS_FILESYSTEM_IDS",
    path: record.path,
    hash: record.hash.toLowerCase(),
    hashKind: record.is_content_hashed ? "CONTENT_SHA256" : "METADATA_FINGERPRINT",
    entropyBits: record.entropy_bits,
    entropyNormalized: record.entropy_norm,
    magicMismatch: record.magic_mismatch,
    detectedType: record.magic_info
  };
}

/** Parse a single JSONL document. Blank lines are ignored; malformed lines fail closed. */
export function parseWindowsIdsJsonl(input: string): WindowsIdsEvidence[] {
  if (typeof input !== "string") {
    throw new Error("Windows IDS JSONL input must be a string");
  }

  const output: WindowsIdsEvidence[] = [];
  input.split(/\r?\n/).forEach((line, index) => {
    if (!line.trim()) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return fail(index + 1, "invalid JSON");
    }
    output.push(parseWindowsIdsRecord(parsed, index + 1));
  });
  return output;
}

/** Streaming parser for large scans; accepts Node Readable streams and async line iterables. */
export async function* parseWindowsIdsLines(
  lines: AsyncIterable<string>
): AsyncGenerator<WindowsIdsEvidence> {
  let lineNumber = 0;
  for await (const rawLine of lines) {
    lineNumber += 1;
    const line = rawLine.trim();
    if (!line) continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return fail(lineNumber, "invalid JSON");
    }
    yield parseWindowsIdsRecord(parsed, lineNumber);
  }
}
