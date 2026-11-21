/**
 * Canonical contract for JSONL records emitted by the Windows IDS scanner.
 *
 * Keep this parser independent of HTTP and persistence so producers, tests, and
 * ingestion paths share one validation contract.
 */
export interface WindowsIdsRecord {
  path: string;
  hash: string;
  is_content_hashed: boolean;
  entropy_bits: number;
  entropy_norm: number;
  magic_mismatch: boolean;
  magic_info: string;
}

export function parseWindowsIdsRecord(value: unknown, lineNumber: number): WindowsIdsRecord {
  const fail = (message: string): never => {
    throw new Error(`JSONL line ${lineNumber}: ${message}`);
  };

  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return fail('expected a JSON object');
  }

  const record = value as Record<string, unknown>;
  if (typeof record.path !== 'string' || !record.path.trim() || record.path.includes('\\0')) {
    return fail('path must be a non-empty string without NUL');
  }
  if (typeof record.hash !== 'string' || !/^[a-f0-9]{64}$/i.test(record.hash)) {
    return fail('hash must be a 64-character SHA-256 digest');
  }
  if (typeof record.is_content_hashed !== 'boolean') {
    return fail('is_content_hashed must be boolean');
  }
  if (typeof record.entropy_bits !== 'number' || !Number.isFinite(record.entropy_bits) ||
      record.entropy_bits < 0 || record.entropy_bits > 8) {
    return fail('entropy_bits must be between 0 and 8');
  }
  if (typeof record.entropy_norm !== 'number' || !Number.isFinite(record.entropy_norm) ||
      record.entropy_norm < 0 || record.entropy_norm > 1) {
    return fail('entropy_norm must be between 0 and 1');
  }
  if (typeof record.magic_mismatch !== 'boolean') {
    return fail('magic_mismatch must be boolean');
  }
  if (typeof record.magic_info !== 'string') {
    return fail('magic_info must be a string');
  }

  return record as unknown as WindowsIdsRecord;
}

/** Parse one non-empty JSONL line and apply the canonical scanner contract. */
export function parseWindowsIdsJsonlLine(raw: string, lineNumber: number): WindowsIdsRecord {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error(`JSONL line ${lineNumber}: invalid JSON`);
  }
  return parseWindowsIdsRecord(value, lineNumber);
}
