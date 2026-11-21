import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import Database from 'better-sqlite3';

export interface IdsScanSummary {
  scanId: string;
  volumeId: string;
  label: string;
  status: string;
  startedAt: string;
  completedAt: string | null;
  recordCount: number;
}

type ProducerRecord = {
  path: string; hash: string; is_content_hashed: boolean;
  entropy_bits: number; entropy_norm: number;
  magic_mismatch: boolean; magic_info: string;
};

function validateRecord(value: unknown, line: number): ProducerRecord {
  const fail = (message: string): never => { throw new Error(`JSONL line ${line}: ${message}`); };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail('expected a JSON object');
  const r = value as Record<string, unknown>;
  if (typeof r.path !== 'string' || !r.path.trim() || r.path.includes('\0')) return fail('path must be a non-empty string without NUL');
  if (typeof r.hash !== 'string' || !/^[a-f0-9]{64}$/i.test(r.hash)) return fail('hash must be a 64-character SHA-256 digest');
  if (typeof r.is_content_hashed !== 'boolean') return fail('is_content_hashed must be boolean');
  if (typeof r.entropy_bits !== 'number' || !Number.isFinite(r.entropy_bits) || r.entropy_bits < 0 || r.entropy_bits > 8) return fail('entropy_bits must be between 0 and 8');
  if (typeof r.entropy_norm !== 'number' || !Number.isFinite(r.entropy_norm) || r.entropy_norm < 0 || r.entropy_norm > 1) return fail('entropy_norm must be between 0 and 1');
  if (typeof r.magic_mismatch !== 'boolean') return fail('magic_mismatch must be boolean');
  if (typeof r.magic_info !== 'string') return fail('magic_info must be a string');
  return r as ProducerRecord;
}

/** Durable, bounded-memory ingestion of the Windows IDS producer JSONL format. */
export class IdsIngestionStore {
  private readonly db: Database.Database;
  constructor(snapshotDir: string) {
    fs.mkdirSync(snapshotDir, { recursive: true });
    this.db = new Database(path.join(path.resolve(snapshotDir), 'ids-ingestion.sqlite'));
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ids_scans (
        scan_id TEXT PRIMARY KEY, volume_id TEXT NOT NULL, label TEXT NOT NULL,
        status TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT,
        record_count INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS ids_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
        path TEXT NOT NULL, hash TEXT NOT NULL, hash_kind TEXT NOT NULL,
        entropy_bits REAL NOT NULL, entropy_norm REAL NOT NULL,
        magic_mismatch INTEGER NOT NULL, magic_info TEXT NOT NULL, record_json TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES ids_scans(scan_id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_ids_events_scan ON ids_events(scan_id, id);
      CREATE INDEX IF NOT EXISTS idx_ids_events_path ON ids_events(path);
    `);
  }

  async ingest(input: {
    lines: AsyncIterable<string>; scanId?: string; volumeId: string; label?: string;
  }): Promise<IdsScanSummary> {
    const scanId = input.scanId || randomUUID();
    if (!/^[0-9a-f-]{36}$/i.test(scanId)) throw new Error('scanId must be a UUID');
    const volumeId = input.volumeId.trim();
    const label = (input.label || 'Windows IDS scan').trim();
    if (!volumeId || volumeId.length > 128) throw new Error('volumeId must be 1-128 characters');
    if (!label || label.length > 200) throw new Error('label must be 1-200 characters');

    const startedAt = new Date().toISOString();
    this.db.prepare('INSERT INTO ids_scans (scan_id, volume_id, label, status, started_at) VALUES (?, ?, ?, ?, ?)')
      .run(scanId, volumeId, label, 'INGESTING', startedAt);

    const insert = this.db.prepare(`INSERT INTO ids_events
      (scan_id, path, hash, hash_kind, entropy_bits, entropy_norm, magic_mismatch, magic_info, record_json)
      VALUES (@scanId, @path, @hash, @hashKind, @entropyBits, @entropyNorm, @magicMismatch, @magicInfo, @recordJson)`);
    const batch: Array<Record<string, unknown>> = [];
    const flush = this.db.transaction((rows: Array<Record<string, unknown>>) => {
      for (const row of rows) insert.run(row);
    });
    let lineNumber = 0;
    let recordCount = 0;
    try {
      for await (const raw of input.lines) {
        lineNumber += 1;
        if (Buffer.byteLength(raw, 'utf8') > 1024 * 1024) throw new Error(`JSONL line ${lineNumber} exceeds 1 MiB`);
        if (!raw.trim()) continue;
        if (lineNumber > 2_000_000) throw new Error('Scan exceeds the 2,000,000-line safety limit');
        let parsed: unknown;
        try { parsed = JSON.parse(raw); } catch { throw new Error(`JSONL line ${lineNumber}: invalid JSON`); }
        const record = validateRecord(parsed, lineNumber);
        batch.push({
          scanId, path: record.path, hash: record.hash.toLowerCase(),
          hashKind: record.is_content_hashed ? 'CONTENT_SHA256' : 'METADATA_FINGERPRINT',
          entropyBits: record.entropy_bits, entropyNorm: record.entropy_norm,
          magicMismatch: record.magic_mismatch ? 1 : 0, magicInfo: record.magic_info,
          recordJson: JSON.stringify(parsed)
        });
        recordCount += 1;
        if (batch.length >= 500) { flush(batch); batch.length = 0; }
      }
      if (batch.length) flush(batch);
      if (recordCount === 0) throw new Error('JSONL stream contained no records');
      const completedAt = new Date().toISOString();
      this.db.prepare("UPDATE ids_scans SET status = 'COMPLETE', completed_at = ?, record_count = ? WHERE scan_id = ?")
        .run(completedAt, recordCount, scanId);
      return { scanId, volumeId, label, status: 'COMPLETE', startedAt, completedAt, recordCount };
    } catch (error) {
      this.db.prepare('DELETE FROM ids_scans WHERE scan_id = ?').run(scanId);
      throw error;
    }
  }

  async backupTo(destinationDir: string): Promise<string> {
    fs.mkdirSync(destinationDir, { recursive: true });
    const target = path.join(destinationDir, 'ids-ingestion.sqlite');
    await this.db.backup(target);
    return target;
  }

  list(limit = 100): IdsScanSummary[] {
    const safeLimit = Math.max(1, Math.min(Math.floor(limit), 500));
    return this.db.prepare(`SELECT scan_id AS scanId, volume_id AS volumeId, label, status,
      started_at AS startedAt, completed_at AS completedAt, record_count AS recordCount
      FROM ids_scans ORDER BY started_at DESC LIMIT ?`).all(safeLimit) as IdsScanSummary[];
  }

  close(): void { this.db.close(); }
}
