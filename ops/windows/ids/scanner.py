#!/usr/bin/env python3
"""BEAN Windows IDS scanner with SQLite-staged, bounded-memory scan state."""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
import sqlite3
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

CHUNK_SIZE = 1024 * 1024
SCHEMA_VERSION = "bean.windows-ids.evidence.v1"
SIGNATURES = {
    ".exe": (b"MZ", "PE/DOS executable"), ".dll": (b"MZ", "PE/DOS executable"),
    ".sys": (b"MZ", "PE/DOS executable"), ".png": (b"\x89PNG\r\n\x1a\n", "PNG image"),
    ".jpg": (b"\xff\xd8\xff", "JPEG image"), ".jpeg": (b"\xff\xd8\xff", "JPEG image"),
    ".pdf": (b"%PDF-", "PDF document"), ".zip": (b"PK\x03\x04", "ZIP archive"),
    ".gz": (b"\x1f\x8b", "GZIP archive"), ".elf": (b"\x7fELF", "ELF executable"),
}

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def entropy_from_counts(counts: Counter[int], total: int) -> float:
    if total <= 0:
        return 0.0
    return -sum((n / total) * math.log2(n / total) for n in counts.values() if n)

def file_evidence(path: Path) -> tuple[dict, str | None]:
    """Read a file in fixed-size chunks and detect unstable content."""
    try:
        before = path.stat(follow_symlinks=False)
        digest, counts, total, prefix = hashlib.sha256(), Counter(), 0, b""
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                if len(prefix) < 32:
                    prefix += chunk[:32 - len(prefix)]
                digest.update(chunk)
                counts.update(chunk)
                total += len(chunk)
        after = path.stat(follow_symlinks=False)
        stable = (before.st_size == after.st_size and
                  before.st_mtime_ns == after.st_mtime_ns and total == after.st_size)
        entropy = entropy_from_counts(counts, total)
        expected = SIGNATURES.get(path.suffix.lower())
        if expected is None:
            mismatch, info = False, "Unknown or unsupported file signature"
        else:
            signature, description = expected
            mismatch = not prefix.startswith(signature)
            info = ("Mismatch: expected " if mismatch else "Detected: ") + description
        record = {
            "path": str(path.resolve(strict=False)),
            "hash": digest.hexdigest(),
            "is_content_hashed": stable,
            "entropy_bits": round(entropy, 4),
            "entropy_norm": round(entropy / 8.0, 4),
            "magic_mismatch": mismatch,
            "magic_info": info if stable else info + "; file changed during read",
        }
        return record, None if stable else "file changed during scan; not baseline-eligible"
    except OSError as exc:
        return {}, f"{type(exc).__name__}: {exc}"

def iter_files(root: Path, exclusions: tuple[Path, ...]) -> Iterator[Path]:
    """Walk without following symlinks and prune excluded directory trees."""
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        kept = []
        for name in dirs:
            candidate = base / name
            if candidate.is_symlink():
                continue
            resolved = candidate.resolve(strict=False)
            if any(resolved == ex or ex in resolved.parents for ex in exclusions):
                continue
            kept.append(name)
        dirs[:] = kept
        for name in names:
            candidate = base / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            resolved = candidate.resolve(strict=False)
            if not any(resolved == ex or ex in resolved.parents for ex in exclusions):
                yield candidate

class ScanState:
    """Persistent baseline plus per-scan SQLite staging; no scan-sized Python collections."""
    def __init__(self, filename: Path):
        filename.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(filename)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY, sha256 TEXT NOT NULL,
                size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_files (
                scan_id TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL,
                size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
                PRIMARY KEY(scan_id, path)
            );
            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id, id);
        """)
        self.db.commit()

    def begin(self, scan_id: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM scan_files WHERE scan_id=?", (scan_id,))
            self.db.execute("DELETE FROM scan_findings WHERE scan_id=?", (scan_id,))

    def add_finding(self, scan_id: str, finding: dict) -> None:
        self.db.execute("INSERT INTO scan_findings(scan_id,payload) VALUES(?,?)",
                        (scan_id, json.dumps(finding, ensure_ascii=False, separators=(",", ":"))))

    def stage_file(self, scan_id: str, record: dict, size: int, mtime_ns: int) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO scan_files(scan_id,path,sha256,size,mtime_ns) VALUES(?,?,?,?,?)",
            (scan_id, record["path"], record["hash"], size, mtime_ns))
        old = self.db.execute("SELECT sha256 FROM files WHERE path=?", (record["path"],)).fetchone()
        if old is None:
            kind = "NEW_FILE"
        elif old[0] != record["hash"]:
            kind = "CONTENT_CHANGED"
        else:
            return
        self.add_finding(scan_id, {"type": kind, "path": record["path"],
                                   "sha256": record["hash"], "timestamp": utc_now()})

    def stage_error(self, scan_id: str, path: str, detail: str) -> None:
        self.add_finding(scan_id, {"type": "SCAN_ERROR", "path": path,
                                   "detail": detail, "timestamp": utc_now()})

    def add_removed_findings(self, scan_id: str) -> None:
        rows = self.db.execute("""
            SELECT f.path FROM files f
            LEFT JOIN scan_files s ON s.scan_id=? AND s.path=f.path
            WHERE s.path IS NULL ORDER BY f.path
        """, (scan_id,))
        for (path,) in rows:
            self.add_finding(scan_id, {"type": "FILE_REMOVED", "path": path,
                                       "timestamp": utc_now()})

    def promote(self, scan_id: str) -> None:
        # Atomic replacement: a failed transaction leaves the previous baseline intact.
        with self.db:
            self.db.execute("DELETE FROM files")
            self.db.execute("""
                INSERT INTO files(path,sha256,size,mtime_ns)
                SELECT path,sha256,size,mtime_ns FROM scan_files WHERE scan_id=?
            """, (scan_id,))

    def write_findings(self, scan_id: str, filename: Path) -> int:
        filename.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with filename.open("w", encoding="utf-8", newline="\n") as out:
            cursor = self.db.execute(
                "SELECT payload FROM scan_findings WHERE scan_id=? ORDER BY id", (scan_id,))
            for (payload,) in cursor:
                item = json.loads(payload)
                item["scan_id"] = scan_id
                out.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
                count += 1
        return count

    def cleanup(self, scan_id: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM scan_files WHERE scan_id=?", (scan_id,))
            self.db.execute("DELETE FROM scan_findings WHERE scan_id=?", (scan_id,))

    def close(self) -> None:
        self.db.close()

def scan(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("--root must be a directory")
    output = Path(args.output).expanduser().resolve()
    state_path = Path(args.baseline).expanduser().resolve()
    findings_path = Path(args.findings).expanduser().resolve() if args.findings else None
    if output == state_path or findings_path == state_path:
        raise ValueError("evidence/findings output must not overwrite the SQLite state database")
    exclusions = tuple(Path(p).expanduser().resolve() for p in args.exclude)
    scan_id, started = args.scan_id or str(uuid.uuid4()), utc_now()
    state = ScanState(state_path)
    state.begin(scan_id)
    errors = count = 0
    completed = False
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="\n") as out:
            for file_path in iter_files(root, exclusions):
                record, error = file_evidence(file_path)
                if error:
                    errors += 1
                    state.stage_error(scan_id, str(file_path), error)
                if not record:
                    continue
                out.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                count += 1
                if record["is_content_hashed"]:
                    try:
                        st = file_path.stat(follow_symlinks=False)
                        state.stage_file(scan_id, record, st.st_size, st.st_mtime_ns)
                    except OSError as exc:
                        errors += 1
                        state.stage_error(scan_id, str(file_path), f"{type(exc).__name__}: {exc}")
        if args.compare_baseline and errors == 0:
            state.add_removed_findings(scan_id)
        if args.promote_baseline:
            if errors:
                raise RuntimeError("baseline promotion refused: scan has collection errors")
            state.promote(scan_id)
        finding_count = state.write_findings(scan_id, findings_path) if findings_path else int(
            state.db.execute("SELECT COUNT(*) FROM scan_findings WHERE scan_id=?", (scan_id,)).fetchone()[0])
        summary = {
            "schema_version": SCHEMA_VERSION, "scan_id": scan_id, "root": str(root),
            "started_at": started, "completed_at": utc_now(), "record_count": count,
            "error_count": errors, "finding_count": finding_count,
            "baseline_promoted": bool(args.promote_baseline),
            "evidence_file": str(output),
            "findings_file": str(findings_path) if findings_path else None,
        }
        output.with_suffix(output.suffix + ".summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2))
        completed = True
        return 2 if errors else 0
    finally:
        if completed:
            state.cleanup(scan_id)
        state.close()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("scan", help="collect filesystem evidence")
    cmd.add_argument("--root", required=True)
    cmd.add_argument("--output", default="evidence/windows-ids.jsonl")
    cmd.add_argument("--baseline", default="state/windows-ids-baseline.sqlite")
    cmd.add_argument("--findings", default="evidence/windows-ids-findings.jsonl")
    cmd.add_argument("--exclude", action="append", default=[])
    cmd.add_argument("--scan-id")
    cmd.add_argument("--compare-baseline", action="store_true")
    cmd.add_argument("--promote-baseline", action="store_true")
    cmd.set_defaults(func=scan)
    return parser

def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"windows-ids: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
