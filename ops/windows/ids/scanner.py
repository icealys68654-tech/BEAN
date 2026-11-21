#!/usr/bin/env python3
"""BEAN Windows IDS scanner: bounded-memory filesystem evidence and baseline comparison."""
from __future__ import annotations
import argparse, hashlib, json, math, os, sqlite3, sys, uuid
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
def utc_now():
    return datetime.now(timezone.utc).isoformat()
def entropy_from_counts(counts: Counter[int], total: int) -> float:
    if total <= 0: return 0.0
    return -sum((n / total) * math.log2(n / total) for n in counts.values() if n)
def file_evidence(path: Path):
    """Hash and calculate entropy in bounded-memory chunks; flag unstable reads."""
    try:
        before = path.stat(follow_symlinks=False)
        digest, counts, total, prefix = hashlib.sha256(), Counter(), 0, b""
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk: break
                if len(prefix) < 32: prefix += chunk[:32-len(prefix)]
                digest.update(chunk); counts.update(chunk); total += len(chunk)
        after = path.stat(follow_symlinks=False)
        stable = before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns and total == after.st_size
        entropy = entropy_from_counts(counts, total)
        expected = SIGNATURES.get(path.suffix.lower())
        if expected is None:
            mismatch, info = False, "Unknown or unsupported file signature"
        else:
            signature, description = expected
            mismatch = not prefix.startswith(signature)
            info = ("Mismatch: expected " if mismatch else "Detected: ") + description
        record = {"path": str(path.resolve(strict=False)), "hash": digest.hexdigest(),
            "is_content_hashed": stable, "entropy_bits": round(entropy, 4),
            "entropy_norm": round(entropy / 8.0, 4), "magic_mismatch": mismatch,
            "magic_info": info if stable else info + "; file changed during read"}
        return record, None if stable else "file changed during scan; not baseline-eligible"
    except OSError as exc:
        return {}, f"{type(exc).__name__}: {exc}"
def iter_files(root: Path, exclusions: tuple[Path, ...]) -> Iterator[Path]:
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        base = Path(current); kept = []
        for name in dirs:
            candidate = base / name
            if candidate.is_symlink(): continue
            resolved = candidate.resolve(strict=False)
            if any(resolved == ex or ex in resolved.parents for ex in exclusions): continue
            kept.append(name)
        dirs[:] = kept
        for name in names:
            candidate = base / name
            if candidate.is_symlink() or not candidate.is_file(): continue
            resolved = candidate.resolve(strict=False)
            if not any(resolved == ex or ex in resolved.parents for ex in exclusions):
                yield candidate
class Baseline:
    """SQLite-backed approved inventory. Promotion is explicit."""
    def __init__(self, filename: Path):
        filename.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(filename)
        self.db.execute("CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL)")
        self.db.commit()
    def lookup(self, path):
        row = self.db.execute("SELECT sha256 FROM files WHERE path=?", (path,)).fetchone()
        return row[0] if row else None
    def compare(self, record):
        old = self.lookup(record["path"])
        return "NEW_FILE" if old is None else ("CONTENT_CHANGED" if old != record["hash"] else "UNCHANGED")
    def removed(self, seen):
        return [r[0] for r in self.db.execute("SELECT path FROM files") if r[0] not in seen]
    def promote(self, records):
        with self.db:
            self.db.execute("DELETE FROM files")
            self.db.executemany("INSERT INTO files VALUES(?,?,?,?)",
                [(r["path"], r["hash"], size, mtime) for r, size, mtime in records])
    def close(self): self.db.close()
def scan(args):
    root = Path(args.root).expanduser().resolve(strict=True)
    if not root.is_dir(): raise ValueError("--root must be a directory")
    output, baseline_path = Path(args.output).resolve(), Path(args.baseline).resolve()
    exclusions = tuple(Path(p).expanduser().resolve() for p in args.exclude)
    scan_id, started = args.scan_id or str(uuid.uuid4()), utc_now()
    baseline = Baseline(baseline_path)
    findings_path = Path(args.findings).resolve() if args.findings else None
    promotion, seen, findings = [], set(), []
    errors = count = 0
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="\n") as out:
            for file_path in iter_files(root, exclusions):
                record, error = file_evidence(file_path)
                if error:
                    errors += 1
                    findings.append({"scan_id": scan_id, "type": "SCAN_ERROR", "path": str(file_path),
                                     "detail": error, "timestamp": utc_now()})
                    if not record: continue
                out.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                count += 1; seen.add(record["path"])
                if record["is_content_hashed"]:
                    st = file_path.stat(follow_symlinks=False)
                    promotion.append((record, st.st_size, st.st_mtime_ns))
                    if args.compare_baseline:
                        kind = baseline.compare(record)
                        if kind != "UNCHANGED":
                            findings.append({"scan_id": scan_id, "type": kind, "path": record["path"],
                                             "sha256": record["hash"], "timestamp": utc_now()})
        if args.compare_baseline and errors == 0:
            for missing in baseline.removed(seen):
                findings.append({"scan_id": scan_id, "type": "FILE_REMOVED", "path": missing, "timestamp": utc_now()})
        if args.promote_baseline:
            if errors: raise RuntimeError("baseline promotion refused: scan has collection errors")
            baseline.promote(promotion)
        if findings_path:
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            with findings_path.open("w", encoding="utf-8", newline="\n") as out:
                for finding in findings: out.write(json.dumps(finding, ensure_ascii=False) + "\n")
        summary = {"schema_version": SCHEMA_VERSION, "scan_id": scan_id, "root": str(root),
            "started_at": started, "completed_at": utc_now(), "record_count": count,
            "error_count": errors, "finding_count": len(findings), "baseline_promoted": bool(args.promote_baseline),
            "evidence_file": str(output), "findings_file": str(findings_path) if findings_path else None}
        output.with_suffix(output.suffix + ".summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
        print(json.dumps(summary, indent=2))
        return 2 if errors else 0
    finally: baseline.close()
def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("scan", help="collect filesystem evidence")
    cmd.add_argument("--root", required=True); cmd.add_argument("--output", default="evidence/windows-ids.jsonl")
    cmd.add_argument("--baseline", default="state/windows-ids-baseline.sqlite")
    cmd.add_argument("--findings", default="evidence/windows-ids-findings.jsonl")
    cmd.add_argument("--exclude", action="append", default=[]); cmd.add_argument("--scan-id")
    cmd.add_argument("--compare-baseline", action="store_true"); cmd.add_argument("--promote-baseline", action="store_true")
    cmd.set_defaults(func=scan)
    return parser
def main():
    args = build_parser().parse_args()
    try: return args.func(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"windows-ids: {exc}", file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())
