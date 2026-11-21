import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanner import ScanState, entropy_from_counts, file_evidence, scan

class ScannerTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(entropy_from_counts(Counter(), 0), 0.0)
        self.assertEqual(entropy_from_counts(Counter({65: 20}), 20), 0.0)

    def test_evidence_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "hello.txt"
            path.write_text("hello world", encoding="utf-8")
            record, error = file_evidence(path)
            self.assertIsNone(error)
            self.assertEqual(len(record["hash"]), 64)
            self.assertTrue(record["is_content_hashed"])
            self.assertEqual(set(record), {"path","hash","is_content_hashed","entropy_bits","entropy_norm","magic_mismatch","magic_info"})
            self.assertGreaterEqual(record["entropy_bits"], 0)
            self.assertLessEqual(record["entropy_norm"], 1)

    def test_signature_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fake.exe"
            path.write_bytes(b"not a PE")
            record, error = file_evidence(path)
            self.assertIsNone(error)
            self.assertTrue(record["magic_mismatch"])

    def test_scan_promotes_and_detects_changes_and_removals(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "root"
            root.mkdir()
            first = root / "first.txt"
            removed = root / "removed.txt"
            first.write_text("one", encoding="utf-8")
            removed.write_text("remove me", encoding="utf-8")
            state = base / "state.sqlite"
            evidence = base / "first.jsonl"
            findings = base / "first-findings.jsonl"
            args = SimpleNamespace(root=str(root), output=str(evidence), baseline=str(state),
                findings=str(findings), exclude=[], scan_id="initial", compare_baseline=False,
                promote_baseline=True)
            self.assertEqual(scan(args), 0)
            removed.unlink()
            first.write_text("two", encoding="utf-8")
            args.scan_id = "followup"
            args.compare_baseline = True
            args.promote_baseline = False
            args.output = str(base / "second.jsonl")
            args.findings = str(base / "second-findings.jsonl")
            self.assertEqual(scan(args), 0)
            rows = [json.loads(line) for line in Path(args.findings).read_text(encoding="utf-8").splitlines()]
            kinds = {row["type"] for row in rows}
            self.assertIn("CONTENT_CHANGED", kinds)
            self.assertIn("FILE_REMOVED", kinds)
            self.assertTrue(all(row["scan_id"] == "followup" for row in rows))

    def test_state_cleanup_and_no_findings_without_compare(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "root"
            root.mkdir()
            (root / "new.txt").write_text("new", encoding="utf-8")
            args = SimpleNamespace(root=str(root), output=str(base / "out.jsonl"),
                baseline=str(base / "state.sqlite"), findings=str(base / "findings.jsonl"),
                exclude=[], scan_id="no-compare", compare_baseline=False, promote_baseline=False)
            self.assertEqual(scan(args), 0)
            self.assertEqual(Path(args.findings).read_text(encoding="utf-8"), "")
            state = ScanState(Path(args.baseline))
            try:
                self.assertEqual(state.db.execute("SELECT COUNT(*) FROM scan_files").fetchone()[0], 0)
                self.assertEqual(state.db.execute("SELECT COUNT(*) FROM scan_findings").fetchone()[0], 0)
            finally:
                state.close()

if __name__ == "__main__":
    unittest.main()
