import tempfile
import unittest
from collections import Counter
from pathlib import Path
from scanner import entropy_from_counts, file_evidence

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
if __name__ == "__main__": unittest.main()
