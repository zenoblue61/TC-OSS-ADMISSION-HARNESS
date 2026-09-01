import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class VendoredEvidenceTest(unittest.TestCase):
    """A recorded hash is a claim about the tree; it has to stay true."""

    def test_vendored_files_match_their_recorded_hash(self):
        checked = 0
        for evidence in sorted((ROOT / "evidence").glob("*.json")):
            data = json.loads(evidence.read_text(encoding="utf-8"))
            for entry in data.get("vendored_files", []):
                with self.subTest(evidence=evidence.name, path=entry["path"]):
                    path = ROOT / entry["path"]
                    self.assertTrue(path.is_file(), f"vendored file is missing: {entry['path']}")
                    self.assertEqual(
                        hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"],
                        f"{entry['path']} no longer matches the content admitted in {evidence.name}")
                checked += 1
        # Without this the test passes vacuously if the evidence format changes.
        self.assertGreater(checked, 0, "no vendored files are recorded in evidence")


if __name__ == "__main__":
    unittest.main()
