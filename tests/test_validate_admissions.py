import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("validator", ROOT / "scripts" / "validate_admissions.py")
validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(validator)

class AdmissionValidationTest(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / "registry" / "oss-registry.json").read_text())["records"][0]
    def errors_for(self, mutate):
        record = copy.deepcopy(self.record); mutate(record); errors = []
        validator.validate_record(record, errors, validator.dt.date(2026, 8, 31)); return errors
    def test_baseline_record_is_valid(self): self.assertEqual(self.errors_for(lambda r: None), [])
    def test_branch_is_rejected_as_git_ref(self): self.assertTrue(self.errors_for(lambda r: r["source"].update(immutable_ref="main")))
    def test_unapproved_license_is_rejected(self): self.assertTrue(self.errors_for(lambda r: r.update(license="AGPL-3.0")))
    def test_pending_record_is_rejected(self): self.assertTrue(self.errors_for(lambda r: r.update(status="PENDING")))
    def test_expired_review_is_rejected(self): self.assertTrue(self.errors_for(lambda r: r.update(reviewed_at="2025-01-01")))
    def test_missing_evidence_is_rejected(self): self.assertTrue(self.errors_for(lambda r: r.update(evidence_refs=["evidence/nope.json"])))
    def test_ledger_status_must_match(self): self.assertTrue(self.errors_for(lambda r: r["jarvis_ledger"].update(governance_status="PENDING")))
