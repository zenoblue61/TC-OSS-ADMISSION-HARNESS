"""Specification for the P4 TC-JARVIS ledger adapter.

Written before scripts/project_ledger.py existed; every test failed first and
was then made to pass. Each test loads the adapter itself rather than at module
scope, so a missing adapter fails all fourteen individually instead of
collapsing into one import error.

Contract: docs/JARVIS_LEDGER_ADAPTER.md
Schema:   schemas/jarvis-ledger-projection.schema.json
"""

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "project_ledger.py"

COMMIT_A = "cf8245dc0db33b86bcf433c73c61ec0f93c26b04"
COMMIT_B = "6c44c9df7ffad25c8382f278f31bf68b7c810670"


def adapter():
    """Load the adapter per test, so a missing adapter fails all fourteen
    individually rather than collapsing into one module-import error."""
    if not ADAPTER.is_file():
        raise AssertionError("scripts/project_ledger.py is missing")
    spec = importlib.util.spec_from_file_location("project_ledger", ADAPTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def registry(ledger_id="oss.left-pad", status="APPROVED"):
    return {"registry_version": "1.0.0", "records": [{
        "admission_id": "oss-left-pad", "component": "left-pad",
        "source": {"type": "npm", "source_url": "https://registry.npmjs.org/left-pad",
                   "immutable_ref": "1.3.0"},
        "license": "MIT", "intended_use": "fixture", "status": status,
        "owner": "tc.governance", "reviewed_at": "2026-08-31",
        "evidence_refs": ["evidence/left-pad.json"],
        "jarvis_ledger": {"ledger_id": ledger_id, "governance_status": "ADMITTED"}}]}


def candidate(status="ADMITTED_MATCH", matched="oss-left-pad", ref="1.3.0"):
    return {"candidate_id": f"npm:left-pad@{ref}", "ecosystem": "npm",
            "component": "left-pad", "source_url": "https://registry.npmjs.org/left-pad",
            "declared_ref": ref, "ref_kind": "exact_version", "pinned": True,
            "immutable_ref": ref, "status": status, "matched_admission_id": matched,
            "reason": "fixture", "occurrences": [{"file": "package.json",
                                                  "locator": "dependencies.left-pad"}]}


def discovery(scan_status="OK", candidates=None, errors=()):
    cands = [candidate()] if candidates is None else candidates
    return {"discovery_version": "1.0.0", "generator": "tc-oss-dependency-discovery",
            "registry_version": "1.0.0", "scan_status": scan_status,
            "summary": {"files_scanned": 1, "candidates": len(cands),
                        "admitted_match": 0, "pending_admission": 0, "unpinned_blocked": 0},
            "errors": list(errors), "scanned_files": ["package.json"], "candidates": cands}


def evidence(validation_status="PASS", **kwargs):
    return {
        "validation": {"validator": "tc-oss-admission-harness", "registry_version": "1.0.0",
                       "status": validation_status, "error_count": 0, "errors": []},
        "discovery": kwargs.pop("discovery", discovery()),
        "registry": kwargs.pop("registry", registry()),
    }


def project(ev=None, commit=COMMIT_A):
    return adapter().project(ev or evidence(), {"source_commit": commit})


class NeverGrantsAdmission(unittest.TestCase):
    """The adapter must never become an approval mechanism."""

    def test_01_admitted_match_does_not_become_an_admission_status(self):
        p = project(evidence(discovery=discovery(candidates=[candidate("ADMITTED_MATCH")])))
        entry = p["review_queue"][0]
        self.assertEqual(entry["discovery_status"], "ADMITTED_MATCH")
        self.assertNotIn("admission_status", entry)

    def test_02_unadmitted_candidate_gets_no_ledger_id(self):
        pending = candidate("PENDING_ADMISSION", matched=None, ref="9.9.9")
        unpinned = candidate("UNPINNED_BLOCKED", matched=None, ref="^1.0.0")
        p = project(evidence(discovery=discovery(candidates=[pending, unpinned])))
        for entry in p["review_queue"]:
            self.assertNotIn("id", entry)
            self.assertIsNone(entry["source_record_id"])

    def test_03_ledger_id_is_copied_from_the_registry_not_derived(self):
        # A ledger_id that breaks the oss-X -> oss.X convention must survive verbatim.
        p = project(evidence(registry=registry(ledger_id="oss.renamed-by-governance")))
        self.assertEqual(p["admitted_sources"][0]["id"], "oss.renamed-by-governance")

    def test_04_discovery_alone_produces_no_admitted_sources(self):
        ev = evidence()
        ev["registry"] = {"registry_version": "1.0.0", "records": []}
        p = project(ev)
        self.assertEqual(p["admitted_sources"], [])
        self.assertEqual(len(p["review_queue"]), 1)

    def test_05_unknown_matched_admission_id_fails_closed(self):
        ev = evidence(discovery=discovery(
            candidates=[candidate(matched="oss-does-not-exist")]))
        p = project(ev)
        self.assertEqual(p["adapter_status"], "FAIL")


class StatusPropagation(unittest.TestCase):

    def test_06_validation_fail_propagates_and_is_not_retryable(self):
        p = project(evidence("FAIL"))
        self.assertEqual(p["registry_integrity"], "FAIL")
        self.assertEqual(p["adapter_status"], "FAIL")
        self.assertEqual(project(evidence("FAIL"))["adapter_status"], "FAIL")

    def test_07_failed_scan_with_empty_queue_is_not_reported_clean(self):
        p = project(evidence(discovery=discovery("FAIL", candidates=[])))
        self.assertEqual(p["scan_integrity"], "FAIL")
        self.assertEqual(p["adapter_status"], "FAIL")
        self.assertEqual(p["review_queue"], [])

    def test_13_adapter_error_is_distinct_from_governance_fail(self):
        module = adapter()
        ev = evidence()
        del ev["validation"]
        p = module.project(ev, {"source_commit": COMMIT_A})
        self.assertEqual(p["adapter_status"], "ERROR")
        self.assertEqual(p["registry_integrity"], "UNKNOWN")
        self.assertNotEqual(p["adapter_status"], "FAIL")


class RunIdentity(unittest.TestCase):

    def test_08_identical_input_yields_identical_run_id_and_bytes(self):
        module = adapter()
        first, second = project(), project()
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertEqual(module.render(first), module.render(second))

    def test_09_same_input_at_a_different_commit_yields_a_different_run_id(self):
        self.assertNotEqual(project(commit=COMMIT_A)["run_id"],
                            project(commit=COMMIT_B)["run_id"])

    def test_15_key_order_and_whitespace_do_not_change_the_run_id(self):
        # run_id is computed over canonical JSON, so semantically identical
        # evidence that was serialised differently must project identically.
        plain = evidence()
        reordered = json.loads(json.dumps(plain, sort_keys=True, indent=4))
        self.assertNotEqual(list(plain["discovery"]), list(reordered["discovery"]),
                            "fixture must actually differ in key order to be meaningful")
        self.assertEqual(project(plain)["run_id"], project(reordered)["run_id"])


class SecretHygiene(unittest.TestCase):

    def test_10_url_credentials_never_reach_the_projection(self):
        leaky = candidate()
        leaky["source_url"] = "https://x-access-token:ghp_SECRETVALUE@github.com/o/r"
        rendered = adapter().render(project(
            evidence(discovery=discovery(candidates=[leaky]))))
        for token in ("ghp_", "x-access-token", "SECRETVALUE"):
            self.assertNotIn(token, rendered)

    def test_11_absolute_paths_in_errors_are_masked(self):
        ev = evidence(discovery=discovery("FAIL", candidates=[], errors=[
            "registry: unreadable or malformed ([Errno 13] Permission denied: "
            "'/home/runner/work/repo/registry/oss-registry.json')"]))
        rendered = adapter().render(project(ev))
        self.assertNotIn("/home/runner", rendered)
        self.assertIn("oss-registry.json", rendered)


class ReadOnlyAndAtomic(unittest.TestCase):

    def test_12_collect_does_not_modify_any_input_file(self):
        module = adapter()
        inputs = [ROOT / "registry" / "oss-registry.json",
                  ROOT / "evidence" / "validation-result.json",
                  ROOT / "evidence" / "discovery-result.json"]
        before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs]
        module.collect(ROOT)
        self.assertEqual([hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs], before)

    def test_14_an_error_run_publishes_nothing(self):
        module = adapter()
        with tempfile.TemporaryDirectory() as tmp:
            root, out = Path(tmp) / "empty", Path(tmp) / "projection.json"
            root.mkdir()
            code = module.main(["--root", str(root), "--output", str(out),
                                "--source-commit", COMMIT_A])
            self.assertEqual(code, 2, "missing input must exit ERROR(2), not PASS/FAIL")
            self.assertFalse(out.exists(), "ERROR publishes nothing")

    def test_16_a_fail_run_is_published_and_exits_one(self):
        # FAIL is a complete, determined verdict: the ledger has to record it.
        module = adapter()
        with tempfile.TemporaryDirectory() as tmp:
            root, out = Path(tmp) / "repo", Path(tmp) / "projection.json"
            (root / "evidence").mkdir(parents=True)
            (root / "registry").mkdir()
            ev = evidence("FAIL")
            (root / "evidence" / "validation-result.json").write_text(json.dumps(ev["validation"]))
            (root / "evidence" / "discovery-result.json").write_text(json.dumps(ev["discovery"]))
            (root / "registry" / "oss-registry.json").write_text(json.dumps(ev["registry"]))

            code = module.main(["--root", str(root), "--output", str(out),
                                "--source-commit", COMMIT_A])
            self.assertEqual(code, 1, "FAIL must exit 1")
            self.assertTrue(out.exists(), "FAIL must be published")
            self.assertEqual(json.loads(out.read_text())["adapter_status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
