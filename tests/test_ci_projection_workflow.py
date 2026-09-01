"""Static contract for the CI ledger-projection smoke step.

The workflow cannot be executed here, so these tests read it as text and assert
the properties that matter: that the projection runs, that it runs early enough
to read committed evidence, that it proves determinism, and that adding it did
not widen the job's blast radius.

The RED tests describe the step before it exists; the baseline invariants
describe what must not change while adding it, so they pass from the start.
Each test reads the workflow itself rather than sharing module state, so a
missing or unreadable workflow fails them individually.

Contract: docs/JARVIS_LEDGER_ADAPTER.md
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "oss-admission-ci.yml"

PROJECTION = "scripts/project_ledger.py"
VALIDATOR = "scripts/validate_admissions.py"
DISCOVERY = "scripts/discover_dependencies.py"
CHECKOUT_PIN = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"


def workflow():
    if not WORKFLOW.is_file():
        raise AssertionError(f"{WORKFLOW.relative_to(ROOT)} is missing")
    return WORKFLOW.read_text(encoding="utf-8")


def position(text, needle):
    """Character offset of a command, or -1. Order in the file is order of
    execution: the job has a single linear step list."""
    return text.find(needle)


class ProjectionSmokeStep(unittest.TestCase):
    """RED-01..06 — the step the workflow must grow."""

    def test_red_01_workflow_runs_the_projection_script(self):
        self.assertIn(PROJECTION, workflow(),
                      "workflow must run scripts/project_ledger.py")

    def test_red_02_projection_runs_before_the_validator(self):
        text = workflow()
        projection, validator = position(text, PROJECTION), position(text, VALIDATOR)
        self.assertNotEqual(projection, -1, "projection step is absent")
        self.assertNotEqual(validator, -1, "validator step is absent")
        # The validator rewrites evidence/validation-result.json, so a later
        # projection would read that run's output instead of the committed file.
        self.assertLess(projection, validator,
                        "projection must run before validate_admissions.py")

    def test_red_03_projection_runs_twice_with_one_source_commit(self):
        text = workflow()
        self.assertEqual(text.count(PROJECTION), 2,
                         "determinism needs exactly two projection runs")
        self.assertEqual(text.count("--source-commit"), 2,
                         "both runs must pin the same source_commit")
        self.assertIn("SOURCE_COMMIT", text,
                      "the commit must come from one env value, not two literals")

    def test_red_04_both_outputs_live_under_runner_temp(self):
        text = workflow()
        outputs = re.findall(r"--output\s+\"?([^\s\"\\]+)", text)
        self.assertEqual(len(outputs), 2, f"expected two --output paths, got {outputs}")
        for path in outputs:
            self.assertTrue(path.startswith("$RUNNER_TEMP/"),
                            f"{path} must be under $RUNNER_TEMP, never the repository")

    def test_red_05_outputs_are_byte_compared(self):
        self.assertIn("cmp", workflow(),
                      "the two projections must be compared byte for byte")

    def test_red_06_source_commit_is_verified_against_the_json(self):
        text = workflow()
        self.assertIn("source_commit", text,
                      "the run must assert the projection's source_commit field")
        self.assertTrue("json" in text and "python3 -c" in text,
                        "verification must parse the JSON rather than grep it")


class BaselineInvariants(unittest.TestCase):
    """What must stay true while the step is added. These pass from the start."""

    def test_no_artifact_upload_action(self):
        self.assertNotIn("upload-artifact", workflow(),
                         "artifacts are out of scope and would need registry admission")

    def test_pull_request_head_sha_is_not_used(self):
        self.assertNotIn("pull_request.head.sha", workflow(),
                         "GITHUB_SHA names the tree that was actually checked out")

    def test_permissions_stay_read_only(self):
        text = workflow()
        self.assertIn("contents: read", text)
        self.assertNotIn("contents: write", text)

    def test_no_secrets_are_referenced(self):
        self.assertNotIn("secrets.", workflow())

    def test_the_job_list_is_unchanged(self):
        # Only keys under `jobs:`. Trigger names sit at the same indent under
        # `on:`, so scanning the whole file would count them as jobs.
        text = workflow()
        self.assertIn("\njobs:\n", text, "workflow has no jobs block")
        jobs = re.findall(r"^  ([A-Za-z0-9_-]+):$", text.split("\njobs:\n", 1)[1],
                          re.MULTILINE)
        self.assertEqual(jobs, ["validate"], f"no new job may appear, found {jobs}")

    def test_checkout_pin_is_unchanged(self):
        self.assertIn(CHECKOUT_PIN, workflow(),
                      "the admitted checkout SHA must not move")

    def test_only_the_admitted_action_is_used(self):
        uses = re.findall(r"uses:\s*(\S+)", workflow())
        self.assertEqual(uses, [CHECKOUT_PIN],
                         f"a new action would need registry admission, found {uses}")

    def test_existing_gate_commands_are_intact(self):
        text = workflow()
        self.assertIn(f"python3 {VALIDATOR}", text)
        self.assertIn(f"python3 {DISCOVERY} --check --strict", text)
        self.assertIn("python3 -m unittest discover -s tests -v", text)

    def test_existing_gate_order_is_preserved(self):
        text = workflow()
        validator = position(text, f"python3 {VALIDATOR}")
        discovery = position(text, f"python3 {DISCOVERY} --check --strict")
        tests = position(text, "python3 -m unittest discover -s tests -v")
        self.assertLess(validator, discovery, "validator must precede strict discovery")
        self.assertLess(discovery, tests, "strict discovery must precede the tests")

    def test_failures_are_not_swallowed(self):
        self.assertNotIn("continue-on-error", workflow(),
                         "FAIL(1) and ERROR(2) must both fail the job")


if __name__ == "__main__":
    unittest.main()
