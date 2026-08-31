import contextlib
import hashlib
import importlib.util
import io
import json
import random
import re
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SAMPLE = FIXTURES / "sample-project"
APPROVING_REGISTRY = FIXTURES / "registry" / "approving-registry.json"
MALFORMED_REGISTRY = FIXTURES / "registry" / "malformed-registry.json"

spec = importlib.util.spec_from_file_location(
    "discovery", ROOT / "scripts" / "discover_dependencies.py")
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)


def discover(root=SAMPLE, registry=APPROVING_REGISTRY, excludes=()):
    return discovery.build_result(Path(root), tuple(excludes), Path(registry))


def raw_scan(root=SAMPLE):
    """Reproduce build_result's scanning phase so finding order can be permuted."""
    scan = discovery.Scan()
    root = Path(root)
    for rel, path, scanner in discovery.collect_targets(root, ()):
        scan.seen_file(rel)
        if scanner is discovery.scan_requirements:
            scanner(path, rel, scan, root)
        else:
            scanner(path, rel, scan)
    return scan


def find(result, ecosystem, component, declared_ref=None):
    matches = [c for c in result["candidates"]
               if c["ecosystem"] == ecosystem and c["component"] == component
               and (declared_ref is None or c["declared_ref"] == declared_ref)]
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one {ecosystem}:{component}@{declared_ref}, got {len(matches)}")
    return matches[0]


def tree_digest(path):
    entries = []
    for item in sorted(Path(path).rglob("*")):
        if item.is_file():
            entries.append((item.relative_to(path).as_posix(),
                            hashlib.sha256(item.read_bytes()).hexdigest()))
    return entries


class NpmDiscoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = discover()

    def test_exact_pin_matching_registry_is_admitted(self):
        candidate = find(self.result, "npm", "left-pad", "1.3.0")
        self.assertEqual(candidate["status"], discovery.ADMITTED_MATCH)
        self.assertEqual(candidate["ref_kind"], "exact_version")
        self.assertTrue(candidate["pinned"])
        self.assertEqual(candidate["matched_admission_id"], "oss-fixture-left-pad")

    def test_version_range_is_unpinned_blocked(self):
        candidate = find(self.result, "npm", "lodash", "^4.17.21")
        self.assertEqual(candidate["status"], discovery.UNPINNED_BLOCKED)
        self.assertEqual(candidate["ref_kind"], "version_range")
        self.assertFalse(candidate["pinned"])
        self.assertIsNone(candidate["immutable_ref"])

    def test_dist_tag_is_unpinned_blocked(self):
        candidate = find(self.result, "npm", "eslint", "latest")
        self.assertEqual(candidate["status"], discovery.UNPINNED_BLOCKED)
        self.assertEqual(candidate["ref_kind"], "latest")

    def test_lockfile_resolved_version_is_a_separate_pinned_candidate(self):
        candidate = find(self.result, "npm", "lodash", "4.17.21")
        self.assertEqual(candidate["status"], discovery.PENDING_ADMISSION)
        self.assertTrue(candidate["pinned"])
        self.assertEqual([o["file"] for o in candidate["occurrences"]], ["package-lock.json"])

    def test_registry_ref_normalisation_matches_v_prefixed_pin(self):
        candidate = find(self.result, "npm", "typescript", "5.4.5")
        self.assertEqual(candidate["status"], discovery.ADMITTED_MATCH)
        self.assertEqual(candidate["matched_admission_id"], "oss-fixture-typescript")

    def test_occurrences_merge_across_manifest_and_lockfile(self):
        candidate = find(self.result, "npm", "left-pad", "1.3.0")
        self.assertEqual([o["file"] for o in candidate["occurrences"]],
                         ["package-lock.json", "package.json"])
        self.assertIn("integrity", candidate["occurrences"][0])

    def test_local_file_protocol_is_not_an_external_source(self):
        self.assertFalse([c for c in self.result["candidates"] if c["component"] == "local-tool"])


class PythonDiscoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = discover()

    def test_exact_pin_is_pending_admission(self):
        candidate = find(self.result, "pypi", "requests", "2.31.0")
        self.assertEqual(candidate["status"], discovery.PENDING_ADMISSION)
        self.assertEqual(candidate["ref_kind"], "exact_version")
        self.assertEqual(candidate["source_url"], "https://pypi.org/project/requests")

    def test_version_range_is_unpinned_blocked(self):
        candidate = find(self.result, "pypi", "urllib3", ">=1.26,<3")
        self.assertEqual(candidate["status"], discovery.UNPINNED_BLOCKED)
        self.assertEqual(candidate["ref_kind"], "version_range")

    def test_unconstrained_requirement_is_unpinned_blocked(self):
        candidate = find(self.result, "pypi", "flask", "*")
        self.assertEqual(candidate["status"], discovery.UNPINNED_BLOCKED)
        self.assertEqual(candidate["ref_kind"], "unspecified")

    def test_extras_and_environment_markers_are_stripped(self):
        candidate = find(self.result, "pypi", "pinned-extra", "3.0.1")
        self.assertEqual(candidate["status"], discovery.PENDING_ADMISSION)

    def test_included_requirements_file_is_followed(self):
        candidate = find(self.result, "pypi", "pytest", "8.2.0")
        self.assertEqual([o["file"] for o in candidate["occurrences"]], ["requirements-dev.txt"])

    def test_pep621_and_build_system_requirements_are_discovered(self):
        self.assertEqual(find(self.result, "pypi", "httpx", "0.27.0")["status"],
                         discovery.PENDING_ADMISSION)
        self.assertEqual(find(self.result, "pypi", "setuptools", "69.5.1")["status"],
                         discovery.PENDING_ADMISSION)
        self.assertEqual(find(self.result, "pypi", "mkdocs", "1.6.0")["status"],
                         discovery.PENDING_ADMISSION)

    def test_poetry_caret_constraint_is_unpinned_blocked(self):
        candidate = find(self.result, "pypi", "rich", "^13.7.0")
        self.assertEqual(candidate["status"], discovery.UNPINNED_BLOCKED)

    def test_poetry_bare_version_is_an_exact_pin(self):
        candidate = find(self.result, "pypi", "typer", "0.12.3")
        self.assertEqual(candidate["ref_kind"], "exact_version")

    def test_python_interpreter_constraint_is_not_a_dependency(self):
        self.assertFalse([c for c in self.result["candidates"] if c["component"] == "python"])


class GitAndActionDiscoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = discover()

    def test_action_pinned_to_sha_matches_registry(self):
        candidate = find(self.result, "github-action", "actions/checkout")
        self.assertEqual(candidate["status"], discovery.ADMITTED_MATCH)
        self.assertEqual(candidate["ref_kind"], "commit_sha")
        self.assertEqual(candidate["matched_admission_id"], "oss-fixture-actions-checkout")

    def test_action_tag_reference_is_unpinned_blocked(self):
        candidate = find(self.result, "github-action", "actions/setup-node", "v4")
        self.assertEqual(candidate["status"], discovery.UNPINNED_BLOCKED)
        self.assertEqual(candidate["ref_kind"], "tag")

    def test_local_action_reference_is_ignored(self):
        self.assertFalse([c for c in self.result["candidates"]
                          if c["component"].startswith(".")])

    def test_docker_uses_reference_is_discovered(self):
        candidate = find(self.result, "docker", "alpine", "3.19")
        self.assertEqual(candidate["status"], discovery.UNPINNED_BLOCKED)

    def test_git_dependency_pinned_to_sha_matches_registry(self):
        candidate = find(self.result, "git", "vendored-lib")
        self.assertEqual(candidate["status"], discovery.ADMITTED_MATCH)
        self.assertEqual(candidate["source_url"], "https://github.com/example/vendored-lib")

    def test_git_branch_reference_is_unpinned_blocked(self):
        self.assertEqual(find(self.result, "git", "edge-lib", "main")["ref_kind"], "branch")
        self.assertEqual(find(self.result, "git", "py-edge", "develop")["status"],
                         discovery.UNPINNED_BLOCKED)

    def test_poetry_git_tag_is_unpinned_blocked(self):
        self.assertEqual(find(self.result, "git", "poetry-tag-lib", "v2.0.0")["ref_kind"], "tag")

    def test_vendored_source_declaration_is_discovered(self):
        pinned = find(self.result, "git", "vendored-crypto")
        self.assertEqual(pinned["status"], discovery.PENDING_ADMISSION)
        self.assertEqual(pinned["occurrences"][0]["file"], "vendor/vendored-sources.json")
        self.assertEqual(find(self.result, "git", "vendored-floating")["status"],
                         discovery.UNPINNED_BLOCKED)


class RegistryComparisonTest(unittest.TestCase):
    def test_ref_mismatch_on_known_source_is_pending(self):
        candidate = find(discover(), "git", "example-git")
        self.assertEqual(candidate["status"], discovery.PENDING_ADMISSION)
        self.assertIsNone(candidate["matched_admission_id"])
        self.assertIn("immutable_ref", candidate["reason"])

    def test_non_approved_registry_record_never_admits(self):
        candidate = find(discover(), "git", "poetry-git-lib")
        self.assertEqual(candidate["status"], discovery.PENDING_ADMISSION)
        self.assertIn("PENDING", candidate["reason"])

    def test_unknown_source_is_pending(self):
        candidate = find(discover(), "pypi", "requests", "2.31.0")
        self.assertIn("no APPROVED registry record", candidate["reason"])

    def test_missing_registry_fails_closed(self):
        result = discover(registry=FIXTURES / "registry" / "does-not-exist.json")
        self.assertEqual(result["scan_status"], "FAIL")
        self.assertTrue(any("missing" in error for error in result["errors"]))
        self.assertEqual(result["summary"]["admitted_match"], 0)

    def test_malformed_registry_fails_closed(self):
        result = discover(registry=MALFORMED_REGISTRY)
        self.assertEqual(result["scan_status"], "FAIL")
        self.assertEqual(result["summary"]["admitted_match"], 0)
        self.assertTrue(all(c["status"] != discovery.ADMITTED_MATCH for c in result["candidates"]))

    def test_admission_is_keyed_on_source_url_and_ref_only(self):
        # The registry spells the source with a .git suffix; discovery sees the
        # bare URL. Matching must survive that, and nothing else may be consulted.
        registry = discovery.load_registry(APPROVING_REGISTRY, discovery.Scan())
        self.assertIn(("https://github.com/example/vendored-lib",
                       "1111111111111111111111111111111111111111"), registry.approved)


class FailClosedInputTest(unittest.TestCase):
    def assert_fails_closed(self, root, needle):
        result = discover(root=root)
        self.assertEqual(result["scan_status"], "FAIL", result["errors"])
        self.assertTrue(any(needle in error for error in result["errors"]), result["errors"])

    def test_malformed_package_json(self):
        self.assert_fails_closed(FIXTURES / "malformed-package-json", "malformed JSON")

    def test_malformed_pyproject(self):
        self.assert_fails_closed(FIXTURES / "malformed-pyproject", "malformed TOML")

    def test_missing_requirements_include(self):
        self.assert_fails_closed(FIXTURES / "missing-include", "included requirements file is missing")

    def test_malformed_vendored_manifest(self):
        self.assert_fails_closed(FIXTURES / "malformed-vendored", "missing source_url")

    def test_clean_scan_reports_ok(self):
        self.assertEqual(discover()["scan_status"], "OK")

    def test_invalid_scan_root_exits_non_zero(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = discovery.main(["--root", str(FIXTURES / "no-such-tree")])
        self.assertEqual(code, 1)
        self.assertIn("SCAN_ROOT_INVALID", stderr.getvalue())


class DeterminismTest(unittest.TestCase):
    def test_repeated_runs_are_byte_identical(self):
        self.assertEqual(discovery.render(discover()), discovery.render(discover()))

    def test_candidates_are_sorted_by_stable_key(self):
        candidates = discover()["candidates"]
        keys = [(c["ecosystem"], c["component"], c["source_url"], c["declared_ref"])
                for c in candidates]
        self.assertEqual(keys, sorted(keys))

    def test_output_is_independent_of_discovery_order(self):
        registry = discovery.load_registry(APPROVING_REGISTRY, discovery.Scan())
        scan = raw_scan()
        baseline = discovery.build_candidates(scan, registry)
        for seed in (1, 7, 42):
            shuffled = discovery.Scan()
            shuffled.findings = list(scan.findings)
            random.Random(seed).shuffle(shuffled.findings)
            self.assertEqual(discovery.build_candidates(shuffled, registry), baseline)

    def test_scanned_files_and_errors_are_sorted(self):
        result = discover(root=FIXTURES)
        self.assertEqual(result["scanned_files"], sorted(result["scanned_files"]))
        self.assertEqual(result["errors"], sorted(result["errors"]))

    def test_output_carries_no_timestamp_or_absolute_path(self):
        rendered = discovery.render(discover())
        self.assertNotIn(str(ROOT), rendered)
        self.assertIsNone(re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:", rendered))
        for key in ("collected_at", "generated_at", "timestamp"):
            self.assertNotIn(key, rendered)

    def test_relocating_the_tree_does_not_change_output(self):
        baseline = discovery.render(discover())
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "relocated"
            shutil.copytree(SAMPLE, copy)
            self.assertEqual(discovery.render(discover(root=copy)), baseline)


class SafetyContractTest(unittest.TestCase):
    def test_discovery_never_emits_an_approved_status(self):
        result = discover()
        statuses = {c["status"] for c in result["candidates"]}
        self.assertTrue(statuses <= {discovery.ADMITTED_MATCH, discovery.PENDING_ADMISSION,
                                     discovery.UNPINNED_BLOCKED})
        # Only the registry may hold APPROVED; discovery must never emit it as a value.
        self.assertNotIn('"status": "APPROVED"', discovery.render(result))

    def test_scanning_does_not_modify_any_input(self):
        before = tree_digest(FIXTURES)
        discover(root=FIXTURES)
        self.assertEqual(tree_digest(FIXTURES), before)

    def test_registry_is_never_rewritten(self):
        before = APPROVING_REGISTRY.read_bytes()
        discover()
        self.assertEqual(APPROVING_REGISTRY.read_bytes(), before)

    def test_result_conforms_to_the_published_schema_contract(self):
        schema = json.loads((ROOT / "schemas" / "oss-discovery.schema.json").read_text())
        item = schema["properties"]["candidates"]["items"]
        allowed = {key: set(item["properties"][key]["enum"])
                   for key in ("ecosystem", "ref_kind", "status")}
        required = set(item["required"])
        result = discover()
        self.assertLessEqual(set(result), set(schema["properties"]))
        self.assertLessEqual(set(schema["required"]), set(result))
        for candidate in result["candidates"]:
            self.assertLessEqual(required, set(candidate))
            self.assertLessEqual(set(candidate), set(item["properties"]))
            for key, values in allowed.items():
                self.assertIn(candidate[key], values)
            if candidate["status"] == discovery.ADMITTED_MATCH:
                self.assertTrue(candidate["pinned"])
                self.assertIsInstance(candidate["matched_admission_id"], str)
            else:
                self.assertIsNone(candidate["matched_admission_id"])
            self.assertEqual(candidate["pinned"], candidate["immutable_ref"] is not None)


class NormalisationTest(unittest.TestCase):
    def test_equivalent_source_url_spellings_collapse(self):
        canonical = "https://github.com/example/lib"
        for spelling in ("https://github.com/example/lib",
                         "https://github.com/example/lib.git",
                         "https://github.com/example/lib/",
                         "git+https://github.com/example/lib.git",
                         "git://github.com/example/lib.git",
                         "ssh://git@github.com/example/lib.git",
                         "git@github.com:example/lib.git",
                         "github:example/lib",
                         "https://GitHub.com/example/lib"):
            self.assertEqual(discovery.normalize_source_url(spelling), canonical, spelling)

    def test_local_paths_are_not_remote_sources(self):
        for value in ("./local", "../local", "file:../local", "", "not a url"):
            self.assertIsNone(discovery.normalize_source_url(value))

    def test_canonical_ref_folds_version_and_sha_spellings(self):
        self.assertEqual(discovery.canonical_ref("v1.2.3"), "1.2.3")
        self.assertEqual(discovery.canonical_ref("=1.2.3"), "1.2.3")
        self.assertEqual(discovery.canonical_ref("A" * 40), "a" * 40)

    def test_only_sha_refs_are_immutable(self):
        self.assertEqual(discovery.classify_git_ref("a" * 40), "commit_sha")
        for floating in ("main", "v1.0.0", "refs/heads/topic", "latest", "semver:^1.0.0"):
            self.assertNotIn(discovery.classify_git_ref(floating), discovery.IMMUTABLE_KINDS)

    def test_action_ref_immutability(self):
        self.assertEqual(discovery.classify_action_ref("b" * 40), "commit_sha")
        for floating in ("v4", "v4.1.1", "main", "latest"):
            self.assertNotIn(discovery.classify_action_ref(floating), discovery.IMMUTABLE_KINDS)


class ExclusionTest(unittest.TestCase):
    def test_installed_package_trees_are_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
            nested = root / "node_modules" / "left-pad"
            nested.mkdir(parents=True)
            (nested / "package.json").write_text(json.dumps({"dependencies": {"sneaky": "^9.9.9"}}))
            result = discover(root=root)
            self.assertEqual(result["scanned_files"], ["package.json"])
            self.assertFalse([c for c in result["candidates"] if c["component"] == "sneaky"])

    def test_repository_scan_excludes_the_fixture_tree(self):
        result = discover(root=ROOT, registry=ROOT / "registry" / "oss-registry.json")
        self.assertEqual(result["scan_status"], "OK", result["errors"])
        self.assertFalse([f for f in result["scanned_files"] if f.startswith("tests/fixtures")])

    def test_additional_exclude_prefix_is_honoured(self):
        self.assertTrue([f for f in discover()["scanned_files"] if f.startswith("vendor/")])
        self.assertFalse([f for f in discover(excludes=("vendor",))["scanned_files"]
                          if f.startswith("vendor/")])


class NpmSpecifierTest(unittest.TestCase):
    def test_remote_tarball_is_not_mistaken_for_a_version(self):
        ecosystem, kind, url, _ = discovery.classify_npm_spec("https://example.com/pkg-1.0.0.tgz")
        self.assertEqual(ecosystem, "url")
        self.assertNotIn(kind, discovery.IMMUTABLE_KINDS)
        self.assertEqual(url, "https://example.com/pkg-1.0.0.tgz")

    def test_alias_resolves_to_the_aliased_package(self):
        ecosystem, kind, url, ref = discovery.classify_npm_spec("npm:left-pad@1.3.0")
        self.assertEqual((ecosystem, kind, ref), ("npm", "exact_version", "1.3.0"))
        self.assertEqual(url, "https://registry.npmjs.org/left-pad")

    def test_repository_local_protocols_are_not_external_sources(self):
        for spec in ("file:../x", "link:../x", "workspace:*", "portal:../x"):
            self.assertEqual(discovery.classify_npm_spec(spec), (None, None, None, None), spec)

    def test_github_shorthand_is_a_git_source(self):
        ecosystem, kind, url, _ = discovery.classify_npm_spec("owner/repo#" + "c" * 40)
        self.assertEqual((ecosystem, kind, url),
                         ("git", "commit_sha", "https://github.com/owner/repo"))

    def test_semver_fragment_on_a_git_url_is_not_immutable(self):
        _, kind, _, _ = discovery.classify_npm_spec(
            "git+https://github.com/o/r.git#semver:^1.0.0")
        self.assertNotIn(kind, discovery.IMMUTABLE_KINDS)


class CommandLineTest(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = discovery.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_write_then_check_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "discovery-result.json"
            base = ["--root", str(SAMPLE), "--registry", str(APPROVING_REGISTRY),
                    "--output", str(output)]
            self.assertEqual(self.run_cli(base)[0], 0)
            self.assertEqual(self.run_cli(base + ["--check"])[0], 0)

            output.write_text(json.dumps({"drifted": True}))
            code, _, err = self.run_cli(base + ["--check"])
            self.assertEqual(code, 1)
            self.assertIn("DISCOVERY_EVIDENCE_STALE", err)

    def test_check_without_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = self.run_cli(
                ["--root", str(SAMPLE), "--registry", str(APPROVING_REGISTRY),
                 "--output", str(Path(tmp) / "absent.json"), "--check"])
            self.assertEqual(code, 1)
            self.assertIn("DISCOVERY_EVIDENCE_MISSING", err)

    def test_strict_mode_fails_on_outstanding_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            argv = ["--root", str(SAMPLE), "--registry", str(APPROVING_REGISTRY),
                    "--output", str(Path(tmp) / "out.json")]
            self.assertEqual(self.run_cli(argv)[0], 0)
            self.assertEqual(self.run_cli(argv + ["--strict"])[0], 1)

    def test_malformed_input_exits_non_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self.run_cli(
                ["--root", str(FIXTURES / "malformed-package-json"),
                 "--registry", str(APPROVING_REGISTRY),
                 "--output", str(Path(tmp) / "out.json")])
            self.assertEqual(code, 1)

    def test_committed_repository_evidence_is_current(self):
        code, _, err = self.run_cli(["--check"])
        self.assertEqual(code, 0, err or "regenerate evidence/discovery-result.json")


if __name__ == "__main__":
    unittest.main()
