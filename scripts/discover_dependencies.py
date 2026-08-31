#!/usr/bin/env python3
"""Read-only OSS dependency discovery for the TC admission harness.

Scans a target tree for externally sourced dependencies (npm, PyPI, GitHub
Actions, git and vendored sources), compares every candidate against the
approved admission registry, and emits deterministic PENDING candidate
evidence.

Guarantees enforced by this module:
  * no network access and no dependency installation
  * manifests, lockfiles and the registry are opened read-only
  * ``APPROVED`` is never produced; only the registry can admit a source
  * output is sorted, timestamp-free and independent of filesystem order
"""
import argparse
import json
import os
import re
import sys
import tomllib
import urllib.parse
from pathlib import Path

DISCOVERY_VERSION = "1.0.0"
GENERATOR = "tc-oss-dependency-discovery"

ADMITTED_MATCH = "ADMITTED_MATCH"
PENDING_ADMISSION = "PENDING_ADMISSION"
UNPINNED_BLOCKED = "UNPINNED_BLOCKED"

# Ref kinds that identify one immutable artifact. Everything else floats and is
# blocked before it is ever compared against the registry.
IMMUTABLE_KINDS = frozenset({"commit_sha", "exact_version", "digest"})

UNPINNED_PHRASES = {
    "version_range": "a version range",
    "tag": "a tag",
    "branch": "a branch",
    "latest": "a floating dist-tag",
    "unspecified": "unconstrained",
}

DEFAULT_EXCLUDE_DIRS = frozenset({
    ".git", ".hg", ".svn", ".tox", ".venv", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "__pycache__", "node_modules", "venv", "dist", "build",
    "site-packages", ".gradle", "target",
})
# Fixture trees are declarative test input, never a real supply-chain surface.
DEFAULT_EXCLUDE_PREFIXES = ("tests/fixtures",)

SHA1_RE = re.compile(r"[0-9a-fA-F]{40}")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
EXACT_SEMVER_RE = re.compile(r"[v=]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
SCP_URL_RE = re.compile(r"(?:ssh://)?(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):(?!//)(.+)")
USES_RE = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*(?P<value>\S.*?)\s*$")
ACTION_REF_RE = re.compile(r"^(?P<path>[^@\s]+)@(?P<ref>\S+)$")

BRANCH_NAMES = frozenset({"main", "master", "develop", "trunk", "head", "default"})
LOCAL_NPM_PROTOCOLS = ("file:", "link:", "portal:", "workspace:")
SHORTHAND_HOSTS = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}


# --------------------------------------------------------------------------
# URL and ref canonicalisation
# --------------------------------------------------------------------------
def normalize_source_url(url):
    """Reduce any supported source locator to a canonical ``https://host/path``.

    Returns ``None`` when the value is not a remote locator (local paths).
    """
    text = str(url).strip()
    if not text:
        return None
    if text.startswith("git+"):
        text = text[4:]

    shorthand = text.split(":", 1)
    if len(shorthand) == 2 and shorthand[0] in SHORTHAND_HOSTS and not shorthand[1].startswith("//"):
        text = f"https://{SHORTHAND_HOSTS[shorthand[0]]}/{shorthand[1].lstrip('/')}"
    elif "://" not in text:
        scp = SCP_URL_RE.fullmatch(text)
        # Only ``user@host:path`` is an scp-style git URL. A bare ``scheme:path``
        # such as ``file:../local`` must not be mistaken for one.
        if scp and "." in scp.group(1) and not scp.group(2).startswith((".", "/")):
            text = f"https://{scp.group(1)}/{scp.group(2)}"

    parts = urllib.parse.urlsplit(text)
    if not parts.scheme or not parts.netloc:
        return None
    if parts.scheme.lower() in {"file"}:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    path = parts.path
    if path.endswith(".git"):
        path = path[:-4]
    path = "/" + path.strip("/")
    return f"https://{host}{path}" if path != "/" else f"https://{host}"


def canonical_ref(ref):
    """Normalise a ref so both sides of a registry comparison agree.

    Commit SHAs and digests fold to lowercase; version strings drop a leading
    ``v`` or ``=`` so ``v1.2.3``, ``=1.2.3`` and ``1.2.3`` are one identity.
    """
    text = str(ref).strip()
    if SHA1_RE.fullmatch(text) or SHA256_RE.fullmatch(text):
        return text.lower()
    if ":" in text and text.split(":", 1)[0].lower() in {"sha256", "sha512", "sha1", "md5"}:
        return text.lower()
    return re.sub(r"^[v=]+", "", text)


def classify_git_ref(ref):
    """Classify a git ref without network access. Only a SHA is immutable."""
    text = str(ref).strip()
    if not text:
        return "unspecified"
    if SHA1_RE.fullmatch(text) or SHA256_RE.fullmatch(text):
        return "commit_sha"
    if text.lower() in {"latest", "*"}:
        return "latest"
    if text.startswith("semver:") or text.startswith("refs/tags/"):
        return "tag"
    if text.startswith("refs/heads/") or text.lower() in BRANCH_NAMES:
        return "branch"
    return "tag"


def split_git_locator(value):
    """Split a git locator into ``(url, ref)`` for both npm and pip spellings.

    npm pins with a ``#fragment``; pip pins with ``@ref`` before the fragment.
    """
    text = str(value).strip()
    if text.startswith("git+"):
        text = text[4:]
    ref = ""
    if "#" in text:
        text, fragment = text.split("#", 1)
        fragment = fragment.strip()
        if fragment.startswith("egg="):
            fragment = ""
        elif "=" in fragment and not fragment.startswith("semver:"):
            fragment = ""
        ref = fragment
    if not ref:
        scheme, _, remainder = text.partition("://")
        target = remainder if remainder else text
        # Ignore userinfo (``user@host``) when looking for a pip-style ``@ref``.
        host, slash, tail = target.partition("/")
        if slash and "@" in tail:
            tail, _, ref = tail.rpartition("@")
            target = f"{host}/{tail}"
            text = f"{scheme}://{target}" if remainder else target
    return text, ref


# --------------------------------------------------------------------------
# Ecosystem-specific specifier classification
# --------------------------------------------------------------------------
def classify_npm_spec(spec):
    """Map an npm version specifier to ``(ecosystem, ref_kind, url, ref)``.

    ``url`` is ``None`` for registry packages; the caller supplies the
    canonical registry URL from the package name.
    """
    text = str(spec).strip()
    if not text or text in {"*", "x", "X"}:
        return "npm", "unspecified", None, text or "*"
    lowered = text.lower()
    if lowered.startswith(LOCAL_NPM_PROTOCOLS):
        return None, None, None, None  # local, not an external source
    if lowered.startswith("npm:"):
        alias = text[4:]
        name, _, version = alias.rpartition("@")
        if not name:  # bare alias with no version
            return "npm", "unspecified", None, "*"
        return _npm_alias(name, version)
    if lowered in {"latest", "next", "beta", "alpha", "canary"}:
        return "npm", "latest", None, text

    if (lowered.startswith(("git+", "git://", "git@", "ssh://"))
            or lowered.split(":", 1)[0] in SHORTHAND_HOSTS
            or (lowered.startswith(("http://", "https://")) and (".git" in lowered or "#" in lowered))):
        url, ref = split_git_locator(text)
        normalized = normalize_source_url(url)
        if normalized is None:
            return None, None, None, None
        return "git", classify_git_ref(ref), normalized, ref or "*"
    if not text.startswith((".", "/")) and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+(?:#\S+)?", text):
        url, ref = split_git_locator(f"github:{text}")
        normalized = normalize_source_url(url)
        if normalized is not None:
            return "git", classify_git_ref(ref), normalized, ref or "*"
    if lowered.startswith(("http://", "https://")):
        # A remote tarball dependency: external, and never immutable on its own.
        normalized = normalize_source_url(text)
        if normalized is not None:
            return "url", "unspecified", normalized, text

    if EXACT_SEMVER_RE.fullmatch(text):
        return "npm", "exact_version", None, text
    return "npm", "version_range", None, text


def _npm_alias(name, version):
    ecosystem, kind, url, ref = classify_npm_spec(version)
    if ecosystem is None:
        return None, None, None, None
    return ecosystem, kind, url or npm_registry_url(name), ref


def npm_registry_url(name):
    return f"https://registry.npmjs.org/{name}"


def pypi_project_url(name):
    # PEP 503 normalisation keeps one identity per distribution.
    return f"https://pypi.org/project/{re.sub(r'[-_.]+', '-', name).lower()}"


def classify_python_requirement(line):
    """Parse one PEP 508 requirement into a discovery finding tuple.

    Returns ``(ecosystem, component, url, ref_kind, declared_ref)`` or ``None``
    when the line carries no external source.
    """
    text = line.strip()
    if not text:
        return None
    text = text.split(";", 1)[0].strip()  # drop environment markers
    if not text:
        return None

    if text.lower().startswith(("git+", "http://", "https://", "ssh://")):
        return _python_direct_url(None, text)

    name_part, sep, url_part = text.partition("@")
    if sep and url_part.strip().lower().startswith(("git+", "http://", "https://", "ssh://", "file:")):
        return _python_direct_url(name_part.strip(), url_part.strip())

    match = re.match(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*)$", text)
    if not match:
        return None
    name = match.group("name")
    spec = match.group("spec").strip()
    if not spec:
        return "pypi", name, pypi_project_url(name), "unspecified", "*"
    equality = re.fullmatch(r"={2,3}\s*(?P<version>[^,\s]+)", spec)
    if equality:
        version = equality.group("version")
        if "*" not in version:
            return "pypi", name, pypi_project_url(name), "exact_version", version
    return "pypi", name, pypi_project_url(name), "version_range", spec


def _python_direct_url(name, locator):
    """Classify a PEP 508 direct reference (``name @ url``) or a bare URL."""
    lowered = locator.lower()
    if lowered.startswith("file:"):
        return None
    fragment = locator.partition("#")[2]
    url, ref = split_git_locator(locator)
    normalized = normalize_source_url(url)
    if normalized is None:
        return None
    if not name:
        egg = re.search(r"egg=([A-Za-z0-9._-]+)", fragment)
        name = egg.group(1) if egg else normalized.rstrip("/").rpartition("/")[2]

    is_git = lowered.startswith(("git+", "git://")) or ".git" in url.lower()
    if is_git:
        return "git", name, normalized, classify_git_ref(ref) if ref else "unspecified", ref or "*"
    # A plain archive URL is immutable only when it carries a content digest.
    digest = re.search(r"(sha(?:256|512))=([0-9a-fA-F]+)", fragment)
    if digest:
        return "url", name, normalized, "digest", f"{digest.group(1).lower()}:{digest.group(2).lower()}"
    return "url", name, normalized, "unspecified", ref or "*"


def classify_poetry_constraint(value):
    """Poetry accepts caret/tilde ranges; only a bare exact version pins."""
    text = str(value).strip()
    if not text or text == "*":
        return "unspecified", text or "*"
    equality = re.fullmatch(r"={1,3}\s*(?P<version>\S+)", text)
    if equality and "*" not in equality.group("version"):
        return "exact_version", equality.group("version")
    # A bare Poetry constraint pins only when it names a complete version.
    # Anything shorter (``"2"``, ``"2.1"``) is a range, so it fails closed.
    if EXACT_SEMVER_RE.fullmatch(text):
        return "exact_version", text
    return "version_range", text


def classify_action_ref(ref):
    """A GitHub Action is immutable only when pinned to a full commit SHA."""
    text = str(ref).strip()
    if SHA1_RE.fullmatch(text) or SHA256_RE.fullmatch(text):
        return "commit_sha"
    if text.lower() in {"latest", "*"}:
        return "latest"
    if text.lower() in BRANCH_NAMES or text.startswith("refs/heads/"):
        return "branch"
    return "tag"


# --------------------------------------------------------------------------
# Scan state
# --------------------------------------------------------------------------
class Scan:
    """Accumulates findings and fail-closed errors for one discovery run."""

    def __init__(self):
        self.findings = []
        self.errors = []
        self.files = set()

    def error(self, message):
        self.errors.append(message)

    def seen_file(self, rel):
        self.files.add(rel)

    def add(self, *, ecosystem, component, source_url, declared_ref, ref_kind,
            rel, locator, integrity=None):
        if ecosystem is None or not source_url or not component:
            return
        self.findings.append({
            "ecosystem": ecosystem,
            "component": str(component),
            "source_url": source_url,
            "declared_ref": str(declared_ref),
            "ref_kind": ref_kind,
            "file": rel,
            "locator": locator,
            "integrity": integrity,
        })


def read_text(path, rel, scan):
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        scan.error(f"{rel}: unreadable ({exc.__class__.__name__})")
        return None


def read_json(path, rel, scan):
    text = read_text(path, rel, scan)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        scan.error(f"{rel}: malformed JSON ({exc.msg} at line {exc.lineno})")
        return None


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------
NPM_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def scan_package_json(path, rel, scan):
    data = read_json(path, rel, scan)
    if data is None:
        return
    if not isinstance(data, dict):
        scan.error(f"{rel}: package.json must be a JSON object")
        return
    for field in NPM_DEP_FIELDS:
        block = data.get(field)
        if block is None:
            continue
        if not isinstance(block, dict):
            scan.error(f"{rel}: {field} must be a JSON object")
            continue
        for name in sorted(block):
            spec = block[name]
            if not isinstance(spec, str):
                scan.error(f"{rel}: {field}.{name} must be a string specifier")
                continue
            ecosystem, kind, url, ref = classify_npm_spec(spec)
            if ecosystem is None:
                continue
            scan.add(ecosystem=ecosystem, component=name,
                     source_url=url or npm_registry_url(name),
                     declared_ref=ref, ref_kind=kind, rel=rel,
                     locator=f"{field}.{name}")


def scan_package_lock(path, rel, scan):
    data = read_json(path, rel, scan)
    if data is None:
        return
    if not isinstance(data, dict):
        scan.error(f"{rel}: package-lock.json must be a JSON object")
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key in sorted(packages):
            entry = packages[key]
            if not key or not isinstance(entry, dict) or entry.get("link"):
                continue
            name = entry.get("name") or key.rpartition("node_modules/")[2]
            if not name:
                continue
            _lock_entry(name, entry, rel, f"packages[{key}]", scan)
    legacy = data.get("dependencies")
    if isinstance(legacy, dict):
        _scan_lock_v1(legacy, rel, "dependencies", scan)
    if not isinstance(packages, dict) and not isinstance(legacy, dict):
        scan.error(f"{rel}: lockfile has neither a packages nor a dependencies map")


def _scan_lock_v1(block, rel, locator, scan):
    for name in sorted(block):
        entry = block[name]
        if not isinstance(entry, dict):
            continue
        _lock_entry(name, entry, rel, f"{locator}.{name}", scan)
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _scan_lock_v1(nested, rel, f"{locator}.{name}.dependencies", scan)


def _lock_entry(name, entry, rel, locator, scan):
    version = entry.get("version")
    resolved = entry.get("resolved")
    integrity = entry.get("integrity") if isinstance(entry.get("integrity"), str) else None
    candidate = resolved if isinstance(resolved, str) else None
    if isinstance(version, str) and (version.startswith(("git+", "git:")) or "://" in version):
        candidate = version
    if candidate and (candidate.startswith(("git+", "git:")) or ".git" in candidate):
        url, ref = split_git_locator(candidate)
        normalized = normalize_source_url(url)
        if normalized:
            scan.add(ecosystem="git", component=name, source_url=normalized,
                     declared_ref=ref or "*", ref_kind=classify_git_ref(ref),
                     rel=rel, locator=locator, integrity=integrity)
        return
    if not isinstance(version, str) or not version:
        return
    kind = "exact_version" if EXACT_SEMVER_RE.fullmatch(version) else "version_range"
    scan.add(ecosystem="npm", component=name, source_url=npm_registry_url(name),
             declared_ref=version, ref_kind=kind, rel=rel, locator=locator,
             integrity=integrity)


def scan_requirements(path, rel, scan, root, visited=None):
    visited = visited if visited is not None else set()
    resolved = path.resolve()
    if resolved in visited:
        scan.error(f"{rel}: recursive requirement include detected")
        return
    visited.add(resolved)
    text = read_text(path, rel, scan)
    if text is None:
        return
    scan.seen_file(rel)

    joined = []
    buffer = ""
    for raw_line in text.splitlines():
        stripped = raw_line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1]
            continue
        joined.append(buffer + stripped)
        buffer = ""
    if buffer:
        joined.append(buffer)

    for number, raw_line in enumerate(joined, start=1):
        line = re.split(r"(?:^|\s)#", raw_line, maxsplit=1)[0].strip()
        if not line:
            continue
        include = re.match(r"^(?:-r|--requirement)[=\s]+(?P<target>\S+)$", line)
        if include:
            target = (path.parent / include.group("target")).resolve()
            try:
                target_rel = target.relative_to(root).as_posix()
            except ValueError:
                scan.error(f"{rel}:{number}: requirement include escapes the scan root")
                continue
            if not target.is_file():
                scan.error(f"{rel}:{number}: included requirements file is missing: {include.group('target')}")
                continue
            scan_requirements(target, target_rel, scan, root, visited)
            continue
        if line.startswith("-e ") or line.startswith("--editable"):
            line = re.sub(r"^(?:-e|--editable)[=\s]+", "", line).strip()
        elif line.startswith("-"):
            continue  # index URLs, --hash continuations and other pip options
        line = re.sub(r"\s--hash[=\s]\S+", "", line).strip()
        parsed = classify_python_requirement(line)
        if parsed is None:
            continue
        ecosystem, component, url, kind, ref = parsed
        scan.add(ecosystem=ecosystem, component=component, source_url=url,
                 declared_ref=ref, ref_kind=kind, rel=rel, locator=f"line {number}")


def scan_pyproject(path, rel, scan):
    text = read_text(path, rel, scan)
    if text is None:
        return
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        scan.error(f"{rel}: malformed TOML ({exc})")
        return

    def emit(requirement, locator):
        parsed = classify_python_requirement(requirement)
        if parsed is None:
            return
        ecosystem, component, url, kind, ref = parsed
        scan.add(ecosystem=ecosystem, component=component, source_url=url,
                 declared_ref=ref, ref_kind=kind, rel=rel, locator=locator)

    def emit_list(values, locator):
        if not isinstance(values, list):
            scan.error(f"{rel}: {locator} must be an array of requirement strings")
            return
        for item in values:
            if isinstance(item, str):
                emit(item, locator)
            elif not isinstance(item, dict):  # PEP 735 include-group tables are fine
                scan.error(f"{rel}: {locator} contains a non-string requirement")

    project = data.get("project")
    if isinstance(project, dict):
        if "dependencies" in project:
            emit_list(project.get("dependencies"), "project.dependencies")
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for extra in sorted(optional):
                emit_list(optional[extra], f"project.optional-dependencies.{extra}")

    build_system = data.get("build-system")
    if isinstance(build_system, dict) and "requires" in build_system:
        emit_list(build_system.get("requires"), "build-system.requires")

    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group in sorted(groups):
            emit_list(groups[group], f"dependency-groups.{group}")

    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        blocks = []
        if isinstance(poetry.get("dependencies"), dict):
            blocks.append(("tool.poetry.dependencies", poetry["dependencies"]))
        if isinstance(poetry.get("dev-dependencies"), dict):
            blocks.append(("tool.poetry.dev-dependencies", poetry["dev-dependencies"]))
        group_block = poetry.get("group")
        if isinstance(group_block, dict):
            for group in sorted(group_block):
                deps = group_block[group].get("dependencies") if isinstance(group_block[group], dict) else None
                if isinstance(deps, dict):
                    blocks.append((f"tool.poetry.group.{group}.dependencies", deps))
        for locator, block in blocks:
            for name in sorted(block):
                if name.lower() == "python":
                    continue
                _poetry_dependency(name, block[name], rel, f"{locator}.{name}", scan)


def _poetry_dependency(name, value, rel, locator, scan):
    if isinstance(value, list):  # multiple constraints for different markers
        for index, item in enumerate(value):
            _poetry_dependency(name, item, rel, f"{locator}[{index}]", scan)
        return
    if isinstance(value, str):
        kind, ref = classify_poetry_constraint(value)
        scan.add(ecosystem="pypi", component=name, source_url=pypi_project_url(name),
                 declared_ref=ref, ref_kind=kind, rel=rel, locator=locator)
        return
    if not isinstance(value, dict):
        scan.error(f"{rel}: {locator} must be a string or table")
        return
    if "path" in value:
        return  # local source, not externally admitted
    git_url = value.get("git") or value.get("url")
    if isinstance(git_url, str):
        normalized = normalize_source_url(git_url)
        if normalized is None:
            return
        ref = value.get("rev") or value.get("tag") or value.get("branch") or ""
        kind = classify_git_ref(ref) if ref else "unspecified"
        if "tag" in value and not value.get("rev"):
            kind = "tag"
        if "branch" in value and not value.get("rev") and not value.get("tag"):
            kind = "branch"
        scan.add(ecosystem="git", component=name, source_url=normalized,
                 declared_ref=str(ref) if ref else "*", ref_kind=kind,
                 rel=rel, locator=locator)
        return
    version = value.get("version")
    if isinstance(version, str):
        kind, ref = classify_poetry_constraint(version)
        scan.add(ecosystem="pypi", component=name, source_url=pypi_project_url(name),
                 declared_ref=ref, ref_kind=kind, rel=rel, locator=locator)


def _yaml_scalar(text):
    """Extract a YAML scalar value, honouring quotes and inline comments."""
    value = text.strip()
    if value[:1] in {"'", '"'}:
        quote = value[0]
        end = value.find(quote, 1)
        return value[1:end] if end != -1 else None
    return re.split(r"\s#", value, maxsplit=1)[0].strip()


def scan_workflow(path, rel, scan):
    text = read_text(path, rel, scan)
    if text is None:
        return
    for number, raw_line in enumerate(text.splitlines(), start=1):
        match = USES_RE.match(raw_line)
        if not match:
            continue
        value = _yaml_scalar(match.group("value"))
        if not value:
            scan.error(f"{rel}:{number}: unparseable uses: value")
            continue
        locator = f"line {number}"
        if value.startswith((".", "/")):
            continue  # local action inside this repository
        if value.lower().startswith("docker://"):
            image = value[len("docker://"):]
            if "@" in image:
                name, _, digest = image.rpartition("@")
                kind = "digest" if digest.lower().startswith("sha256:") else "tag"
            elif ":" in image.rpartition("/")[2]:
                name, _, tag = image.rpartition(":")
                digest = tag
                kind = "latest" if tag == "latest" else "tag"
            else:
                name, digest, kind = image, "*", "unspecified"
            scan.add(ecosystem="docker", component=name,
                     source_url=f"docker://{name}", declared_ref=digest,
                     ref_kind=kind, rel=rel, locator=locator)
            continue
        ref_match = ACTION_REF_RE.match(value)
        if not ref_match:
            scan.add(ecosystem="github-action", component=value,
                     source_url=_action_url(value), declared_ref="*",
                     ref_kind="unspecified", rel=rel, locator=locator)
            continue
        action_path = ref_match.group("path")
        ref = ref_match.group("ref")
        scan.add(ecosystem="github-action", component=action_path,
                 source_url=_action_url(action_path), declared_ref=ref,
                 ref_kind=classify_action_ref(ref), rel=rel, locator=locator)


def _action_url(action_path):
    segments = [part for part in action_path.split("/") if part]
    owner_repo = "/".join(segments[:2]) if len(segments) >= 2 else action_path
    return f"https://github.com/{owner_repo}"


def scan_vendored(path, rel, scan):
    data = read_json(path, rel, scan)
    if data is None:
        return
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        scan.error(f"{rel}: vendored manifest must be an object with a sources array")
        return
    for index, entry in enumerate(data["sources"]):
        locator = f"sources[{index}]"
        if not isinstance(entry, dict):
            scan.error(f"{rel}: {locator} must be an object")
            continue
        source_url = entry.get("source_url")
        if not isinstance(source_url, str) or not source_url:
            scan.error(f"{rel}: {locator} is missing source_url")
            continue
        normalized = normalize_source_url(source_url)
        if normalized is None:
            scan.error(f"{rel}: {locator} has an unusable source_url")
            continue
        ref = entry.get("immutable_ref") or entry.get("ref") or ""
        if not isinstance(ref, str):
            scan.error(f"{rel}: {locator} has a non-string ref")
            continue
        component = entry.get("component") or entry.get("path") or normalized.rpartition("/")[2]
        scan.add(ecosystem="git", component=component, source_url=normalized,
                 declared_ref=ref or "*",
                 ref_kind=classify_git_ref(ref) if ref else "unspecified",
                 rel=rel, locator=locator)


# --------------------------------------------------------------------------
# Walking the target tree
# --------------------------------------------------------------------------
def is_excluded(rel, exclude_prefixes):
    parts = rel.split("/")
    if any(part in DEFAULT_EXCLUDE_DIRS for part in parts[:-1]):
        return True
    return any(rel == prefix or rel.startswith(prefix.rstrip("/") + "/") for prefix in exclude_prefixes)


def collect_targets(root, exclude_prefixes):
    """Return the sorted set of manifests to scan; order never affects output."""
    targets = []
    for dirpath, dirnames, filenames in os.walk(root):
        parent = Path(dirpath).relative_to(root).as_posix()
        parent = "" if parent == "." else parent
        # Prune excluded trees instead of descending into them.
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in DEFAULT_EXCLUDE_DIRS
            and not is_excluded(f"{parent}/{name}".lstrip("/") + "/x", exclude_prefixes))
        for name in sorted(filenames):
            rel = f"{parent}/{name}".lstrip("/")
            path = Path(dirpath) / name
            if is_excluded(rel, exclude_prefixes) or not path.is_file():
                continue
            if name == "package.json":
                targets.append((rel, path, scan_package_json))
            elif name == "package-lock.json":
                targets.append((rel, path, scan_package_lock))
            elif name.startswith("requirements") and name.endswith(".txt"):
                targets.append((rel, path, scan_requirements))
            elif name == "pyproject.toml":
                targets.append((rel, path, scan_pyproject))
            elif name in {"action.yml", "action.yaml"} or (
                    parent.endswith(".github/workflows") and name.endswith((".yml", ".yaml"))):
                targets.append((rel, path, scan_workflow))
            elif name == "vendored-sources.json":
                targets.append((rel, path, scan_vendored))
    return sorted(targets, key=lambda item: item[0])


# --------------------------------------------------------------------------
# Registry comparison
# --------------------------------------------------------------------------
class Registry:
    """Read-only view of the admission registry used for candidate matching."""

    def __init__(self):
        self.approved = {}      # (url, ref) -> admission_id
        self.unapproved = {}    # (url, ref) -> status
        self.urls = set()
        self.version = None
        self.usable = False


def load_registry(registry_path, scan):
    """Load approved admissions. A missing or broken registry fails closed."""
    registry = Registry()
    if not registry_path.is_file():
        scan.error(f"registry: {registry_path.name} is missing")
        return registry
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        scan.error(f"registry: unreadable or malformed ({exc})")
        return registry
    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
        scan.error("registry: records must be an array")
        return registry
    registry.version = data.get("registry_version")
    registry.usable = True
    for record in data["records"]:
        if not isinstance(record, dict):
            scan.error("registry: record must be an object")
            continue
        source = record.get("source")
        if not isinstance(source, dict):
            continue
        normalized = normalize_source_url(source.get("source_url", ""))
        if normalized is None:
            continue
        key = (normalized.lower(), canonical_ref(source.get("immutable_ref", "")))
        registry.urls.add(key[0])
        if record.get("status") == "APPROVED":
            registry.approved[key] = record.get("admission_id")
        else:
            # PENDING / BLOCKED / REVOKED never admit a source.
            registry.unapproved[key] = record.get("status")
    return registry


def build_candidates(scan, registry):
    """Group findings into deterministic candidates and classify each one."""
    grouped = {}
    for finding in scan.findings:
        key = (finding["ecosystem"], finding["component"],
               finding["source_url"], finding["declared_ref"])
        bucket = grouped.setdefault(key, {"kinds": set(), "occurrences": []})
        bucket["kinds"].add(finding["ref_kind"])
        occurrence = {"file": finding["file"], "locator": finding["locator"]}
        if finding["integrity"]:
            occurrence["integrity"] = finding["integrity"]
        if occurrence not in bucket["occurrences"]:
            bucket["occurrences"].append(occurrence)

    candidates = []
    for key in sorted(grouped):
        ecosystem, component, source_url, declared_ref = key
        bucket = grouped[key]
        ref_kind = sorted(bucket["kinds"])[0]
        pinned = ref_kind in IMMUTABLE_KINDS
        immutable_ref = canonical_ref(declared_ref) if pinned else None

        if not pinned:
            status = UNPINNED_BLOCKED
            phrase = UNPINNED_PHRASES.get(ref_kind, f"a {ref_kind.replace('_', ' ')}")
            reason = f"declared ref '{declared_ref}' is {phrase}; an immutable ref is required"
            admission_id = None
        else:
            lookup = (source_url.lower(), immutable_ref)
            admission_id = registry.approved.get(lookup)
            if admission_id:
                status = ADMITTED_MATCH
                reason = "source_url and immutable_ref match an APPROVED registry record"
            else:
                status = PENDING_ADMISSION
                admission_id = None
                if not registry.usable:
                    reason = "registry could not be read; no admission can be confirmed"
                elif lookup in registry.unapproved:
                    reason = (f"registry record exists but its status is "
                              f"{registry.unapproved[lookup]}, not APPROVED")
                elif lookup[0] in registry.urls:
                    reason = "source_url is registered but this immutable_ref is not approved"
                else:
                    reason = "source_url has no APPROVED registry record"

        candidates.append({
            "candidate_id": f"{ecosystem}:{component}@{declared_ref}",
            "ecosystem": ecosystem,
            "component": component,
            "source_url": source_url,
            "declared_ref": declared_ref,
            "ref_kind": ref_kind,
            "pinned": pinned,
            "immutable_ref": immutable_ref,
            "status": status,
            "matched_admission_id": admission_id,
            "reason": reason,
            "occurrences": sorted(bucket["occurrences"],
                                  key=lambda item: (item["file"], item["locator"])),
        })
    return candidates


def build_result(root, exclude_prefixes, registry_path):
    """Scan ``root`` and classify every candidate. Extra excludes are additive:
    the built-in defaults always apply, however this is invoked."""
    exclude_prefixes = tuple(DEFAULT_EXCLUDE_PREFIXES) + tuple(exclude_prefixes)
    scan = Scan()
    for rel, path, scanner in collect_targets(root, exclude_prefixes):
        scan.seen_file(rel)
        if scanner is scan_requirements:
            scanner(path, rel, scan, root)
        else:
            scanner(path, rel, scan)

    registry = load_registry(registry_path, scan)
    candidates = build_candidates(scan, registry)
    counts = {ADMITTED_MATCH: 0, PENDING_ADMISSION: 0, UNPINNED_BLOCKED: 0}
    for candidate in candidates:
        counts[candidate["status"]] += 1

    return {
        "discovery_version": DISCOVERY_VERSION,
        "generator": GENERATOR,
        "registry_version": registry.version,
        "scan_status": "OK" if not scan.errors else "FAIL",
        "summary": {
            "files_scanned": len(scan.files),
            "candidates": len(candidates),
            "admitted_match": counts[ADMITTED_MATCH],
            "pending_admission": counts[PENDING_ADMISSION],
            "unpinned_blocked": counts[UNPINNED_BLOCKED],
        },
        "errors": sorted(scan.errors),
        "scanned_files": sorted(scan.files),
        "candidates": candidates,
    }


def render(result):
    return json.dumps(result, indent=2) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Discover external OSS dependency candidates (read-only).")
    parser.add_argument("--root", default=None, help="tree to scan (default: repository root)")
    parser.add_argument("--registry", default=None, help="admission registry path")
    parser.add_argument("--output", default=None, help="evidence output path")
    parser.add_argument("--exclude", action="append", default=[], help="additional excluded path prefix")
    parser.add_argument("--check", action="store_true", help="compare against the committed evidence without writing")
    parser.add_argument("--strict", action="store_true", help="exit non-zero when any candidate is not ADMITTED_MATCH")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    root = Path(args.root).resolve() if args.root else repo_root
    if not root.is_dir():
        print(f"SCAN_ROOT_INVALID: {args.root}", file=sys.stderr)
        return 1
    registry_path = Path(args.registry).resolve() if args.registry else repo_root / "registry" / "oss-registry.json"
    output_path = Path(args.output).resolve() if args.output else repo_root / "evidence" / "discovery-result.json"

    result = build_result(root, tuple(args.exclude), registry_path)
    rendered = render(result)

    if args.check:
        try:
            committed = output_path.read_text(encoding="utf-8")
        except OSError:
            print(f"DISCOVERY_EVIDENCE_MISSING: {output_path.name}", file=sys.stderr)
            return 1
        if committed != rendered:
            print("DISCOVERY_EVIDENCE_STALE: regenerate evidence/discovery-result.json", file=sys.stderr)
            return 1
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")

    print(rendered, end="")
    if result["scan_status"] != "OK":
        return 1
    if args.strict and (result["summary"]["pending_admission"] or result["summary"]["unpinned_blocked"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
