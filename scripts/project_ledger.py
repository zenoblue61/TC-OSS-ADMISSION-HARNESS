#!/usr/bin/env python3
"""Project TC-OSS admission evidence into a TC-JARVIS ledger document.

The adapter reports results; it never grants an admission. It reads three
committed files, never writes them, and never invokes the validator or the
discovery scanner (so their write paths cannot be reached from here).

Contract: docs/JARVIS_LEDGER_ADAPTER.md
Schema:   schemas/jarvis-ledger-projection.schema.json
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

PROJECTION_VERSION = "1.0.0"
GENERATOR = "tc-jarvis-ledger-projection"

PASS, FAIL, ERROR = "PASS", "FAIL", "ERROR"
EXIT_CODES = {PASS: 0, FAIL: 1, ERROR: 2}

ADMITTED_MATCH = "ADMITTED_MATCH"
DISCOVERY_STATUSES = frozenset({ADMITTED_MATCH, "PENDING_ADMISSION", "UNPINNED_BLOCKED"})
ADMISSION_STATUSES = frozenset({"PENDING", "APPROVED", "BLOCKED", "REVOKED"})

INPUTS = (("validation", "evidence/validation-result.json"),
          ("discovery", "evidence/discovery-result.json"),
          ("registry", "registry/oss-registry.json"))

SHA1_RE = re.compile(r"[0-9a-f]{40}")
URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>)]+")
# Only a path that is not part of a URL: reject a slash preceded by ':' or a
# word character or another slash, which is what "https://host/a/b" looks like.
ABS_PATH_RE = re.compile(r"(?<![:\w/])/(?:[^\s'\"]+/)+([^\s'\",;)]+)")
TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{8,}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{8,}"
    r"|\bAKIA[0-9A-Z]{12,}")


# --------------------------------------------------------------------------
# Masking — decisions 1, 2, 3
# --------------------------------------------------------------------------
def _clean_url(value):
    """Drop userinfo, query and fragment; keep scheme, host, port and path."""
    parts = urllib.parse.urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return value
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    return urllib.parse.urlunsplit((parts.scheme.lower(), host + port, parts.path, "", ""))


def mask(value):
    """Strip credentials and environment detail from any text leaving the harness.

    URLs first, so userinfo is gone before anything else looks at the string;
    then absolute paths down to their basename; then bare credential tokens.
    """
    text = str(value)
    text = URL_RE.sub(lambda m: _clean_url(m.group(0)), text)
    text = ABS_PATH_RE.sub(r"<\1>", text)
    return TOKEN_RE.sub("[REDACTED]", text)


def _digest(obj):
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# project() — the only policy point, and pure
# --------------------------------------------------------------------------
def project(evidence, provenance):
    """Build a ledger projection. No I/O, no clock, no writes."""
    evidence = evidence if isinstance(evidence, dict) else {}
    validation = evidence.get("validation")
    discovery = evidence.get("discovery")
    registry = evidence.get("registry")

    errors, undetermined, inconsistent = [], [], []

    source_commit = str(provenance.get("source_commit", "") if isinstance(provenance, dict) else "")
    if not SHA1_RE.fullmatch(source_commit):
        undetermined.append("source_commit must be a 40-character commit SHA")

    # Aggregate statuses are forwarded verbatim; the adapter computes neither
    # per-record validity nor review expiry (decisions 3, 4, 5).
    registry_integrity = "UNKNOWN"
    if not isinstance(validation, dict):
        undetermined.append("validation-result is missing or unreadable")
    elif validation.get("status") in {PASS, FAIL}:
        registry_integrity = validation["status"]
        errors.extend(str(e) for e in validation.get("errors", []) if e)
    else:
        undetermined.append("validation-result has no usable status")

    scan_integrity = "UNKNOWN"
    if not isinstance(discovery, dict):
        undetermined.append("discovery-result is missing or unreadable")
    elif discovery.get("scan_status") in {"OK", "FAIL"}:
        scan_integrity = discovery["scan_status"]
        errors.extend(str(e) for e in discovery.get("errors", []) if e)
    else:
        undetermined.append("discovery-result has no usable scan_status")

    records = registry.get("records") if isinstance(registry, dict) else None
    if not isinstance(records, list):
        undetermined.append("registry is missing or unreadable")
        records = []

    admitted_sources, known_admission_ids = _admitted(records, inconsistent)
    review_queue = _queue(discovery, known_admission_ids, inconsistent)

    if undetermined:
        status = ERROR
    elif registry_integrity != PASS or scan_integrity != "OK" or inconsistent:
        status = FAIL
    else:
        status = PASS

    counts = {s: 0 for s in DISCOVERY_STATUSES}
    for entry in review_queue:
        counts[entry["discovery_status"]] += 1

    return {
        "projection_version": PROJECTION_VERSION,
        "generator": GENERATOR,
        "run_id": hashlib.sha256(
            (source_commit + _digest(validation) + _digest(discovery)).encode("utf-8")).hexdigest(),
        "source_commit": source_commit,
        "registry_version": registry.get("registry_version") if isinstance(registry, dict) else None,
        "adapter_status": status,
        "registry_integrity": registry_integrity,
        "scan_integrity": scan_integrity,
        "summary": {
            "admitted_sources": len(admitted_sources),
            "review_queue": len(review_queue),
            "admitted_match": counts[ADMITTED_MATCH],
            "pending_admission": counts["PENDING_ADMISSION"],
            "unpinned_blocked": counts["UNPINNED_BLOCKED"],
        },
        "admitted_sources": admitted_sources,
        "review_queue": review_queue,
        "errors": sorted(mask(e) for e in errors + undetermined + inconsistent),
    }


def _admitted(records, inconsistent):
    """Authoritative records, copied from the registry. Nothing is derived."""
    projected, known = [], set()
    for record in records:
        if not isinstance(record, dict):
            inconsistent.append("registry: record must be an object")
            continue
        source = record.get("source") if isinstance(record.get("source"), dict) else {}
        ledger = record.get("jarvis_ledger") if isinstance(record.get("jarvis_ledger"), dict) else {}
        admission_id = record.get("admission_id")
        ledger_id = ledger.get("ledger_id")
        if admission_id:
            known.add(admission_id)
        # ledger_id is copied verbatim. Deriving it from admission_id would
        # create a second source of truth that fails silently on rename.
        if not ledger_id:
            inconsistent.append(f"registry: {admission_id or '<unknown>'} has no jarvis_ledger.ledger_id")
            continue
        if record.get("status") not in ADMISSION_STATUSES:
            inconsistent.append(f"registry: {admission_id} has an unusable status")
            continue
        projected.append({
            "id": ledger_id,
            "source_record_id": admission_id,
            "component": mask(record.get("component", "")),
            "source_url": mask(source.get("source_url", "")),
            "pinned_ref": str(source.get("immutable_ref", "")),
            "license_expression": str(record.get("license", "")),
            "admission_status": record["status"],
            "evidence_refs": list(record.get("evidence_refs", [])),
        })
    return sorted(projected, key=lambda item: item["id"]), known


def _queue(discovery, known_admission_ids, inconsistent):
    """Non-authoritative observations. No id and no admission_status here."""
    candidates = discovery.get("candidates") if isinstance(discovery, dict) else None
    if not isinstance(candidates, list):
        return []
    queue = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            inconsistent.append("discovery: candidate must be an object")
            continue
        observed = candidate.get("status")
        if observed not in DISCOVERY_STATUSES:
            inconsistent.append("discovery: candidate has an unusable status")
            continue
        matched = candidate.get("matched_admission_id")
        # Only ADMITTED_MATCH may carry a record reference, and the record has
        # to exist. A dangling reference is a governance inconsistency, not a
        # reason to invent one.
        if observed == ADMITTED_MATCH and matched not in known_admission_ids:
            inconsistent.append(
                f"discovery: {candidate.get('candidate_id')} references unknown admission {matched}")
            matched = None
        elif observed != ADMITTED_MATCH:
            matched = None
        pinned = candidate.get("immutable_ref")
        queue.append({
            "candidate_id": mask(candidate.get("candidate_id", "")),
            "discovery_status": observed,
            "component": mask(candidate.get("component", "")),
            "source_url": mask(candidate.get("source_url", "")),
            "pinned_ref": mask(pinned) if pinned is not None else None,
            "source_record_id": matched,
            "declared_in": sorted({str(o.get("file", "")) for o in candidate.get("occurrences", [])
                                   if isinstance(o, dict) and o.get("file")}),
        })
    return sorted(queue, key=lambda item: item["candidate_id"])


def render(projection):
    return json.dumps(projection, indent=2) + "\n"


# --------------------------------------------------------------------------
# I/O boundary — swapped out wholesale by a future remote adapter
# --------------------------------------------------------------------------
def collect(root):
    """Read the three inputs. Read-only: nothing here opens a file for writing."""
    root = Path(root)
    evidence = {}
    for key, rel in INPUTS:
        try:
            evidence[key] = json.loads((root / rel).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            evidence[key] = None
    return evidence


def _head_commit(root):
    try:
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def main(argv=None):
    parser = argparse.ArgumentParser(description="Project admission evidence into the TC-JARVIS ledger.")
    parser.add_argument("--root", default=None, help="repository to read (default: this repository)")
    parser.add_argument("--output", default=None, help="projection path (default: stdout only)")
    parser.add_argument("--source-commit", default=None, help="provenance commit (default: git HEAD)")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]
    projection = project(collect(root),
                         {"source_commit": args.source_commit or _head_commit(root)})
    rendered = render(projection)

    # All-or-nothing: an ERROR run could not determine what is true, so it
    # publishes nothing. A FAIL run is a complete, determined result and is
    # published so the ledger records the failure.
    if projection["adapter_status"] == ERROR:
        for error in projection["errors"]:
            print(f"LEDGER_PROJECTION_ERROR: {error}", file=sys.stderr)
        return EXIT_CODES[ERROR]

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return EXIT_CODES[projection["adapter_status"]]


if __name__ == "__main__":
    sys.exit(main())
