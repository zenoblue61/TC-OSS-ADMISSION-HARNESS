#!/usr/bin/env python3
"""Fail-closed validator for TC OSS admission records; standard library only."""
import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "registry" / "oss-registry.json"
ALLOW = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0"}
STATUSES = {"PENDING", "APPROVED", "BLOCKED", "REVOKED"}

def err(errors, message): errors.append(message)
def date(value):
    try: return dt.date.fromisoformat(value)
    except (TypeError, ValueError): return None

def validate_record(record, errors, today):
    ident = record.get("admission_id", "<missing>")
    required = ("admission_id", "component", "source", "license", "intended_use", "status", "owner", "reviewed_at", "evidence_refs", "jarvis_ledger")
    for key in required:
        if not record.get(key): err(errors, f"{ident}: missing {key}")
    source = record.get("source", {})
    source_type, ref = source.get("type"), source.get("immutable_ref", "")
    if source_type == "git" and not re.fullmatch(r"[0-9a-f]{40}", ref): err(errors, f"{ident}: git immutable_ref must be a 40-char lowercase SHA")
    if source_type in {"npm", "pypi"} and (not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", ref) or ref.startswith(("^", "~"))): err(errors, f"{ident}: package immutable_ref must be an exact SemVer")
    if source_type not in {"git", "npm", "pypi"}: err(errors, f"{ident}: unsupported source type")
    if not str(source.get("source_url", "")).startswith("https://"): err(errors, f"{ident}: source_url must use https")
    if record.get("license") not in ALLOW and not record.get("exception_approval"): err(errors, f"{ident}: license requires an active exception")
    if record.get("status") not in STATUSES: err(errors, f"{ident}: invalid status")
    if record.get("status") != "APPROVED": err(errors, f"{ident}: non-approved admission is not permitted in registry")
    reviewed = date(record.get("reviewed_at"))
    if not reviewed: err(errors, f"{ident}: reviewed_at must be ISO date")
    elif (today - reviewed).days > 180: err(errors, f"{ident}: admission review expired")
    for ref_path in record.get("evidence_refs", []):
        if not (ROOT / ref_path).is_file(): err(errors, f"{ident}: evidence missing: {ref_path}")
    ledger = record.get("jarvis_ledger", {})
    expected = {"APPROVED": "ADMITTED"}.get(record.get("status"))
    if ledger.get("governance_status") != expected: err(errors, f"{ident}: Jarvis governance_status must be {expected}")
    exception = record.get("exception_approval")
    if exception and (not date(exception.get("expires_at")) or date(exception["expires_at"]) < today): err(errors, f"{ident}: exception is expired or invalid")

def main():
    errors = []
    try: data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: print(f"REGISTRY_INVALID: {exc}"); return 1
    records = data.get("records")
    if not isinstance(records, list) or not records: errors.append("registry: records must be a non-empty array")
    ids = set()
    for record in records or []:
        ident = record.get("admission_id")
        if ident in ids: errors.append(f"registry: duplicate admission_id {ident}")
        ids.add(ident); validate_record(record, errors, dt.date.today())
    result = {"validator": "tc-oss-admission-harness", "registry_version": data.get("registry_version"), "status": "PASS" if not errors else "FAIL", "error_count": len(errors), "errors": errors}
    (ROOT / "evidence" / "validation-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if not errors else 1
if __name__ == "__main__": sys.exit(main())
