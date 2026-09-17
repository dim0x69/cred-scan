"""One-shot migration from credentials document schema 2 to schema 3.

This module is intentionally not imported by the runtime. Stop the scanner
before running it against an existing results directory. Every document and
canonical report is checked before any writes; valid schema-3 documents are
skipped so an interrupted write pass can be resumed. This legacy operation does
not upgrade inventories, target IDs, or the newer boundary/scope field names.
Its in-memory validation view uses current models; its persisted output remains
schema 3 and is not readable by the current runtime.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
from stat import S_IMODE
from typing import Any

from cred_scan.scan.models import CredentialsDocument, TitusReport

OLD_SCHEMA_VERSION = 2
NEW_SCHEMA_VERSION = 3


def _validate_document(payload: dict[str, Any], path: Path) -> CredentialsDocument:
    # This historical utility still writes schema 3 with scope_id. Adapt only
    # its validation view; do not introduce a runtime compatibility fallback.
    try:
        if payload.get("schema_version") != NEW_SCHEMA_VERSION:
            raise ValueError("not a schema-3 document")
        return CredentialsDocument.model_validate({
            **payload,
            "schema_version": 4,
            "boundary_id": payload["scope_id"],
        })
    except (KeyError, ValueError):
        # Validation errors can include credential values; report only the path.
        raise ValueError(f"{path}: invalid schema-3 credentials document") from None


def _retains_finding(raw: dict[str, Any], finding: dict[str, Any]) -> bool:
    for key, value in finding.items():
        if key == "Matches" and isinstance(value, list):
            if not isinstance(raw.get(key), list) or any(match not in raw[key] for match in value):
                return False
        elif key not in raw or raw[key] != value:
            return False
    return True


def _validate_report(
    document: CredentialsDocument, original: dict[str, Any], path: Path
) -> None:
    report_path = path.with_name("report.json")
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version", 1) != 1:
            raise ValueError("not a schema-1 report")
        report = TitusReport.model_validate({
            **payload,
            "schema_version": 2,
            "boundary_id": payload["scope_id"],
        })
    except (OSError, KeyError, ValueError):
        raise ValueError(f"{report_path}: missing or invalid canonical report") from None
    if (
        report.boundary_id != document.boundary_id
        or report.generated_at != document.report_generated_at
    ):
        raise ValueError(f"{report_path}: report boundary or generation does not match credentials")

    by_id: dict[str, list[dict[str, Any]]] = {}
    rule_ids, rule_names = set(), set()
    for finding in report.findings:
        if finding.get("ID") is not None:
            by_id.setdefault(str(finding["ID"]), []).append(finding)
        rule_ids.add(str(finding.get("RuleID", "unknown")))
        if finding.get("RuleName"):
            rule_names.add(str(finding["RuleName"]))
        matches = finding.get("Matches", [])
        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, dict) and match.get("RuleName"):
                    rule_names.add(str(match["RuleName"]))

    for credential in document.credentials.values():
        for occurrence in credential.occurrences:
            if any(finding_id not in by_id for finding_id in occurrence.finding_ids):
                raise ValueError(f"{path}: finding reference is absent from canonical report")

    # Check the data being removed, including occurrence-specific match subsets
    # and findings without IDs. An ID alone does not prove metadata is retained.
    for credential in original.get("credentials", {}).values():
        if not set(credential.get("rule_ids", ())) <= rule_ids or not set(
            credential.get("rule_names", ())
        ) <= rule_names:
            raise ValueError(f"{path}: rule metadata is absent from canonical report")
        for record in (credential, *credential.get("occurrences", ())):
            for finding in record.get("titus_findings", ()):
                if not isinstance(finding, dict):
                    raise ValueError(f"{path}: invalid embedded Titus finding")
                candidates = (
                    by_id.get(str(finding["ID"]), ())
                    if finding.get("ID") is not None else report.findings
                )
                if not any(_retains_finding(raw, finding) for raw in candidates):
                    raise ValueError(f"{path}: embedded finding is not preserved in canonical report")


def migrate_payload(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    """Return a schema-3 payload without duplicated Titus/rule metadata."""
    if payload.get("schema_version") != OLD_SCHEMA_VERSION:
        raise ValueError(
            f"{path}: expected credentials schema {OLD_SCHEMA_VERSION}, "
            f"found {payload.get('schema_version')!r}"
        )
    credentials = payload.get("credentials")
    if not isinstance(credentials, dict):
        raise ValueError(f"{path}: credentials must be a JSON object")

    migrated = copy.deepcopy(payload)
    migrated["schema_version"] = NEW_SCHEMA_VERSION
    for credential_id, credential in migrated["credentials"].items():
        if not isinstance(credential, dict):
            raise ValueError(f"{path}: credential {credential_id!r} is not an object")
        credential.pop("rule_ids", None)
        credential.pop("rule_names", None)
        credential.pop("titus_findings", None)
        occurrences = credential.get("occurrences")
        if not isinstance(occurrences, list):
            raise ValueError(
                f"{path}: occurrences for credential {credential_id!r} "
                "must be an array"
            )
        for index, occurrence in enumerate(occurrences):
            if not isinstance(occurrence, dict):
                raise ValueError(
                    f"{path}: occurrence {index} for credential "
                    f"{credential_id!r} is not an object"
                )
            occurrence.pop("titus_findings", None)
    _validate_document(migrated, path)
    return migrated


def _write_json_atomically(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    mode = S_IMODE(path.stat().st_mode)
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def migrate_results_dir(results_dir: Path, *, dry_run: bool = False) -> int:
    """Preflight every document, then convert schema 2; validated schema 3 is skipped.

    Returns the number of documents needing conversion, including in dry-run
    mode. Stop the scanner before running this operator-only utility.
    """
    if not results_dir.is_dir():
        raise ValueError(f"{results_dir}: results directory does not exist")
    pending: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(results_dir.rglob("credentials.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{path}: expected a JSON object")
        migrated = (
            payload if payload.get("schema_version") == NEW_SCHEMA_VERSION
            else migrate_payload(payload, path)
        )
        document = _validate_document(migrated, path)
        _validate_report(document, payload, path)
        if payload.get("schema_version") == OLD_SCHEMA_VERSION:
            pending.append((path, migrated))

    if not dry_run:
        for path, migrated in pending:
            _write_json_atomically(path, migrated)
    return len(pending)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate credentials.json from schema 2 to schema 3 with the scanner stopped."
    )
    parser.add_argument(
        "results_dir",
        type=Path,
        help="results/workspace directory containing boundary credentials.json files",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="preflight all documents/reports and count needed conversions without writing",
    )
    args = parser.parse_args()
    count = migrate_results_dir(args.results_dir, dry_run=args.dry_run)
    action = "would migrate" if args.dry_run else "migrated"
    print(f"{action} {count} credentials document(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
