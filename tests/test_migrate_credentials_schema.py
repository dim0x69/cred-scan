import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from cred_scan.scan.models import CredentialsDocument
from cred_scan.tools import migrate_credentials_schema as migration
from cred_scan.tools.migrate_credentials_schema import migrate_payload, migrate_results_dir


def _raw_finding() -> dict:
    return {
        "ID": "finding-id",
        "RuleID": "rule-1",
        "RuleName": "Example rule",
        "Groups": ["SYNTHETIC_VALUE"],
        "Matches": [{"file_path": "source://immutable/file"}],
    }


def _write_boundary(directory: Path, payload: dict | None = None) -> Path:
    directory.mkdir(parents=True)
    path = directory / "credentials.json"
    path.write_text(json.dumps(_legacy_payload() if payload is None else payload))
    path.with_name("report.json").write_text(json.dumps({
        "schema_version": 1,
        "scope_id": "scope",
        "generated_at": "now",
        "findings": [_raw_finding()],
    }))
    return path


def _legacy_payload() -> dict:
    return {
        "schema_version": 2,
        "scope_id": "scope",
        "report_generated_at": "now",
        "credentials": {
            "credential-id": {
                "credential_id": "credential-id",
                "credential": "secret",
                "rule_ids": ["rule-1"],
                "rule_names": ["Example rule"],
                "occurrences": [
                    {
                        "target_id": "target-id",
                        "locations": [
                            {
                                "provenance": "source://immutable/file",
                                "source_path": "file",
                                "filename": "file",
                            }
                        ],
                        "finding_ids": ["finding-id"],
                        "titus_findings": [_raw_finding()],
                    }
                ],
                "titus_findings": [_raw_finding()],
                "judgment": {"verdict": "VALID", "reasoning": "real"},
                "extraction": None,
            }
        },
        "errors": [],
    }


def test_migrate_payload_removes_redundant_fields(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    migrated = migrate_payload(_legacy_payload(), path)
    credential = migrated["credentials"]["credential-id"]

    assert migrated["schema_version"] == 3
    assert "rule_ids" not in credential
    assert "rule_names" not in credential
    assert "titus_findings" not in credential
    assert "titus_findings" not in credential["occurrences"][0]
    assert credential["occurrences"][0]["finding_ids"] == ["finding-id"]


def test_migrate_results_dir_writes_schema_three(tmp_path: Path) -> None:
    payload = _legacy_payload()
    extraction = {
        "status": "RETAINED",
        "source_fingerprint": "legacy-source-fingerprint",
        "output_path": "evidence/credential-id/file",
        "size": 4,
        "sha256": "existing-checksum",
    }
    payload["credentials"]["credential-id"]["extraction"] = extraction
    credentials = _write_boundary(tmp_path / "scope", payload)
    evidence = credentials.parent / extraction["output_path"]
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"test")
    report = credentials.with_name("report.json")
    report_bytes = report.read_bytes()

    assert migrate_results_dir(tmp_path) == 1
    migrated = json.loads(credentials.read_text(encoding="utf-8"))
    document = migration._validate_document(migrated, credentials)
    assert document.boundary_id == migrated["scope_id"]
    assert "boundary_id" not in migrated
    with pytest.raises(ValidationError):
        CredentialsDocument.model_validate(migrated)
    candidate = migrated["credentials"]["credential-id"]
    assert migrated["schema_version"] == 3
    assert "titus_findings" not in candidate
    assert candidate["judgment"] == payload["credentials"]["credential-id"]["judgment"]
    assert candidate["extraction"] == extraction
    assert "source_fingerprint" not in (
        document.credentials["credential-id"].extraction.model_dump()
    )
    assert report.read_bytes() == report_bytes
    assert evidence.read_bytes() == b"test"


def test_migrate_results_dir_dry_run_does_not_write(tmp_path: Path) -> None:
    credentials = _write_boundary(tmp_path / "scope")
    original = credentials.read_bytes()

    assert migrate_results_dir(tmp_path, dry_run=True) == 1
    assert credentials.read_bytes() == original


def test_migration_rejects_non_schema_two(tmp_path: Path) -> None:
    payload = _legacy_payload()
    payload["schema_version"] = 3
    with pytest.raises(ValueError, match="expected credentials schema 2"):
        migrate_payload(payload, tmp_path / "credentials.json")


def test_runtime_rejects_schema_two_document() -> None:
    with pytest.raises(ValidationError):
        CredentialsDocument.model_validate(_legacy_payload())


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("defect", ["missing_target", "empty_target", "empty_occurrences", "wrong_id", "invalid_verdict", "schema"])
def test_migration_preflights_all_documents_before_writing(tmp_path, dry_run, defect):
    first = _write_boundary(tmp_path / "a")
    payload = _legacy_payload()
    candidate = payload["credentials"]["credential-id"]
    if defect == "missing_target":
        del candidate["occurrences"][0]["target_id"]
    elif defect == "empty_target":
        candidate["occurrences"][0]["target_id"] = ""
    elif defect == "empty_occurrences":
        candidate["occurrences"] = []
    elif defect == "wrong_id":
        candidate["credential_id"] = "mismatched"
    elif defect == "invalid_verdict":
        candidate["judgment"]["verdict"] = "unexpected"
    else:
        payload["schema_version"] = 4
    second = _write_boundary(tmp_path / "b", payload)
    originals = {path: path.read_bytes() for path in (first, second)}
    with pytest.raises(ValueError):
        migrate_results_dir(tmp_path, dry_run=dry_run)
    assert all(path.read_bytes() == original for path, original in originals.items())


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("defect", ["missing", "invalid", "scope", "generation", "reference", "metadata", "matches"])
def test_migration_rejects_missing_or_inconsistent_raw_report(tmp_path, dry_run, defect):
    first = _write_boundary(tmp_path / "a")
    second = _write_boundary(tmp_path / "b")
    report_path = second.with_name("report.json")
    report = json.loads(report_path.read_text())
    if defect == "missing":
        report_path.unlink()
    elif defect == "invalid":
        report_path.write_text("not JSON")
    else:
        if defect == "scope":
            report["scope_id"] = "other-scope"
        elif defect == "generation":
            report["generated_at"] = "other-generation"
        elif defect == "reference":
            report["findings"][0]["ID"] = "other-finding"
        elif defect == "metadata":
            report["findings"][0]["Groups"] = ["CHANGED_VALUE"]
        else:
            report["findings"][0]["Matches"] = []
        report_path.write_text(json.dumps(report))
    originals = {path: path.read_bytes() for path in (first, second)}
    with pytest.raises(ValueError):
        migrate_results_dir(tmp_path, dry_run=dry_run)
    assert all(path.read_bytes() == original for path, original in originals.items())


def test_migration_skips_valid_schema_three_without_rewriting(tmp_path):
    first = _write_boundary(
        tmp_path / "a", migrate_payload(_legacy_payload(), tmp_path / "a/credentials.json")
    )
    second = _write_boundary(tmp_path / "b")
    original = first.read_bytes()
    assert migrate_results_dir(tmp_path, dry_run=True) == 1
    assert migrate_results_dir(tmp_path) == 1
    assert first.read_bytes() == original
    assert json.loads(second.read_text())["schema_version"] == 3
    assert migrate_results_dir(tmp_path) == 0


def test_migration_validates_schema_three_before_skipping(tmp_path):
    payload = migrate_payload(_legacy_payload(), tmp_path / "credentials.json")
    del payload["credentials"]["credential-id"]["occurrences"][0]["target_id"]
    credentials = _write_boundary(tmp_path / "scope", payload)
    original = credentials.read_bytes()
    with pytest.raises(ValueError, match="invalid schema-3"):
        migrate_results_dir(tmp_path)
    assert credentials.read_bytes() == original


def test_migration_resumes_after_interrupted_write(tmp_path, monkeypatch):
    first = _write_boundary(tmp_path / "a")
    second = _write_boundary(tmp_path / "b")
    write = migration._write_json_atomically

    def interrupted(path, payload):
        if path == second:
            raise OSError("synthetic interruption")
        write(path, payload)

    monkeypatch.setattr(migration, "_write_json_atomically", interrupted)
    with pytest.raises(OSError, match="synthetic interruption"):
        migrate_results_dir(tmp_path)
    assert json.loads(first.read_text())["schema_version"] == 3
    assert json.loads(second.read_text())["schema_version"] == 2
    first_bytes = first.read_bytes()
    monkeypatch.setattr(migration, "_write_json_atomically", write)
    assert migrate_results_dir(tmp_path) == 1
    assert first.read_bytes() == first_bytes
    assert json.loads(second.read_text())["schema_version"] == 3


def test_migration_preserves_idless_findings_and_occurrence_subsets(tmp_path):
    payload = _legacy_payload()
    candidate = payload["credentials"]["credential-id"]
    raw = _raw_finding()
    del raw["ID"]
    candidate["occurrences"][0]["finding_ids"] = []
    candidate["occurrences"][0]["titus_findings"] = [json.loads(json.dumps(raw))]
    raw["Matches"].append({"file_path": "source://immutable/other-file"})
    candidate["titus_findings"] = [raw]
    credentials = _write_boundary(tmp_path / "scope", payload)
    report_path = credentials.with_name("report.json")
    report = json.loads(report_path.read_text())
    report["findings"] = [raw, {"RuleID": "unrelated", "Matches": None}]
    report_path.write_text(json.dumps(report))
    original = report_path.read_bytes()
    assert migrate_results_dir(tmp_path) == 1
    assert report_path.read_bytes() == original
    migrated = migration._validate_document(
        json.loads(credentials.read_text()), credentials
    )
    assert migrated.credentials["credential-id"].occurrences[0].finding_ids == ()


def test_migration_requires_existing_results_directory(tmp_path):
    with pytest.raises(ValueError, match="directory does not exist"):
        migrate_results_dir(tmp_path / "missing")


def test_migrate_payload_rejects_missing_target_without_mutating_input(tmp_path):
    payload = _legacy_payload()
    del payload["credentials"]["credential-id"]["occurrences"][0]["target_id"]
    original = json.dumps(payload, sort_keys=True)
    with pytest.raises(ValueError, match="invalid schema-3"):
        migrate_payload(payload, tmp_path / "credentials.json")
    assert json.dumps(payload, sort_keys=True) == original
