import asyncio
import logging
from pathlib import Path
from unittest.mock import AsyncMock, Mock, create_autospec

import pytest

from cred_scan.backend.adapters.artifactory.docker import parse_provenance
from cred_scan.backend.models import ResolvedProvenance, ScanBoundaryInventory
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.common.models import WorkspaceConfig
from cred_scan.common.workspace import Workspace
from cred_scan.judge.proto import FindingJudge
from cred_scan.orch import runtime
from cred_scan.orch.credentials import merge_scan, with_judgment
from cred_scan.orch.models import AppConfig, TitusConfig
from cred_scan.orch.runtime import LocalRuntime, ReportBoundary
from cred_scan.scan.models import (
    CredentialsDocument,
    ExclusionPolicy,
    JudgmentResult,
    TitusReport,
)
from cred_scan.scan.proto import CredentialScanner


def publish(workspace, document):
    path = workspace.boundary(document.boundary_id).credentials
    published = merge_scan(workspace.read(path, CredentialsDocument), document)
    workspace.write(path, published, CredentialsDocument)
    return published


def make_boundary(tmp_path: Path, inventory: ScanBoundaryInventory, findings=()):
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    workspace.write(
        workspace.boundary(inventory.boundary.id).inventory,
        inventory,
        ScanBoundaryInventory,
    )
    scanner = create_autospec(CredentialScanner, instance=True)
    scanner.scan.side_effect = lambda target, *_: target.model_copy(
        update={"result": target.result.model_copy(update={"status": "scanned"})}
    )
    scanner.export_report.return_value = TitusReport(
        boundary_id=inventory.boundary.id,
        generated_at="2026-01-01T00:00:00+00:00",
        findings=tuple(findings),
    )
    backend = create_autospec(BackendAdapter, instance=True)
    backend.name = "primary"
    reader = create_autospec(ContentReader, instance=True)

    async def resolve(raw_path: str, *, target_id=None):
        source_path = raw_path.split("sha256:layer:", 1)[-1]
        resolved_target_id = target_id or inventory.targets[0].id
        return ResolvedProvenance(
            target_id=resolved_target_id,
            provenance=parse_provenance(raw_path).model_copy(
                update={"target_id": resolved_target_id}
            ),
            source_path=source_path,
            filename=source_path.rsplit("/", 1)[-1],
        )

    reader.resolve_provenance.side_effect = resolve
    backend.content_reader.return_value = reader
    judge = create_autospec(FindingJudge, instance=True)
    boundary = ReportBoundary(inventory, workspace, backend=backend)
    return boundary, scanner, backend, judge


def test_scan_persists_raw_report_and_deduplicated_credentials(
    tmp_path, repository_inventory
):
    finding = {
        "ID": "f1",
        "RuleID": "np.generic.3",
        "Groups": ["user", "c2VjcmV0"],
        "Matches": [
            {
                "file_path": "docker://registry/docker-local/team/api@sha256:manifest/sha256:layer:etc/app.env"
            }
        ],
    }
    boundary, scanner, _, _ = make_boundary(tmp_path, repository_inventory, [finding])
    policy = ExclusionPolicy(path_file=tmp_path / "paths.list")
    document = asyncio.run(boundary.scan(scanner, policy))
    assert (
        boundary.workspace.read(boundary.paths.report, TitusReport).findings[0]["ID"]
        == "f1"
    )
    assert len(document.credentials) == 1
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert saved is not None
    assert next(iter(saved.credentials.values())).judgment.verdict == "PENDING"


def test_scan_publishes_raw_report_when_all_findings_are_excluded(
    tmp_path, repository_inventory
):
    finding = {
        "ID": "excluded-finding",
        "RuleID": "np.generic.3",
        "Groups": ["user", "c2VjcmV0"],
        "Matches": [
            {
                "file_path": (
                    "docker://registry/docker-local/team/api@sha256:manifest/"
                    "sha256:layer:vendor/app.env"
                )
            }
        ],
    }
    boundary, scanner, _, _ = make_boundary(tmp_path, repository_inventory, [finding])
    policy = ExclusionPolicy(
        path_file=tmp_path / "paths.list", path_patterns=("vendor/",)
    )

    document = asyncio.run(boundary.scan(scanner, policy))

    assert document.credentials == {}
    report = boundary.workspace.read(boundary.paths.report, TitusReport)
    assert report is not None
    assert report.findings == (finding,)
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert saved is not None
    assert saved.credentials == {}


def test_error_only_inventory_publishes_diagnostic_empty_documents(
    tmp_path, repository_inventory
):
    inventory = repository_inventory.model_copy(
        update={"targets": (), "errors": ("repository discovery failed",)}
    )
    boundary, scanner, backend, _ = make_boundary(tmp_path, inventory)
    policy = ExclusionPolicy(path_file=tmp_path / "paths.list")

    document = asyncio.run(boundary.scan(scanner, policy))

    assert document.incomplete is True
    assert document.credentials == {}
    assert document.errors == ("repository discovery failed",)
    scanner.export_report.assert_not_awaited()
    backend.content_reader.assert_not_called()
    report = boundary.workspace.read(boundary.paths.report, TitusReport)
    assert report is not None
    assert report.incomplete is True
    assert report.errors == ("repository discovery failed",)
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert saved is not None
    assert saved.incomplete is True
    assert saved.errors == ("repository discovery failed",)
    assert saved.credentials == {}


def test_judgment_returns_and_persists_only_judgment_result(
    tmp_path, repository_inventory, credential, caplog
):
    boundary, scanner, backend, judge = make_boundary(tmp_path, repository_inventory)
    caplog.set_level(logging.INFO)
    policy = ExclusionPolicy(path_file=tmp_path / "paths.list")
    asyncio.run(boundary.scan(scanner, policy))
    publish(
        boundary.workspace,
        CredentialsDocument(
            boundary_id=repository_inventory.boundary.id,
            report_generated_at="now",
            credentials={credential.credential_id: credential},
        ),
    )
    reader = create_autospec(ContentReader, instance=True)
    backend.content_reader.return_value = reader
    judge.judge.return_value = JudgmentResult(verdict="INVALID", reasoning="example")
    document = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    count = asyncio.run(boundary.judge(document, judge))
    assert count == 1
    assert any(
        f"judged credential={credential.credential_id}" in record.message
        and "verdict=INVALID" in record.message
        for record in caplog.records
    )
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert next(iter(saved.credentials.values())).judgment.verdict == "INVALID"
    judge.judge.assert_awaited_once()


def test_combined_judgment_extracts_with_live_reader_without_republishing(
    tmp_path, repository_inventory, credential, monkeypatch
):
    boundary, scanner, backend, judge = make_boundary(tmp_path, repository_inventory)
    policy = ExclusionPolicy(path_file=tmp_path / "paths.list")
    asyncio.run(boundary.scan(scanner, policy))

    document = CredentialsDocument(
        boundary_id=repository_inventory.boundary.id,
        report_generated_at="now",
        credentials={credential.credential_id: credential},
    )
    publish(boundary.workspace, document)
    publication = Mock(wraps=runtime.merge_scan)
    monkeypatch.setattr(runtime, "merge_scan", publication)

    reader = create_autospec(ContentReader, instance=True)

    async def extract_file(_provenance, destination):
        reader.aclose.assert_not_awaited()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"SYNTHETIC_VALUE")
        return destination

    reader.extract_file.side_effect = extract_file
    backend.content_reader.return_value = reader
    judge.judge.return_value = JudgmentResult(verdict="VALID", reasoning="example")

    count = asyncio.run(boundary.judge(document, judge, extract_valid=True))

    assert count == 1
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert saved is not None
    candidate = saved.credentials[credential.credential_id]
    assert candidate.judgment.verdict == "VALID"
    assert candidate.extraction is not None
    assert candidate.extraction.status == "RETAINED"
    publication.assert_not_called()
    judge.judge.assert_awaited_once_with(credential, reader)
    reader.extract_file.assert_awaited_once()
    reader.aclose.assert_awaited_once()


def test_combined_evidence_failure_is_retryable_without_rejudging(
    tmp_path, repository_inventory, credential
):
    boundary, scanner, backend, judge = make_boundary(tmp_path, repository_inventory)
    policy = ExclusionPolicy(path_file=tmp_path / "paths.list")
    asyncio.run(boundary.scan(scanner, policy))

    document = CredentialsDocument(
        boundary_id=repository_inventory.boundary.id,
        report_generated_at="now",
        credentials={credential.credential_id: credential},
    )
    publish(boundary.workspace, document)
    readers = [create_autospec(ContentReader, instance=True) for _ in range(2)]
    for index, reader in enumerate(readers):

        async def extract_file(_provenance, destination, reader=reader, index=index):
            reader.aclose.assert_not_awaited()
            if index == 0:
                raise OSError("temporary evidence failure")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"SYNTHETIC_VALUE")
            return destination

        reader.extract_file.side_effect = extract_file
    backend.content_reader.side_effect = readers
    judge.judge.return_value = JudgmentResult(verdict="VALID", reasoning="example")

    asyncio.run(boundary.judge(document, judge, extract_valid=True))
    failed = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert failed is not None
    assert failed.credentials[credential.credential_id].judgment.verdict == "VALID"
    assert failed.credentials[credential.credential_id].extraction.status == "ERROR"

    retry_document = boundary.workspace.read(
        boundary.paths.credentials, CredentialsDocument
    )
    assert retry_document is not None
    retained = asyncio.run(boundary.extract(retry_document))
    assert retained == 1
    recovered = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert recovered is not None
    assert (
        recovered.credentials[credential.credential_id].extraction.status == "RETAINED"
    )
    judge.judge.assert_awaited_once()
    for reader in readers:
        reader.extract_file.assert_awaited_once()
        reader.aclose.assert_awaited_once()


def test_boundaries_skip_empty_successful_inventory(tmp_path, repository_inventory):
    config = AppConfig(
        workspace=WorkspaceConfig(workspace_dir=tmp_path),
        titus=TitusConfig(executable="unused"),
        exclusions={
            "paths": tmp_path / "paths.list",
            "credentials": tmp_path / "values.list",
        },
        backends=(),
    )
    workspace = Workspace(config.workspace)
    empty = repository_inventory.model_copy(update={"targets": ()})
    workspace.write(
        workspace.boundary(empty.boundary.id).inventory, empty, ScanBoundaryInventory
    )

    assert list(LocalRuntime(config).boundaries()) == []


def test_local_runtime_scan_returns_boundary_count(tmp_path, monkeypatch):
    config = AppConfig(
        workspace=WorkspaceConfig(workspace_dir=tmp_path),
        titus=TitusConfig(executable="unused"),
        exclusions={
            "paths": tmp_path / "paths.list",
            "credentials": tmp_path / "values.list",
        },
        backends=(),
    )
    local = LocalRuntime(config)
    item = create_autospec(ReportBoundary, instance=True)
    item.scan.return_value = CredentialsDocument(
        boundary_id="scope", report_generated_at="now"
    )
    monkeypatch.setattr(local, "boundaries", lambda: iter((item,)))
    scanner = create_autospec(CredentialScanner, instance=True)
    monkeypatch.setattr(local, "_make_scanner", Mock(return_value=scanner))
    monkeypatch.setattr(
        runtime,
        "load_exclusions",
        Mock(return_value=ExclusionPolicy(path_file="paths")),
    )
    assert asyncio.run(local.scan()) == 1


@pytest.mark.parametrize(
    ("command", "state", "expected"),
    [
        ("judge", "missing", 0),
        ("judge", "empty", 0),
        ("judge", "PENDING", 1),
        ("judge", "ERROR", 1),
        ("judge", "VALID", 0),
        ("judge", "INVALID", 0),
        ("judge", "UNKNOWN", 0),
        ("extract", "missing", 0),
        ("extract", "empty", 0),
        ("extract", "PENDING", 0),
        ("extract", "ERROR", 0),
        ("extract", "VALID", 1),
        ("extract", "INVALID", 0),
        ("extract", "UNKNOWN", 0),
    ],
)
def test_existing_phases_construct_services_only_for_eligible_work(
    app_config, repository_inventory, credential, monkeypatch, command, state, expected
):
    local = LocalRuntime(app_config)
    repository = local.workspace.boundary(repository_inventory.boundary.id)
    local.workspace.write(
        repository.inventory, repository_inventory, ScanBoundaryInventory
    )
    document = None
    if state != "missing":
        credentials = {}
        if state != "empty":
            candidate = credential.model_copy(
                update={"judgment": JudgmentResult(verdict=state)}
            )
            credentials[candidate.credential_id] = candidate
        document = publish(
            local.workspace,
            CredentialsDocument(
                boundary_id=repository_inventory.boundary.id,
                report_generated_at="now",
                credentials=credentials,
            ),
        )

    backend = create_autospec(BackendAdapter, instance=True)
    build = Mock(return_value=backend)
    judge_factory = Mock(return_value=create_autospec(FindingJudge, instance=True))
    scanner_factory = Mock(
        side_effect=AssertionError("standalone phase created scanner")
    )
    process = AsyncMock(return_value=1)
    monkeypatch.setattr(runtime, "build_backend", build)
    monkeypatch.setattr(runtime, "DspyFindingJudge", judge_factory)
    monkeypatch.setattr(runtime, "TitusCliScanner", scanner_factory)
    monkeypatch.setattr(ReportBoundary, command, process)

    assert asyncio.run(getattr(local, command)()) == expected
    assert build.call_count == expected
    assert judge_factory.call_count == (expected if command == "judge" else 0)
    scanner_factory.assert_not_called()
    if expected:
        if command == "judge":
            process.assert_awaited_once_with(document, judge_factory.return_value)
        else:
            process.assert_awaited_once_with(document)
        backend.aclose.assert_awaited_once()
    else:
        process.assert_not_awaited()
        backend.aclose.assert_not_awaited()


def test_combined_processing_handles_existing_valid_and_reuses_retained_evidence(
    tmp_path, repository_inventory, credential
):
    boundary, scanner, backend, judge = make_boundary(tmp_path, repository_inventory)
    asyncio.run(
        boundary.scan(scanner, ExclusionPolicy(path_file=tmp_path / "paths.list"))
    )
    existing = credential.model_copy(
        update={
            "credential_id": "existing-valid",
            "credential": "SECOND_SYNTHETIC_VALUE",
            "judgment": JudgmentResult(verdict="VALID", reasoning="already judged"),
        }
    )
    document = publish(
        boundary.workspace,
        CredentialsDocument(
            boundary_id=repository_inventory.boundary.id,
            report_generated_at="now",
            credentials={
                credential.credential_id: credential,
                existing.credential_id: existing,
            },
        ),
    )
    readers = [create_autospec(ContentReader, instance=True) for _ in range(2)]
    for reader in readers:

        async def extract_file(_provenance, destination, reader=reader):
            reader.aclose.assert_not_awaited()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"SYNTHETIC_VALUE\nSECOND_SYNTHETIC_VALUE")
            return destination

        reader.extract_file.side_effect = extract_file
    backend.content_reader.reset_mock()
    backend.content_reader.side_effect = readers
    judge.judge.return_value = JudgmentResult(verdict="VALID", reasoning="newly judged")

    assert asyncio.run(boundary.judge(document, judge, extract_valid=True)) == 1
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert saved is not None
    for current in saved.credentials.values():
        assert current.extraction is not None
        assert current.extraction.status == "RETAINED"
    assert saved.credentials[existing.credential_id].judgment == existing.judgment
    judge.judge.assert_awaited_once_with(credential, readers[0])
    for reader in readers:
        reader.extract_file.assert_awaited_once()
        reader.aclose.assert_awaited_once()

    assert asyncio.run(boundary.judge(saved, judge, extract_valid=True)) == 0
    assert backend.content_reader.call_count == 2
    judge.judge.assert_awaited_once()


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
@pytest.mark.parametrize("rejudge", [False, True])
def test_evidence_recovery_reports_integrity_failure_without_overwriting_history(
    tmp_path, repository_inventory, credential, damage, rejudge
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    publish(
        boundary.workspace,
        CredentialsDocument(
            boundary_id=repository_inventory.boundary.id,
            report_generated_at="now",
            credentials={credential.credential_id: credential},
        ),
    )
    reader = create_autospec(ContentReader, instance=True)

    async def extract_file(_provenance, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"verified evidence")
        return destination

    reader.extract_file.side_effect = extract_file
    backend.content_reader.return_value = reader
    judge.judge.return_value = JudgmentResult(verdict="VALID")
    asyncio.run(
        boundary.judge(
            boundary.workspace.read(boundary.paths.credentials, CredentialsDocument),
            judge,
            extract_valid=True,
        )
    )
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    extraction = saved.credentials[credential.credential_id].extraction
    evidence = boundary.paths.boundary_dir / extraction.output_path
    original_document = boundary.paths.credentials.read_bytes()
    if damage == "missing":
        evidence.unlink()
    else:
        evidence.write_bytes(b"damaged artifact")
    if rejudge:
        boundary.workspace.write(
            boundary.paths.credentials,
            with_judgment(
                saved, credential.credential_id, JudgmentResult(verdict="ERROR")
            ),
            CredentialsDocument,
        )
    backend.content_reader.reset_mock()
    document = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    with pytest.raises(RuntimeError, match="retained evidence is missing or corrupt"):
        asyncio.run(
            boundary.judge(document, judge, extract_valid=True)
            if rejudge
            else boundary.extract(document)
        )
    assert backend.content_reader.call_count == int(rejudge)
    reader.extract_file.assert_not_awaited()  # Reset above; no new extraction.
    assert boundary.paths.credentials.read_bytes() == original_document
    if damage == "missing":
        assert not evidence.exists()
    else:
        assert evidence.read_bytes() == b"damaged artifact"
    # An operator can restore the artifact verified by the original hash.
    evidence.write_bytes(b"verified evidence")
    backend.content_reader.reset_mock()
    assert (
        asyncio.run(
            boundary.extract(
                boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
            )
        )
        == 0
    )
    backend.content_reader.assert_not_called()


@pytest.mark.parametrize("invalid", ["boundary", "target", "empty-target"])
def test_invalid_credential_references_fail_before_content_access(
    tmp_path, repository_inventory, credential, invalid
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    if invalid != "boundary":
        credential = credential.model_copy(
            update={
                "occurrences": (
                    credential.occurrences[0].model_copy(
                        update={"target_id": "unknown" if invalid == "target" else ""}
                    ),
                )
            }
        )
    # model_copy intentionally simulates an invalid queued in-memory document.
    document = CredentialsDocument(
        boundary_id="other"
        if invalid == "boundary"
        else repository_inventory.boundary.id,
        report_generated_at="now",
    ).model_copy(update={"credentials": {credential.credential_id: credential}})
    with pytest.raises(ValueError, match="another boundary|unknown target"):
        asyncio.run(boundary.judge(document, judge, extract_valid=True))
    backend.content_reader.assert_not_called()
    judge.judge.assert_not_awaited()


@pytest.mark.parametrize("phase", ["judge", "extract"])
@pytest.mark.parametrize("missing", ["document", "credential"])
def test_lifecycle_does_not_recreate_missing_persisted_state(
    tmp_path, repository_inventory, credential, phase, missing
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    if phase == "extract":
        credential = credential.model_copy(
            update={"judgment": JudgmentResult(verdict="VALID")}
        )
    document = CredentialsDocument(
        boundary_id=repository_inventory.boundary.id,
        report_generated_at="now",
        credentials={credential.credential_id: credential},
    )
    if missing == "credential":
        boundary.workspace.write(
            boundary.paths.credentials,
            document.model_copy(update={"credentials": {}}),
            CredentialsDocument,
        )
    reader = create_autospec(ContentReader, instance=True)

    async def extract_file(_provenance, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"synthetic evidence")
        return destination

    reader.extract_file.side_effect = extract_file
    backend.content_reader.return_value = reader
    judge.judge.return_value = JudgmentResult(verdict="VALID")
    with pytest.raises(ValueError, match="without|inactive credential"):
        asyncio.run(
            boundary.judge(document, judge)
            if phase == "judge"
            else boundary.extract(document)
        )
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert saved is None if missing == "document" else saved.credentials == {}
    reader.aclose.assert_awaited_once()


def test_publication_guard_detects_an_injected_republication(
    tmp_path, repository_inventory, credential, monkeypatch
):
    original = ReportBoundary.judge

    async def incorrectly_republish(self, document, judge, **kwargs):
        runtime.merge_scan(document, document)
        return await original(self, document, judge, **kwargs)

    monkeypatch.setattr(ReportBoundary, "judge", incorrectly_republish)
    with pytest.raises(AssertionError, match="not have been called"):
        test_combined_judgment_extracts_with_live_reader_without_republishing(
            tmp_path,
            repository_inventory,
            credential,
            monkeypatch,
        )


@pytest.mark.parametrize("failure", ["reader", "judge"])
@pytest.mark.parametrize("fatal", [False, True])
def test_judgment_error_boundary_keeps_fatal_failures_visible(
    tmp_path, repository_inventory, credential, failure, fatal
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    document = publish(
        boundary.workspace,
        CredentialsDocument(
            boundary_id=repository_inventory.boundary.id,
            report_generated_at="now",
            credentials={credential.credential_id: credential},
        ),
    )
    reader = create_autospec(ContentReader, instance=True)
    backend.content_reader.return_value = reader
    error = (
        runtime.FatalJudgeError("fatal configuration")
        if fatal
        else OSError("transient failure")
    )
    if failure == "reader":
        backend.content_reader.side_effect = error
    else:
        judge.judge.side_effect = error
    if fatal:
        with pytest.raises(runtime.FatalJudgeError):
            asyncio.run(boundary.judge(document, judge, extract_valid=True))
    else:
        assert asyncio.run(boundary.judge(document, judge, extract_valid=True)) == 1
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert saved is not None
    current = saved.credentials[credential.credential_id]
    assert current.judgment.verdict == ("PENDING" if fatal else "ERROR")
    assert current.extraction is None
    reader.extract_file.assert_not_awaited()
    assert reader.aclose.await_count == int(failure == "judge")


def test_extraction_reader_failure_is_checkpointed_once(
    tmp_path, repository_inventory, credential, monkeypatch
):
    boundary, _, backend, _ = make_boundary(tmp_path, repository_inventory)
    valid = credential.model_copy(update={"judgment": JudgmentResult(verdict="VALID")})
    document = publish(
        boundary.workspace,
        CredentialsDocument(
            boundary_id=repository_inventory.boundary.id,
            report_generated_at="now",
            credentials={valid.credential_id: valid},
        ),
    )
    backend.content_reader.side_effect = OSError("temporary content error")
    checkpoint = Mock(wraps=boundary.workspace.write)
    monkeypatch.setattr(boundary.workspace, "write", checkpoint)
    assert asyncio.run(boundary.extract(document)) == 0
    checkpoint.assert_called_once()
    saved = boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)
    assert saved is not None
    current = saved.credentials[valid.credential_id]
    assert current.judgment.verdict == "VALID"
    assert current.extraction is not None and current.extraction.status == "ERROR"
