"""Boundary operations with real persistence; claim/scheduler tests live in recovery."""

import asyncio
from unittest.mock import Mock, create_autospec

import pytest

from cred_scan.extract import evidence as evidence_module

from cred_scan.backend.models import ContentLocation, ContentRead, ScanTargetInventory
from cred_scan.orch.execution import BoundaryExecution, Phase
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.orch.models import WorkspaceConfig
from cred_scan.orch.workspace import Workspace
from cred_scan.judge.proto import FatalJudgeError, FindingJudge
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch.boundary import Boundary
from cred_scan.scan.models import (
    CredentialsDocument,
    ExclusionPolicy,
    JudgmentResult,
    TitusReport,
)
from cred_scan.scan.proto import CredentialScanner


def make_boundary(tmp_path, inventory, findings=()):
    store = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    # These are operation unit tests. Integration tests exercise real claim fencing.
    workspace = create_autospec(Workspace, instance=True)
    workspace.boundary.side_effect = store.boundary
    workspace.read.side_effect = store.read
    workspace.write.side_effect = store.write
    paths = store.boundary(inventory.boundary.id)
    store.write(paths.inventory, inventory, ScanTargetInventory)

    def checkpoint(boundary):
        store.write(boundary.paths.inventory, boundary.inventory, ScanTargetInventory)
        if boundary.report is not None:
            store.write(boundary.paths.report, boundary.report, TitusReport)
        if boundary.document is not None:
            store.write(
                boundary.paths.credentials, boundary.document, CredentialsDocument
            )
        store.write(boundary.paths.execution, boundary.execution, BoundaryExecution)

    workspace.checkpoint.side_effect = checkpoint
    scanner = create_autospec(CredentialScanner, instance=True)
    scanner.scan.side_effect = lambda target, *_: target.model_copy(
        update={"result": target.result.model_copy(update={"status": "scanned"})}
    )
    scanner.export_report.return_value = TitusReport(
        boundary_id=inventory.boundary.id, generated_at="now", findings=tuple(findings)
    )
    backend = create_autospec(BackendAdapter, instance=True)
    reader = create_autospec(ContentReader, instance=True)
    reader.resolve_location.side_effect = lambda locator: ContentLocation(
        target_id=inventory.targets[0].id,
        locator=locator,
        source_path=locator.split("sha256:layer:", 1)[-1],
        filename=locator.rsplit("/", 1)[-1],
    )
    reader.read.return_value = ContentRead(
        content=b"SYNTHETIC_VALUE", source_path="etc/app.env", filename="app.env"
    )
    backend.content_reader.return_value = reader
    judge = create_autospec(FindingJudge, instance=True)
    boundary = Boundary(
        inventory=inventory,
        workspace=workspace,
        paths=paths,
        backend=backend,
        document=None,
        report=None,
        execution=BoundaryExecution(boundary_id=inventory.boundary.id),
        phase=Phase.SCAN,
        scanner=scanner,
        judge=judge,
        policy=ExclusionPolicy(path_file=tmp_path / "paths"),
        extract_after_judgment=True,
    )
    return boundary, scanner, backend, judge


def publish(boundary, *credentials):
    document = CredentialsDocument(
        boundary_id=boundary.boundary_id,
        report_generated_at="now",
        credentials={c.credential_id: c for c in credentials},
    )
    boundary.workspace.write(boundary.paths.credentials, document, CredentialsDocument)
    # The loaded object must not alias the inputs used to assert saved history.
    boundary.document = boundary.workspace.read(
        boundary.paths.credentials, CredentialsDocument
    )
    return boundary.document


def saved(boundary):
    return boundary.workspace.read(boundary.paths.credentials, CredentialsDocument)


@pytest.mark.parametrize("excluded", [False, True])
def test_scan_publishes_final_raw_report_before_normalized_candidates(
    tmp_path, repository_inventory, excluded
):
    finding = {
        "ID": "f1",
        "RuleID": "np.generic.3",
        "Groups": ["user", "c2VjcmV0"],
        "Matches": [
            {
                "file_path": "docker://registry/docker-local/team/api@sha256:manifest/sha256:layer:vendor/app.env"
            }
        ],
    }
    boundary, scanner, backend, _ = make_boundary(
        tmp_path, repository_inventory, [finding]
    )
    policy = ExclusionPolicy(
        path_file=tmp_path / "paths", path_patterns=("vendor/",) if excluded else ()
    )
    boundary.policy = policy
    assert asyncio.run(boundary.run()) == 0
    report = boundary.workspace.read(boundary.paths.report, TitusReport)
    assert report.findings == (finding,)
    assert len(saved(boundary).credentials) == (0 if excluded else 1)
    assert boundary.document == saved(boundary)
    backend.aclose.assert_not_awaited()


def test_error_only_inventory_publishes_diagnostic_empty_documents(
    tmp_path, repository_inventory
):
    inventory = repository_inventory.model_copy(
        update={"targets": (), "errors": ("discovery failed",)}
    )
    boundary, scanner, backend, _ = make_boundary(tmp_path, inventory)
    boundary.policy = ExclusionPolicy(path_file=tmp_path / "paths")
    asyncio.run(boundary.run())
    document = saved(boundary)
    report = boundary.workspace.read(boundary.paths.report, TitusReport)
    assert document.incomplete and report.incomplete
    assert document.errors == report.errors == ("discovery failed",)
    assert document.credentials == {}
    scanner.export_report.assert_not_awaited()
    backend.content_reader.assert_not_called()


def test_judge_only_saves_results_without_extraction(
    tmp_path, repository_inventory, credential
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    publish(boundary, credential)
    judge.judge.return_value = JudgmentResult(verdict="VALID")
    boundary.phase = Phase.JUDGE
    boundary.extract_after_judgment = False
    assert asyncio.run(boundary.run()) == 1
    current = saved(boundary).credentials[credential.credential_id]
    assert current.judgment.verdict == "VALID" and current.extraction is None
    backend.content_reader.return_value.read.assert_not_awaited()
    backend.content_reader.return_value.aclose.assert_awaited_once()
    backend.aclose.assert_not_awaited()


def test_combined_judgment_extracts_with_live_reader_without_republishing(
    tmp_path, repository_inventory, credential, monkeypatch
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    publish(boundary, credential)
    publication = Mock(wraps=boundary_module.merge_scan)
    monkeypatch.setattr(boundary_module, "merge_scan", publication)
    reader = backend.content_reader.return_value
    sessions = []

    async def judge_with_content(candidate, content):
        sessions.append(content)
        reader.aclose.assert_not_awaited()
        assert (
            await content.read(candidate.occurrences[0].locator)
        ).content == b"SYNTHETIC_VALUE"
        await content.read(candidate.occurrences[0].locator)
        return JudgmentResult(verdict="VALID")

    judge.judge.side_effect = judge_with_content
    boundary.phase = Phase.JUDGE
    assert asyncio.run(boundary.run()) == 1
    candidate = saved(boundary).credentials[credential.credential_id]
    assert candidate.judgment.verdict == "VALID"
    assert candidate.extraction.status == "RETAINED"
    assert (
        boundary.paths.boundary_dir / candidate.extraction.output_path
    ).read_bytes() == b"SYNTHETIC_VALUE"
    publication.assert_not_called()
    reader.read.assert_awaited_once()
    reader.aclose.assert_awaited_once()
    assert not sessions[0]._cache
    with pytest.raises(RuntimeError, match="closed"):
        asyncio.run(sessions[0].read(credential.occurrences[0].locator))


def test_publication_guard_detects_injected_republication(
    tmp_path, repository_inventory, credential, monkeypatch
):
    original = Boundary.run

    async def incorrectly_republish(self):
        boundary_module.merge_scan(self.document, self.document)
        return await original(self)

    monkeypatch.setattr(Boundary, "run", incorrectly_republish)
    with pytest.raises(AssertionError, match="not have been called"):
        test_combined_judgment_extracts_with_live_reader_without_republishing(
            tmp_path, repository_inventory, credential, monkeypatch
        )


def test_combined_evidence_failure_retries_without_rejudgment(
    tmp_path, repository_inventory, credential
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    publish(boundary, credential)
    reader = backend.content_reader.return_value
    good_read = reader.read.return_value
    reader.read.side_effect = OSError("temporary failure")
    judge.judge.return_value = JudgmentResult(verdict="VALID")
    boundary.phase = Phase.JUDGE
    assert asyncio.run(boundary.run()) == 1
    failed = saved(boundary).credentials[credential.credential_id]
    assert failed.judgment.verdict == "VALID" and failed.extraction.status == "ERROR"
    reader.read.side_effect = None
    reader.read.return_value = good_read
    boundary.document = saved(boundary)
    boundary.phase = Phase.EXTRACT
    assert asyncio.run(boundary.run()) == 1
    assert (
        saved(boundary).credentials[credential.credential_id].extraction.status
        == "RETAINED"
    )
    judge.judge.assert_awaited_once()


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
@pytest.mark.parametrize("rejudge", [False, True])
def test_retained_is_trusted_without_audit_download_or_overwrite(
    tmp_path, repository_inventory, credential, damage, rejudge, monkeypatch
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    publish(boundary, credential)
    judge.judge.return_value = JudgmentResult(verdict="VALID")
    boundary.phase = Phase.JUDGE
    asyncio.run(boundary.run())
    document = saved(boundary)
    expected = document.credentials[credential.credential_id].extraction.model_copy(
        deep=True
    )
    evidence = boundary.paths.boundary_dir / expected.output_path
    if damage == "missing":
        evidence.unlink()
    else:
        evidence.write_bytes(b"damaged")
    if rejudge:
        document.credentials[credential.credential_id].judgment = JudgmentResult(
            verdict="ERROR"
        )
    boundary.document = document
    reader = backend.content_reader.return_value
    reader.read.reset_mock()
    retention = Mock(side_effect=AssertionError("RETAINED must be skipped"))
    monkeypatch.setattr(evidence_module, "retain_first_evidence", retention)
    if rejudge:
        boundary.phase = Phase.JUDGE
        assert asyncio.run(boundary.run()) == 1
    else:
        boundary.phase = Phase.EXTRACT
        assert asyncio.run(boundary.run()) == 0
    reader.read.assert_not_awaited()
    retention.assert_not_called()
    assert saved(boundary).credentials[credential.credential_id].extraction == expected
    if damage == "missing":
        assert not evidence.exists()
    else:
        assert evidence.read_bytes() == b"damaged"


def test_existing_valid_and_pending_credentials_share_normal_pass(
    tmp_path, repository_inventory, credential
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    valid = credential.model_copy(
        update={
            "credential_id": "older-valid",
            "judgment": JudgmentResult(verdict="VALID"),
        }
    )
    publish(boundary, valid, credential)
    judge.judge.return_value = JudgmentResult(verdict="VALID")
    boundary.phase = Phase.JUDGE
    assert asyncio.run(boundary.run()) == 1
    assert all(
        c.extraction.status == "RETAINED" for c in saved(boundary).credentials.values()
    )
    boundary.phase = Phase.JUDGE
    assert asyncio.run(boundary.run()) == 0
    judge.judge.assert_awaited_once()
    assert backend.content_reader.call_count == 2


def test_wrong_document_boundary_fails_before_content_access(
    tmp_path, repository_inventory, credential
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    boundary.document = CredentialsDocument(
        boundary_id="another", report_generated_at="now"
    )
    with pytest.raises(ValueError, match="another boundary"):
        boundary.phase = Phase.JUDGE
        asyncio.run(boundary.run())
    backend.content_reader.assert_not_called()
    judge.judge.assert_not_awaited()


@pytest.mark.parametrize("failure", ["reader", "judge"])
@pytest.mark.parametrize("fatal", [False, True])
def test_judgment_errors_keep_fatal_failures_visible(
    tmp_path, repository_inventory, credential, failure, fatal
):
    boundary, _, backend, judge = make_boundary(tmp_path, repository_inventory)
    publish(boundary, credential)
    error = FatalJudgeError("configuration") if fatal else OSError("transient")
    reader = backend.content_reader.return_value
    if failure == "reader":
        backend.content_reader.side_effect = error
    else:
        judge.judge.side_effect = error
    if fatal:
        with pytest.raises(FatalJudgeError):
            boundary.phase = Phase.JUDGE
            asyncio.run(boundary.run())
    else:
        boundary.phase = Phase.JUDGE
        assert asyncio.run(boundary.run()) == 1
    current = saved(boundary).credentials[credential.credential_id]
    assert current.judgment.verdict == ("PENDING" if fatal else "ERROR")
    assert current.extraction is None
    assert reader.aclose.await_count == int(failure == "judge")


def test_extraction_reader_failure_checkpoints_once(
    tmp_path, repository_inventory, credential
):
    boundary, _, backend, _ = make_boundary(tmp_path, repository_inventory)
    valid = credential.model_copy(update={"judgment": JudgmentResult(verdict="VALID")})
    publish(boundary, valid)
    backend.content_reader.side_effect = OSError("content unavailable")
    boundary.workspace.checkpoint.reset_mock()
    boundary.phase = Phase.EXTRACT
    assert asyncio.run(boundary.run()) == 0
    assert boundary.workspace.checkpoint.call_count == 3
    assert all(call.args == (boundary,) for call in boundary.workspace.checkpoint.call_args_list)
    result = saved(boundary).credentials[valid.credential_id]
    assert result.judgment.verdict == "VALID" and result.extraction.status == "ERROR"
