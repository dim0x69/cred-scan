import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.models import BoundaryRecord, ScanTargetInventory
from cred_scan.extract.models import ExtractionResult
from cred_scan.orch import global_config
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch.boundary import Boundary
from cred_scan.orch.workspace import Workspace
from cred_scan.scan.models import (
    Credential,
    CredentialOccurrence,
    CredentialsDocument,
    JudgmentResult,
    TitusReport,
)


def persisted_boundary(tmp_path, *, phase="scan", name="repository"):
    reference = ArtifactoryRepository(
        id=f"artifactory:artifactory_docker:{name}",
        name=name,
    )
    path = tmp_path / quote(reference.id, safe="")
    path.mkdir()
    path.joinpath("boundary.json").write_text(
        BoundaryRecord(
            backend_id="artifactory_docker",
            phase=phase,
            boundary=reference,
        ).model_dump_json()
    )
    path.joinpath("scantargets.json").write_text(
        ScanTargetInventory(
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            boundary=reference,
        ).model_dump_json()
    )
    if phase != "scan":
        path.joinpath("report.json").write_text(
            TitusReport(
                boundary_id=reference.id, generated_at="2026-01-01T00:00:00+00:00"
            ).model_dump_json()
        )
    backend = Mock()
    backend.name = "artifactory_docker"
    backend.content_reader.return_value = Mock(aclose=AsyncMock())
    return Boundary(backend, path)


def credential(
    credential_id: str,
    verdict: str,
    extraction: ExtractionResult | None = None,
) -> Credential:
    return Credential(
        credential_id=credential_id,
        occurrences=(CredentialOccurrence(locator=f"source:{credential_id}"),),
        judgment=(
            JudgmentResult()
            if verdict == "pending"
            else JudgmentResult(status="failed", error="previous failure")
            if verdict == "failed"
            else JudgmentResult(status="completed", verdict=verdict)
        ),
        extraction=extraction or ExtractionResult(),
    )


def write_credentials(boundary: Boundary, *credentials: Credential) -> None:
    boundary.paths.credentials.write_text(
        CredentialsDocument(
            boundary_id=boundary.boundary_id,
            report_generated_at="2026-01-01T00:00:00+00:00",
            credentials={item.credential_id: item for item in credentials},
        ).model_dump_json()
    )


def install_services(monkeypatch, *, judge=None, extractor=None) -> None:
    monkeypatch.setattr(boundary_module, "TitusCliScanner", Mock())
    monkeypatch.setattr(
        boundary_module,
        "DspyFindingJudge",
        Mock(return_value=judge or Mock()),
    )
    monkeypatch.setattr(
        boundary_module,
        "EvidenceExtractor",
        Mock(return_value=extractor or Mock()),
    )


def test_upstream_phase_is_not_loaded_or_started(tmp_path, monkeypatch):
    boundary = persisted_boundary(tmp_path)
    boundary.paths.credentials.write_text("invalid JSON must not be read")
    assert asyncio.run(boundary.judge(failed=True)) == 0
    assert asyncio.run(boundary.extract(failed=True)) == 0
    boundary.backend.content_reader.assert_not_called()


def test_pending_publication_exports_without_rescanning(tmp_path, monkeypatch) -> None:
    boundary = persisted_boundary(tmp_path)
    boundary.paths.datastore.touch()
    scanner = Mock(scan=AsyncMock())
    scanner.export_report = AsyncMock(
        return_value=TitusReport(
            boundary_id=boundary.boundary_id,
            generated_at="2026-01-01T00:00:00+00:00",
        )
    )
    monkeypatch.setattr(
        boundary_module,
        "TitusCliScanner",
        Mock(return_value=scanner),
    )
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", Mock())
    monkeypatch.setattr(boundary_module, "EvidenceExtractor", Mock())
    deduplicate = AsyncMock(
        return_value=CredentialsDocument(
            boundary_id=boundary.boundary_id,
            report_generated_at="2026-01-01T00:00:00+00:00",
        )
    )
    monkeypatch.setattr(boundary_module, "deduplicate_report", deduplicate)

    assert asyncio.run(boundary.scan()) is True

    scanner.scan.assert_not_awaited()
    scanner.export_report.assert_awaited_once_with(boundary.paths.datastore)
    assert phase_of(boundary) == "judge"
    assert boundary.paths.report.is_file()
    assert boundary.paths.credentials.is_file()
    boundary.backend.content_reader.return_value.aclose.assert_awaited_once()


def test_boundary_calls_scanner_once_with_owned_target(
    tmp_path, repository_inventory
) -> None:
    boundary = Boundary(Mock(), tmp_path / "boundary")
    target = repository_inventory.targets[0]
    seen = []

    async def scan(candidate, *_args):
        seen.append(candidate)
        candidate.result.status = "failed" if len(seen) == 1 else "scanned"

    boundary.scanner = Mock(scan=AsyncMock(side_effect=scan))

    assert asyncio.run(boundary._scan_target(target)) is None
    assert seen == [target]
    assert target.result.status == "failed"


def test_judge_selects_work_once_and_returns_attempted_count(
    tmp_path, monkeypatch
) -> None:
    boundary = persisted_boundary(tmp_path, phase="judge")
    write_credentials(
        boundary,
        credential("pending", "pending"),
        credential("retry", "failed"),
        credential("complete", "valid"),
    )
    judge = Mock(
        judge=AsyncMock(
            side_effect=[
                JudgmentResult(status="completed", verdict="valid"),
                RuntimeError("temporary failure"),
            ]
        )
    )
    install_services(monkeypatch, judge=judge)

    assert asyncio.run(boundary.judge(failed=True)) == 2

    saved = CredentialsDocument.model_validate_json(
        boundary.paths.credentials.read_text()
    )
    assert saved.credentials["pending"].judgment.verdict == "valid"
    assert saved.credentials["retry"].judgment.status == "failed"
    assert saved.credentials["complete"].judgment.verdict == "valid"
    assert judge.judge.await_count == 2


def test_extract_audits_retained_evidence_without_pending_work(
    tmp_path, monkeypatch
) -> None:
    boundary = persisted_boundary(tmp_path, phase="done")
    retained = ExtractionResult(
        status="retained",
        output_path="evidence/retained/app.env",
        size=6,
        sha256="synthetic",
    )
    write_credentials(
        boundary,
        credential("retained", "valid", retained),
        credential("ineligible", "invalid"),
    )
    extractor = Mock(extract=AsyncMock())
    install_services(monkeypatch, extractor=extractor)
    evidence = Mock(return_value=False)
    monkeypatch.setattr(boundary_module, "evidence_exists", evidence)

    assert asyncio.run(boundary.extract()) == 0

    evidence.assert_called_once()
    extractor.extract.assert_not_awaited()


def test_extract_returns_selected_count_including_handled_failures(
    tmp_path, monkeypatch
) -> None:
    boundary = persisted_boundary(tmp_path, phase="extract")
    write_credentials(
        boundary,
        credential("valid", "valid"),
        credential("unknown", "unknown"),
        credential("invalid", "invalid"),
    )
    extractor = Mock(
        extract=AsyncMock(
            side_effect=[
                ExtractionResult(
                    status="retained",
                    output_path="evidence/valid/app.env",
                    size=6,
                    sha256="synthetic",
                ),
                RuntimeError("read failed"),
            ]
        )
    )
    install_services(monkeypatch, extractor=extractor)

    assert asyncio.run(boundary.extract()) == 2

    saved = CredentialsDocument.model_validate_json(
        boundary.paths.credentials.read_text()
    )
    assert saved.credentials["valid"].extraction.status == "retained"
    assert saved.credentials["unknown"].extraction.status == "failed"
    assert saved.credentials["invalid"].extraction.status == "skipped"


def phase_of(boundary):
    return BoundaryRecord.model_validate_json(boundary.paths.record.read_text()).phase


@pytest.mark.parametrize("failure_at", ["credentials", "cleanup", "phase", None])
def test_handoff_is_final_write_and_failure_keeps_upstream_phase(
    tmp_path, monkeypatch, failure_at
):
    boundary = persisted_boundary(tmp_path, phase="judge")
    original = credential(
        "new", "pending", ExtractionResult(status="skipped", reason="earlier")
    )
    write_credentials(boundary, original)
    install_services(
        monkeypatch,
        judge=Mock(
            judge=AsyncMock(
                return_value=JudgmentResult(status="completed", verdict="valid")
            )
        ),
    )
    events = []
    write = boundary._write

    def observe(path, document, model):
        events.append(path.name)
        if failure_at == "credentials" and path == boundary.paths.credentials:
            raise OSError("disk unavailable")
        if failure_at == "phase" and path == boundary.paths.record:
            raise OSError("phase unavailable")
        write(path, document, model)

    async def close():
        events.append("cleanup")
        assert phase_of(boundary) == "judge"
        if failure_at == "cleanup":
            raise OSError("cleanup failed")

    monkeypatch.setattr(boundary, "_write", observe)
    boundary.backend.content_reader.return_value.aclose.side_effect = close
    if failure_at:
        with pytest.raises(OSError):
            asyncio.run(boundary.judge())
        assert phase_of(boundary) == "judge"
    else:
        assert asyncio.run(boundary.judge()) == 1
        assert phase_of(boundary) == "extract"
        assert events[-2:] == ["cleanup", "boundary.json"]
        saved = CredentialsDocument.model_validate_json(
            boundary.paths.credentials.read_text()
        )
        assert saved.credentials["new"].extraction == original.extraction


@pytest.mark.parametrize("failed", [False, True])
def test_judgment_retry_reopens_done_only_explicitly(tmp_path, monkeypatch, failed):
    boundary = persisted_boundary(tmp_path, phase="done")
    write_credentials(
        boundary, credential("failure", "failed"), credential("complete", "unknown")
    )
    judge = Mock(judge=AsyncMock(side_effect=RuntimeError("still failing")))
    install_services(monkeypatch, judge=judge)
    assert asyncio.run(boundary.judge(failed=failed)) == int(failed)
    assert judge.judge.await_count == int(failed)
    assert phase_of(boundary) == ("extract" if failed else "done")
    saved = CredentialsDocument.model_validate_json(
        boundary.paths.credentials.read_text()
    )
    assert saved.credentials["failure"].judgment.status == "failed"
    assert saved.credentials["complete"].judgment.verdict == "unknown"


@pytest.mark.parametrize("failed", [False, True])
def test_extraction_retry_preserves_judgment_and_skips_completed_items(
    tmp_path, monkeypatch, failed
):
    boundary = persisted_boundary(tmp_path, phase="done")
    write_credentials(
        boundary,
        credential("failure", "valid", ExtractionResult(status="failed", error="old")),
        credential(
            "skipped", "valid", ExtractionResult(status="skipped", reason="earlier")
        ),
    )
    extractor = Mock(extract=AsyncMock(side_effect=RuntimeError("still failing")))
    install_services(monkeypatch, extractor=extractor)
    before = boundary.paths.credentials.read_bytes()
    assert asyncio.run(boundary.extract(failed=failed)) == int(failed)
    assert extractor.extract.await_count == int(failed)
    assert phase_of(boundary) == "done"
    saved = CredentialsDocument.model_validate_json(
        boundary.paths.credentials.read_text()
    )
    assert saved.credentials["failure"].judgment.verdict == "valid"
    assert saved.credentials["skipped"].extraction.status == "skipped"
    if not failed:
        assert boundary.paths.credentials.read_bytes() == before
        boundary.backend.content_reader.assert_not_called()


@pytest.mark.parametrize("failed", [False, True])
def test_scan_recovery_skips_saved_failure_unless_explicit(
    tmp_path, monkeypatch, repository_inventory, failed
):
    boundary = persisted_boundary(tmp_path)
    repository_inventory.boundary = boundary._read(boundary.paths.record, BoundaryRecord).boundary
    repository_inventory.targets[0].result.status = "failed"
    boundary.paths.scan_targets.write_text(repository_inventory.model_dump_json())
    boundary.paths.datastore.touch()
    scanner = Mock(
        scan=AsyncMock(),
        export_report=AsyncMock(
            return_value=TitusReport(
                boundary_id=boundary.boundary_id, generated_at="now"
            )
        ),
    )

    async def scan(target, *_):
        target.result.status = "failed"

    scanner.scan.side_effect = scan
    install_services(monkeypatch)
    monkeypatch.setattr(boundary_module, "TitusCliScanner", Mock(return_value=scanner))
    monkeypatch.setattr(
        boundary_module,
        "deduplicate_report",
        AsyncMock(
            return_value=CredentialsDocument(
                boundary_id=boundary.boundary_id,
                report_generated_at="now",
                credentials={"finding": credential("finding", "pending")},
            )
        ),
    )
    assert asyncio.run(boundary.scan(failed=failed))
    assert scanner.scan.await_count == int(failed)
    assert phase_of(boundary) == "judge"
    assert (
        "finding"
        in CredentialsDocument.model_validate_json(
            boundary.paths.credentials.read_text()
        ).credentials
    )


def test_empty_boundary_completes_all_stages(tmp_path, monkeypatch, app_config):
    monkeypatch.setattr(global_config, "CONFIG", app_config)
    boundary = persisted_boundary(tmp_path)
    install_services(monkeypatch)

    async def scenario():
        assert await boundary.scan()
        assert phase_of(boundary) == "judge"
        assert await boundary.judge() == 0
        assert phase_of(boundary) == "extract"
        assert await boundary.extract() == 0
        assert phase_of(boundary) == "done"

    asyncio.run(scenario())


def test_done_audit_never_rewrites_missing_evidence(tmp_path, monkeypatch):
    boundary = persisted_boundary(tmp_path, phase="done")
    write_credentials(
        boundary,
        credential(
            "retained",
            "valid",
            ExtractionResult(
                status="retained", output_path="evidence/missing", size=1, sha256="abc"
            ),
        ),
    )
    original = {p: p.read_bytes() for p in boundary.paths.boundary_dir.iterdir()}
    asyncio.run(boundary.extract())
    assert {
        p: p.read_bytes() for p in boundary.paths.boundary_dir.iterdir()
    } == original
    boundary.backend.content_reader.assert_not_called()


def test_different_stages_overlap_without_picking_up_newly_ready_boundaries(
    tmp_path, monkeypatch, app_config
):
    monkeypatch.setattr(global_config, "CONFIG", app_config)
    backend_dir = tmp_path / "artifactory_docker"
    root = backend_dir / "boundaries"
    root.mkdir(parents=True)
    scanning = persisted_boundary(root, name="scanning")
    ready = persisted_boundary(root, name="ready", phase="judge")
    write_credentials(ready, credential("ready", "pending"))
    backend = scanning.backend
    backend.aclose = AsyncMock()
    # Independent workspace/Boundary instances simulate each command's loaded state.
    scan_workspace = Workspace(backend, backend_dir, create=True)
    judge_workspace = Workspace(backend, backend_dir, create=True)
    original_scan = Boundary._scan

    async def scenario():
        scan_started, judge_started = asyncio.Event(), asyncio.Event()
        release_scan, release_judge = asyncio.Event(), asyncio.Event()

        async def slow_scan(boundary):
            scan_started.set()
            await release_scan.wait()
            await original_scan(boundary)

        async def slow_judge(*_):
            judge_started.set()
            await release_judge.wait()
            return JudgmentResult(status="completed", verdict="valid")

        install_services(
            monkeypatch, judge=Mock(judge=AsyncMock(side_effect=slow_judge))
        )
        monkeypatch.setattr(Boundary, "_scan", slow_scan)
        scan_task = asyncio.create_task(scan_workspace.scan())
        await scan_started.wait()
        judge_task = asyncio.create_task(judge_workspace.judge())
        await judge_started.wait()
        assert phase_of(scanning) == "scan"
        assert phase_of(ready) == "judge"
        release_scan.set()
        assert await scan_task == 1
        assert phase_of(scanning) == "judge"
        assert not judge_task.done()
        release_judge.set()
        assert await judge_task == 1
        assert phase_of(ready) == "extract"
        # Newly ready boundary was excluded from the already-running judge batch.
        assert phase_of(scanning) == "judge"
        await scan_workspace.close()
        await judge_workspace.close()

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize("phase", ["judge", "extract", "done"])
def test_published_phase_requires_documents(tmp_path, phase):
    boundary = persisted_boundary(tmp_path, phase=phase)
    with pytest.raises(ValueError, match="requires published"):
        asyncio.run(getattr(boundary, "extract" if phase == "done" else phase)())
    boundary.backend.content_reader.assert_not_called()


@pytest.mark.parametrize("change", ["same", "changed", "absent", "restored"])
def test_inventory_phase_policy(tmp_path, repository_inventory, change):
    boundary = persisted_boundary(tmp_path, phase="done")
    reference = boundary._read(boundary.paths.record, BoundaryRecord).boundary
    repository_inventory.boundary = reference
    if change == "restored":
        record = boundary._read(boundary.paths.record, BoundaryRecord)
        record.availability = "absent"
        boundary.paths.record.write_text(record.model_dump_json())
        boundary.paths.scan_targets.unlink()
    if change in {"same", "restored"}:
        repository_inventory.targets = ()
    boundary.backend.inventory = AsyncMock(
        return_value=None if change == "absent" else repository_inventory
    )
    assert asyncio.run(boundary.refresh_inventory())
    assert phase_of(boundary) == ("done" if change in {"same", "absent"} else "scan")
    assert boundary.paths.scan_targets.exists() == (change != "absent")


def test_inventory_revokes_downstream_phase_before_writing_changed_targets(
    tmp_path, repository_inventory, monkeypatch
):
    boundary = persisted_boundary(tmp_path, phase="done")
    repository_inventory.boundary = boundary._read(boundary.paths.record, BoundaryRecord).boundary
    boundary.backend.inventory = AsyncMock(return_value=repository_inventory)
    original_targets = boundary.paths.scan_targets.read_bytes()
    original_write = boundary._write

    def fail_targets(path, document, model):
        if path == boundary.paths.scan_targets:
            assert phase_of(boundary) == "scan"
            raise OSError("inventory write failed")
        original_write(path, document, model)

    monkeypatch.setattr(boundary, "_write", fail_targets)
    with pytest.raises(OSError, match="inventory write failed"):
        asyncio.run(boundary.refresh_inventory())
    assert phase_of(boundary) == "scan"
    assert boundary.paths.scan_targets.read_bytes() == original_targets
