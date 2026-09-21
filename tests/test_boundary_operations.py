import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.models import BoundaryRecord, ScanTargetInventory
from cred_scan.extract.models import ExtractionResult
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch.boundary import Boundary
from cred_scan.orch.locking import BoundaryBusyError, boundary_lock
from cred_scan.scan.models import (
    Credential,
    CredentialOccurrence,
    CredentialsDocument,
    JudgmentResult,
    TitusReport,
)


def persisted_boundary(tmp_path, *, publication_pending: bool = False):
    reference = ArtifactoryRepository(
        id="artifactory:artifactory_docker:repository",
        name="repository",
    )
    path = tmp_path / quote(reference.id, safe="")
    path.mkdir()
    path.joinpath("boundary.json").write_text(
        BoundaryRecord(
            backend_id="artifactory_docker",
            boundary=reference,
        ).model_dump_json()
    )
    path.joinpath("scantargets.json").write_text(
        ScanTargetInventory(
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            boundary=reference,
            publication_pending=publication_pending,
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
        judgment=JudgmentResult(verdict=verdict),
        extraction=extraction,
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


def test_busy_boundary_rejects_operation_before_starting_services(tmp_path) -> None:
    boundary = persisted_boundary(tmp_path)

    with boundary_lock(boundary.paths.operation_lock):
        with pytest.raises(BoundaryBusyError):
            asyncio.run(boundary.judge())

    boundary.backend.content_reader.assert_not_called()


def test_pending_publication_exports_without_rescanning(tmp_path, monkeypatch) -> None:
    boundary = persisted_boundary(tmp_path, publication_pending=True)
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
    saved = ScanTargetInventory.model_validate_json(
        boundary.paths.scan_targets.read_text()
    )
    assert saved.publication_pending is False
    assert boundary.paths.report.is_file()
    assert boundary.paths.credentials.is_file()
    boundary.backend.content_reader.return_value.aclose.assert_awaited_once()


def test_scan_retries_the_same_mutated_target(
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
    assert seen == [target, target]
    assert target.result.status == "scanned"


def test_judge_selects_work_once_and_returns_attempted_count(
    tmp_path, monkeypatch
) -> None:
    boundary = persisted_boundary(tmp_path)
    write_credentials(
        boundary,
        credential("pending", "PENDING"),
        credential("retry", "ERROR"),
        credential("complete", "VALID"),
    )
    judge = Mock(
        judge=AsyncMock(
            side_effect=[
                JudgmentResult(verdict="VALID"),
                RuntimeError("temporary failure"),
            ]
        )
    )
    install_services(monkeypatch, judge=judge)

    assert asyncio.run(boundary.judge()) == 2

    saved = CredentialsDocument.model_validate_json(
        boundary.paths.credentials.read_text()
    )
    assert saved.credentials["pending"].judgment.verdict == "VALID"
    assert saved.credentials["retry"].judgment.verdict == "ERROR"
    assert saved.credentials["complete"].judgment.verdict == "VALID"
    assert judge.judge.await_count == 2


def test_extract_audits_retained_evidence_without_pending_work(
    tmp_path, monkeypatch
) -> None:
    boundary = persisted_boundary(tmp_path)
    retained = ExtractionResult(
        status="RETAINED",
        output_path="evidence/retained/app.env",
        size=6,
        sha256="synthetic",
    )
    write_credentials(
        boundary,
        credential("retained", "VALID", retained),
        credential("ineligible", "INVALID"),
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
    boundary = persisted_boundary(tmp_path)
    write_credentials(
        boundary,
        credential("valid", "VALID"),
        credential("unknown", "UNKNOWN"),
        credential("invalid", "INVALID"),
    )
    extractor = Mock(
        extract=AsyncMock(
            side_effect=[
                ExtractionResult(
                    status="RETAINED",
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
    assert saved.credentials["valid"].extraction.status == "RETAINED"
    assert saved.credentials["unknown"].extraction.status == "ERROR"
    assert saved.credentials["invalid"].extraction is None
