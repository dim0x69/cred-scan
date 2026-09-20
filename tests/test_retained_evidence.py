"""Extraction checks retained files even when no new extraction is pending."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.models import ContentLocation, ContentRead, ScanBoundaryInventory
from cred_scan.extract import evidence as evidence_module
from cred_scan.extract.evidence import evidence_path
from cred_scan.extract.models import ExtractionResult
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch.boundary import Boundary
from cred_scan.scan.models import Credential, CredentialOccurrence, CredentialsDocument


@pytest.mark.parametrize("file_state", ["present", "missing", "directory"])
@pytest.mark.parametrize("verdict", ["VALID", "UNKNOWN", "INVALID"])
def test_retained_file_check_preserves_history(
    tmp_path, monkeypatch, caplog, file_state, verdict
):
    repository = ArtifactoryRepository(id="artifactory:primary:repo", name="repo")
    boundary_dir = tmp_path / quote(repository.id, safe="")
    boundary_dir.mkdir()
    inventory = ScanBoundaryInventory(
        generated_at=datetime.now(UTC), boundary=repository,
    )
    (boundary_dir / "inventory.json").write_text(inventory.model_dump_json())
    destination = evidence_path(boundary_dir, "credential", "app.env")
    if file_state == "present":
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"different contents from original evidence")
    elif file_state == "directory":
        destination.mkdir(parents=True)
    credential = Credential(
        credential_id="credential",
        occurrences=(CredentialOccurrence(locator="synthetic-location"),),
        judgment={"verdict": verdict},
        extraction=ExtractionResult(
            status="RETAINED", output_path="evidence/credential/app.env",
            size=1, sha256="old-digest",
        ),
    )
    document = CredentialsDocument(
        boundary_id=repository.id, report_generated_at="now",
        credentials={credential.credential_id: credential},
    )
    document_path = boundary_dir / "credentials.json"
    document_path.write_text(document.model_dump_json())
    before = document_path.read_bytes()
    reader = Mock(aclose=AsyncMock())
    reader.resolve_location = AsyncMock()
    reader.read = AsyncMock()
    backend = Mock()
    backend.content_reader.return_value = reader
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", Mock())
    monkeypatch.setattr(boundary_module, "TitusCliScanner", Mock())
    boundary = Boundary(backend, boundary_dir)
    boundary.extractor.extract = AsyncMock()

    def forbid_read(*args, **kwargs):
        raise AssertionError("retained evidence must not be read")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(type(destination), "read_bytes", forbid_read)
            assert boundary.needs_extract()
            assert asyncio.run(boundary.extract()) == 0
        assert document_path.read_bytes() == before
        assert boundary.credentials == document
        reader.resolve_location.assert_not_awaited()
        reader.read.assert_not_awaited()
        boundary.extractor.extract.assert_not_awaited()
        if file_state == "present":
            assert "retained evidence missing" not in caplog.text
            assert destination.read_bytes() == b"different contents from original evidence"
        else:
            assert "retained evidence missing" in caplog.text
            assert repository.id in caplog.text
            assert "evidence/credential/app.env" in caplog.text
            assert not destination.is_file()
    finally:
        asyncio.run(boundary.aclose())


@pytest.fixture
def extraction_boundary(tmp_path, monkeypatch):
    repository = ArtifactoryRepository(id="artifactory:primary:repo", name="repo")
    path = tmp_path / quote(repository.id, safe="")
    path.mkdir()
    inventory = ScanBoundaryInventory(generated_at=datetime.now(UTC), boundary=repository)
    (path / "inventory.json").write_text(inventory.model_dump_json())
    reader = Mock(aclose=AsyncMock())
    reader.resolve_location = AsyncMock(return_value=ContentLocation(
        locator="first", source_path="app.env", filename="app.env",
    ))
    reader.read = AsyncMock(return_value=ContentRead(
        content=b"synthetic evidence", source_path="app.env", filename="app.env",
    ))
    backend = Mock(content_reader=Mock(return_value=reader))
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", Mock())
    monkeypatch.setattr(boundary_module, "TitusCliScanner", Mock())
    boundary = Boundary(backend, path)
    boundary.credentials.credentials["credential"] = Credential(
        credential_id="credential",
        occurrences=(CredentialOccurrence(locator="first"), CredentialOccurrence(locator="second")),
    )
    boundary._has_credentials = True
    yield boundary
    asyncio.run(boundary.aclose())


@pytest.mark.parametrize("verdict", ["VALID", "UNKNOWN", "INVALID", "PENDING", "ERROR"])
@pytest.mark.parametrize("previous_error", [False, True])
def test_new_extraction_eligibility_and_persistence(extraction_boundary, verdict, previous_error):
    boundary = extraction_boundary
    credential = boundary.credentials.credentials["credential"]
    credential.judgment.verdict = verdict
    credential.judgment.reasoning = "saved reasoning"
    if previous_error:
        credential.extraction = ExtractionResult(status="ERROR", error="previous failure")
    judgment = credential.judgment.model_dump()
    eligible = verdict in {"VALID", "UNKNOWN"}
    assert boundary.needs_extract() == eligible
    assert asyncio.run(boundary.extract()) == int(eligible)
    assert credential.judgment.model_dump() == judgment
    if eligible:
        saved = CredentialsDocument.model_validate_json(boundary.paths.credentials.read_text())
        result = saved.credentials["credential"]
        assert result.judgment.model_dump() == judgment
        assert result.extraction.status == "RETAINED"
        assert (boundary.paths.boundary_dir / result.extraction.output_path).read_bytes() == b"synthetic evidence"
        boundary.reader.resolve_location.assert_awaited_once_with("first")
        boundary.reader.read.assert_awaited_once()
    else:
        boundary.reader.resolve_location.assert_not_awaited()
        boundary.reader.read.assert_not_awaited()
        assert not boundary.paths.credentials.exists()


@pytest.mark.parametrize("verdict", ["VALID", "UNKNOWN"])
@pytest.mark.parametrize("failure", ["read", "write"])
def test_extraction_failure_preserves_judgment_and_retries_after_reload(
    extraction_boundary, monkeypatch, verdict, failure
):
    boundary = extraction_boundary
    credential = boundary.credentials.credentials["credential"]
    credential.judgment.verdict = verdict
    credential.judgment.reasoning = "saved reasoning"
    judgment = credential.judgment.model_dump()
    with monkeypatch.context() as patch:
        failing = AsyncMock(side_effect=OSError("source unavailable"))
        if failure == "read":
            patch.setattr(boundary.reader, "read", failing)
        else:
            patch.setattr(evidence_module, "retain_first_evidence", failing)
        assert asyncio.run(boundary.extract()) == 0
    saved = CredentialsDocument.model_validate_json(boundary.paths.credentials.read_text())
    assert saved.credentials["credential"].judgment.model_dump() == judgment
    assert saved.credentials["credential"].extraction.status == "ERROR"
    assert credential.judgment.model_dump() == judgment

    reloaded = Boundary(boundary.backend, boundary.paths.boundary_dir)
    try:
        assert not reloaded.needs_judge()
        assert reloaded.needs_extract()
        assert asyncio.run(reloaded.extract()) == 1
        saved = CredentialsDocument.model_validate_json(reloaded.paths.credentials.read_text())
        assert saved.credentials["credential"].judgment.model_dump() == judgment
        assert saved.credentials["credential"].extraction.status == "RETAINED"
    finally:
        asyncio.run(reloaded.aclose())
