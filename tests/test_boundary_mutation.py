"""Direct mutation and durable checkpoints, using the current service interfaces.

Can run with --noconftest while the legacy shared fixtures are being migrated.
"""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.docker import DockerImageScanScope
from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import ScanBoundaryInventory, ScanTarget, target_id_for
from cred_scan.backend.proto import UnsupportedTitusTargetError
from cred_scan.extract.models import ExtractionResult
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch import global_config
from cred_scan.orch.boundary import Boundary
from cred_scan.orch.credentials import merge_scan
from cred_scan.orch.models import AppConfig, TitusConfig
from cred_scan.scan import titus as titus_module
from cred_scan.scan.models import (
    Credential,
    CredentialOccurrence,
    CredentialsDocument,
    JudgmentResult,
    TitusReport,
)


def inventory():
    repository = ArtifactoryRepository(id="artifactory:primary:repo", name="repo")
    scope = DockerImageScanScope(
        image="registry/repo/image", digest="sha256:old", root_digest="sha256:old",
        platform="linux/amd64", manifest_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return ScanBoundaryInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC), boundary=repository,
        targets=(ScanTarget(
            id=target_id_for(scope), backend_id="primary", boundary=repository, scope=scope,
        ),),
    )


def credential(locator="first"):
    return Credential(
        credential_id="synthetic", credential="synthetic-value",
        occurrences=(CredentialOccurrence(locator=locator),),
    )


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    initial = inventory()
    path = tmp_path / quote(initial.boundary.id, safe="")
    path.mkdir()
    (path / "inventory.json").write_text(initial.model_dump_json())
    backend = Mock()
    backend.inventory = AsyncMock()
    backend.content_reader.return_value = Mock(aclose=AsyncMock())
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", Mock())
    monkeypatch.setattr(boundary_module, "TitusCliScanner", Mock())
    return Boundary(backend, path)


def test_merge_inventory_adopts_discovery_and_reuses_results():
    current, discovered = inventory(), inventory()
    current.targets[0].result.status = "scanned"
    discovered.targets[0].scope.tags = ("new-tag",)
    merged = merge_inventory(current, discovered)
    assert merged is discovered
    assert merged.targets[0].result is current.targets[0].result
    assert merged.targets[0].scope.tags == ("new-tag",)


def test_failed_discovery_preserves_memory_and_disk(boundary):
    before = boundary.inventory.model_dump()
    saved = boundary.paths.inventory.read_bytes()
    discovered = inventory()
    discovered.errors = ("incomplete discovery",)
    boundary.backend.inventory.return_value = discovered
    with pytest.raises(ValueError, match="incomplete inventory discovery"):
        asyncio.run(boundary.refresh_inventory())
    assert boundary.inventory.model_dump() == before
    assert boundary.paths.inventory.read_bytes() == saved


def test_merge_credentials_mutates_history_and_preserves_retained_state():
    old = credential()
    old.judgment = JudgmentResult(verdict="VALID")
    old.extraction = ExtractionResult(status="ERROR", error="retry extraction")
    document = CredentialsDocument(
        boundary_id="repo", report_generated_at="old", credentials={old.credential_id: old},
    )
    candidate = credential("second")
    candidates = CredentialsDocument(
        boundary_id="repo", report_generated_at="new", incomplete=True,
        errors=("partial scan",), credentials={candidate.credential_id: candidate},
    )
    merged = merge_scan(document, candidates)
    assert merged is document
    assert merged.credentials[old.credential_id] is old
    assert old.paths == ("first", "second")
    assert old.judgment.verdict == "VALID"
    assert old.extraction.error == "retry extraction"
    assert merged.report_generated_at == "new"
    assert merged.incomplete and merged.errors == ("partial scan",)
    merge_scan(document, candidates)
    assert old.paths == ("first", "second")
    candidates.credentials.clear()
    merge_scan(document, candidates)
    assert document.credentials[old.credential_id] is old


@pytest.mark.parametrize("stop", ["complete", "cancel", "checkpoint_failure"])
def test_scan_retries_mutate_owned_target_and_recover_from_disk(boundary, monkeypatch, stop):
    target = boundary.inventory.targets[0]
    attempts = []

    async def scan(actual, scratch, datastore):
        assert actual is target
        assert actual.result.status == "running"
        persisted = ScanBoundaryInventory.model_validate_json(boundary.paths.inventory.read_text())
        assert persisted.targets[0].result.status == "running"
        attempts.append(actual)
        if len(attempts) == 1:
            actual.result.status = "failed"
        elif stop == "cancel":
            raise asyncio.CancelledError()
        else:
            actual.result.status = "scanned"
        return actual

    boundary.scanner.scan = AsyncMock(side_effect=scan)
    report = TitusReport(boundary_id=boundary.boundary_id, generated_at="now")
    boundary.scanner.export_report = AsyncMock(return_value=report)
    candidate = credential()
    candidates = CredentialsDocument(
        boundary_id=boundary.boundary_id, report_generated_at="now",
        credentials={candidate.credential_id: candidate},
    )
    monkeypatch.setattr(boundary_module, "deduplicate_report", AsyncMock(return_value=candidates))
    owned_credentials = boundary.credentials
    if stop == "checkpoint_failure":
        write = boundary._write

        def fail(path, document, model_type):
            if path == boundary.paths.inventory and target.result.status == "scanned":
                raise OSError("checkpoint failed")
            return write(path, document, model_type)

        monkeypatch.setattr(boundary, "_write", fail)

    if stop == "complete":
        assert asyncio.run(boundary.scan())
        assert boundary.report is report
        assert boundary.credentials is owned_credentials
        assert boundary.credentials.credentials[candidate.credential_id] is candidate
    else:
        exception = asyncio.CancelledError if stop == "cancel" else OSError
        with pytest.raises(exception):
            asyncio.run(boundary.scan())
        boundary.scanner.export_report.assert_not_awaited()

    assert len(attempts) == 2
    assert not boundary.paths.operation_lock.exists()
    reloaded = Boundary(boundary.backend, boundary.paths.boundary_dir)
    assert reloaded.inventory.targets[0].result.status == (
        "scanned" if stop == "complete" else "running"
    )
    if stop == "complete":
        assert reloaded.credentials.credentials[candidate.credential_id].paths == ("first",)


@pytest.mark.parametrize("outcome", ["success", "unsupported", "launch_error", "transient"])
def test_titus_updates_same_target(tmp_path, monkeypatch, outcome):
    config = AppConfig(
        workspace={"workspace-dir": tmp_path}, titus=TitusConfig(executable="unused"),
        exclusions={"paths": tmp_path / "paths", "credentials": tmp_path / "values"},
        backends=({"name": "artifactory_docker"},),
    )
    monkeypatch.setattr(global_config, "CONFIG", config)
    monkeypatch.setattr(titus_module, "get_exclusions", lambda: Mock(path_file=tmp_path / "paths"))
    selected = inventory()
    target = selected.targets[0]
    target.result.status = "running"
    original_result = target.result
    backend = Mock(titus_scan_arguments=Mock(return_value=("synthetic",)))
    if outcome == "unsupported":
        backend.titus_scan_arguments.side_effect = UnsupportedTitusTargetError("unsupported")

    async def lines():
        if outcome == "transient":
            yield b"connection reset\n"

    code = 1 if outcome == "transient" else 0
    process = Mock(returncode=code, stderr=lines(), wait=AsyncMock(return_value=code))
    spawn = AsyncMock(return_value=process)
    if outcome == "launch_error":
        spawn.side_effect = OSError("launch failed")
    monkeypatch.setattr(titus_module, "_spawn", spawn)
    datastore = tmp_path / "titus.ds"
    datastore.touch()
    scanner = titus_module.TitusCliScanner(selected, backend)
    result = asyncio.run(scanner.scan(target, tmp_path / "scratch", datastore))
    assert result is target
    assert result.result is original_result
    assert result.result.status == ("scanned" if outcome == "success" else "failed")
    assert result.result.retryable == (outcome != "unsupported")
