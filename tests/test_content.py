import asyncio
import io
import json
import tarfile
import threading
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from cred_scan.backend.adapters.artifactory import docker
from cred_scan.backend.adapters.artifactory.docker import (
    ArtifactoryDockerReader,
    LayerEvidenceError,
)
from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import (
    ArtifactoryBackendConfig,
    ArtifactoryRepository,
    DockerImageScanScope,
    ScanBoundaryInventory,
    target_id_for,
)
from cred_scan.common.models import WorkspaceConfig
from cred_scan.common.workspace import Workspace
from cred_scan.scan.credentials import deduplicate_report
from cred_scan.scan.models import ExclusionPolicy, TitusReport


PROVENANCE = (
    "docker://registry/docker-local/team/api@sha256:manifest/sha256:layer:etc/app.env"
)
COLON_PROVENANCE = (
    "docker://registry/docker-local/team/api@sha256:manifest/"
    "sha256:layer:etc/app:prod.env"
)


@pytest.fixture
def backend(tmp_path: Path):
    backend = docker.ArtifactoryDockerBackend(
        ArtifactoryBackendConfig(name="primary", base_url="https://example.invalid"),
        "synthetic-token",
        workspace=Workspace(
            WorkspaceConfig(workspace_dir=tmp_path, results_dir=tmp_path / "results")
        ),
        max_directory_entries=5,
    )
    yield backend
    asyncio.run(backend.aclose())


def test_backend_provides_titus_arguments(
    backend, repository_inventory: ScanBoundaryInventory
) -> None:
    target = repository_inventory.targets[0]
    assert isinstance(target.scope, DockerImageScanScope)
    assert backend.titus_scan_arguments(repository_inventory, target) == (
        "--docker",
        "--artifactory-repository",
        repository_inventory.boundary.name,
        f"{target.scope.image}@{target.scope.digest}",
    )


def test_reader_resolves_colon_filename_without_losing_prefix(
    backend, repository_inventory: ScanBoundaryInventory
) -> None:
    reader = backend.content_reader(
        repository_inventory.boundary, repository_inventory.targets
    )
    resolved = asyncio.run(reader.resolve_provenance(COLON_PROVENANCE))
    assert resolved.target_id == repository_inventory.targets[0].id
    assert resolved.source_path == "etc/app:prod.env"
    assert resolved.filename == "app:prod.env"
    asyncio.run(reader.aclose())


def test_new_root_index_with_same_child_manifest_reuses_resolvable_target(
    backend, repository_inventory
):
    original = repository_inventory.targets[0]
    original.result.status = "scanned"
    scope = original.scope.model_copy(update={"root_digest": "sha256:new-root"})
    fresh = original.model_copy(update={"id": target_id_for(scope), "scope": scope})
    discovered = repository_inventory.model_copy(update={"targets": (fresh,)})
    merged = merge_inventory(repository_inventory, discovered)
    assert merged.targets == (original,)
    assert backend.titus_scan_arguments(merged, fresh) == backend.titus_scan_arguments(
        merged, original
    )
    reader = backend.content_reader(merged.boundary, merged.targets)
    try:
        resolved = asyncio.run(reader.resolve_provenance(PROVENANCE))
        assert resolved.target_id == original.id
    finally:
        asyncio.run(reader.aclose())


def test_cumulative_report_resolves_current_and_superseded_docker_pins(
    backend, repository_inventory
):
    original = repository_inventory.targets[0]
    scope = original.scope.model_copy(update={"digest": "sha256:new-manifest"})
    fresh = original.model_copy(update={"id": target_id_for(scope), "scope": scope})
    discovered = repository_inventory.model_copy(update={"targets": (fresh,)})
    merged = merge_inventory(repository_inventory, discovered)
    assert merged.targets[0].lifecycle == "superseded"
    report = TitusReport(
        boundary_id=merged.boundary.id,
        generated_at="now",
        findings=tuple(
            {
                "ID": f"finding-{index}",
                "RuleID": "np.github.1",
                "Groups": ["c2VjcmV0"],
                "Matches": [{"file_path": path}],
            }
            for index, path in enumerate(
                (
                    PROVENANCE,
                    PROVENANCE.replace("sha256:manifest", "sha256:new-manifest"),
                )
            )
        ),
    )
    reader = backend.content_reader(merged.boundary, merged.targets)
    try:
        document = asyncio.run(
            deduplicate_report(
                report, merged, ExclusionPolicy(path_file="unused"), reader
            )
        )
        credential = next(iter(document.credentials.values()))
        assert [occurrence.target_id for occurrence in credential.occurrences] == [
            original.id,
            fresh.id,
        ]
    finally:
        asyncio.run(reader.aclose())


def test_reader_reuses_complete_bytes_for_evidence(
    tmp_path: Path, backend, repository_inventory: ScanBoundaryInventory
) -> None:
    reader = backend.content_reader(
        repository_inventory.boundary, repository_inventory.targets
    )
    assert reader.max_directory_entries == 5
    retrieved = b"A" * 512_001
    reader._cache[PROVENANCE] = retrieved

    content = asyncio.run(reader.read_file(PROVENANCE))
    destination = tmp_path / "evidence.bin"
    asyncio.run(reader.extract_file(PROVENANCE, destination))

    assert content.content == retrieved.decode("utf-8")
    assert destination.read_bytes() == retrieved
    asyncio.run(reader.aclose())
    assert not reader._cache


def test_direct_reader_creation_requires_target_context(
    backend, repository_inventory: ScanBoundaryInventory
) -> None:
    with pytest.raises(ValueError, match="at least one target"):
        backend.content_reader(repository_inventory.boundary, ())
    with pytest.raises(ValueError, match="must belong to the boundary"):
        backend.content_reader(
            ArtifactoryRepository(id="other", name="other"),
            repository_inventory.targets,
        )


def test_reader_validates_provenance_even_for_cached_bytes(
    backend, repository_inventory: ScanBoundaryInventory
) -> None:
    reader = backend.content_reader(
        repository_inventory.boundary, repository_inventory.targets
    )
    unpinned = PROVENANCE.replace("sha256:manifest", "sha256:other")
    reader._cache[unpinned] = b"untrusted"
    with pytest.raises(LayerEvidenceError, match="pinned target"):
        asyncio.run(reader.read_file(unpinned))
    asyncio.run(reader.aclose())


def _layer_bytes(
    content: bytes = b"SECRET=from-layer\n", path: str = "etc/app.env"
) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo(path)
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def test_reader_rejects_unmapped_layer_instead_of_searching_other_layers(
    repository_inventory: ScanBoundaryInventory, tmp_path: Path
) -> None:
    older = _layer_bytes(b"SECRET=older\n")
    newer = _layer_bytes(b"SECRET=newer\n")
    manifest = {
        "config": {"digest": "sha256:config"},
        "layers": [
            {"digest": "sha256:older"},
            {"digest": "sha256:newer"},
        ],
    }
    config = {"rootfs": {"diff_ids": ["sha256:unrelated", "sha256:other"]}}
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path.endswith("/manifests/sha256:manifest"):
            return httpx.Response(200, json=manifest)
        if request.url.path.endswith("/blobs/sha256:config"):
            return httpx.Response(200, content=json.dumps(config).encode())
        if request.url.path.endswith("/blobs/sha256:older"):
            return httpx.Response(200, content=older)
        if request.url.path.endswith("/blobs/sha256:newer"):
            return httpx.Response(200, content=newer)
        raise AssertionError(f"unexpected request: {request.url}")

    workspace = Workspace(
        WorkspaceConfig(workspace_dir=tmp_path, results_dir=tmp_path / "results")
    )
    backend = docker.ArtifactoryDockerBackend(
        ArtifactoryBackendConfig(name="primary", base_url="https://example.invalid"),
        "synthetic-token",
        workspace=workspace,
    )

    async def replace_session() -> None:
        await backend.session.aclose()
        backend.session = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={
                "User-Agent": "cred-scan/0.1",
                "X-JFrog-Art-Api": "synthetic-token",
            },
            follow_redirects=True,
            timeout=120,
            trust_env=False,
        )

    asyncio.run(replace_session())
    reader = ArtifactoryDockerReader(
        backend,
        repository_inventory.boundary,
        repository_inventory.targets,
        workspace=workspace,
    )
    unmapped = PROVENANCE.replace("sha256:layer", "sha256:missing")
    try:
        with pytest.raises(LayerEvidenceError, match="requested Docker layer"):
            asyncio.run(reader.read_file(unmapped))
        assert not any(path.endswith("/blobs/sha256:older") for path in requests)
        assert not any(path.endswith("/blobs/sha256:newer") for path in requests)
    finally:
        asyncio.run(reader.aclose())
        asyncio.run(backend.aclose())


def test_async_reader_returns_complete_files_and_uses_workspace_scratch(
    repository_inventory: ScanBoundaryInventory, tmp_path: Path
) -> None:
    layer_content = b"A" * 512_001
    layer = _layer_bytes(layer_content)
    manifest = {
        "config": {"digest": "sha256:config"},
        "layers": [{"digest": "sha256:layer"}],
    }
    config = {"rootfs": {"diff_ids": ["sha256:layer"]}}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/sha256:manifest"):
            return httpx.Response(200, json=manifest)
        if request.url.path.endswith("/blobs/sha256:config"):
            return httpx.Response(200, content=json.dumps(config).encode())
        if request.url.path.endswith("/blobs/sha256:layer"):
            return httpx.Response(200, content=layer)
        raise AssertionError(f"unexpected request: {request.url}")

    workspace = Workspace(
        WorkspaceConfig(workspace_dir=tmp_path, results_dir=tmp_path / "results")
    )
    backend = docker.ArtifactoryDockerBackend(
        ArtifactoryBackendConfig(name="primary", base_url="https://example.invalid"),
        "synthetic-token",
        workspace=workspace,
    )

    async def replace_session() -> None:
        await backend.session.aclose()
        backend.session = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={
                "User-Agent": "cred-scan/0.1",
                "X-JFrog-Art-Api": "synthetic-token",
            },
            follow_redirects=True,
            timeout=120,
            trust_env=False,
        )

    asyncio.run(replace_session())
    reader = ArtifactoryDockerReader(
        backend,
        repository_inventory.boundary,
        repository_inventory.targets,
        workspace=workspace,
    )
    try:
        content = asyncio.run(reader.read_file(PROVENANCE))
        files = asyncio.run(
            reader.list_files(PROVENANCE.replace(":etc/app.env", ":etc"))
        )
        listed_content = asyncio.run(reader.read_file(files[0]))
        assert content.content == layer_content.decode("utf-8")
        assert files == (PROVENANCE,)
        assert listed_content.path == files[0]
        assert listed_content.content == layer_content.decode("utf-8")
    finally:
        asyncio.run(reader.aclose())
        asyncio.run(backend.aclose())

    scratch_parent = workspace.boundary(repository_inventory.boundary.id).scratch_parent
    assert not scratch_parent.exists()


def test_listed_locators_preserve_the_selected_layer(
    repository_inventory: ScanBoundaryInventory, tmp_path: Path
) -> None:
    older = _layer_bytes(b"SECRET=older\n")
    newer = _layer_bytes(b"SECRET=newer\n")
    manifest = {
        "config": {"digest": "sha256:config"},
        "layers": [
            {"digest": "sha256:older"},
            {"digest": "sha256:newer"},
        ],
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/manifests/sha256:manifest"):
            return httpx.Response(200, json=manifest)
        if request.url.path.endswith("/blobs/sha256:older"):
            return httpx.Response(200, content=older)
        if request.url.path.endswith("/blobs/sha256:newer"):
            return httpx.Response(200, content=newer)
        raise AssertionError(f"unexpected request: {request.url}")

    workspace = Workspace(
        WorkspaceConfig(workspace_dir=tmp_path, results_dir=tmp_path / "results")
    )
    backend = docker.ArtifactoryDockerBackend(
        ArtifactoryBackendConfig(name="primary", base_url="https://example.invalid"),
        "synthetic-token",
        workspace=workspace,
    )

    async def replace_session() -> None:
        await backend.session.aclose()
        backend.session = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={
                "User-Agent": "cred-scan/0.1",
                "X-JFrog-Art-Api": "synthetic-token",
            },
            follow_redirects=True,
            timeout=120,
            trust_env=False,
        )

    asyncio.run(replace_session())
    reader = ArtifactoryDockerReader(
        backend,
        repository_inventory.boundary,
        repository_inventory.targets,
        workspace=workspace,
    )
    try:
        directory = PROVENANCE.replace(":etc/app.env", ":etc")
        files = asyncio.run(reader.list_files(directory))
        listed = asyncio.run(reader.read_file(files[0]))

        expected = PROVENANCE.replace("sha256:layer", "sha256:newer")
        assert files == (expected,)
        assert listed.path == expected
        assert listed.content == "SECRET=newer\n"
    finally:
        asyncio.run(reader.aclose())
        asyncio.run(backend.aclose())


@pytest.mark.parametrize("operation", ["read", "list"])
@pytest.mark.parametrize("cancel_count", [1, 2])
@pytest.mark.parametrize("worker_error", [False, True])
def test_cancelled_archive_work_finishes_before_reader_scratch_is_removed(
    backend, repository_inventory, monkeypatch, operation, cancel_count, worker_error
):
    async def scenario():
        reader = backend.content_reader(
            repository_inventory.boundary, repository_inventory.targets
        )
        archive = reader._scratch_dir / "layer.tar"
        archive.write_bytes(b"worker input")
        scratch = reader._scratch_dir
        entered = asyncio.Event()
        release, finished = threading.Event(), threading.Event()
        loop = asyncio.get_running_loop()

        def parse(*_args):
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(5), "test must release the archive worker"
            assert archive.read_bytes() == b"worker input"
            assert scratch.exists() and not reader._closed
            finished.set()
            if worker_error:
                raise ValueError("archive parser failed")
            return (b"content", {}) if operation == "read" else ["etc/app.env"]

        monkeypatch.setattr(
            reader,
            "_manifest",
            AsyncMock(return_value={"layers": [{"digest": "sha256:layer"}]}),
        )
        monkeypatch.setattr(
            reader,
            "_matching_layer",
            AsyncMock(return_value={"digest": "sha256:layer"}),
        )
        monkeypatch.setattr(reader, "_download_blob", AsyncMock(return_value=archive))
        monkeypatch.setattr(
            reader,
            "_find_file_in_archive"
            if operation == "read"
            else "_list_files_in_archive",
            parse,
        )

        async def request():
            try:
                if operation == "read":
                    await reader.read_file(PROVENANCE)
                else:
                    await reader.list_files(PROVENANCE.replace(":etc/app.env", ":etc"))
            finally:
                await reader.aclose()

        task = asyncio.create_task(request())
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            for _ in range(cancel_count):
                task.cancel()
                done, _ = await asyncio.wait({task}, timeout=0.05)
                assert not done and archive.exists() and not reader._closed
            release.set()
            done, _ = await asyncio.wait({task}, timeout=2)
            assert task in done
            with pytest.raises(asyncio.CancelledError):
                await task
            assert finished.is_set()
            assert reader._closed and not scratch.exists()
            assert not archive.exists()
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
            await reader.aclose()

    asyncio.run(scenario())
