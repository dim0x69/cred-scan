import asyncio
from datetime import UTC, datetime
from email.utils import format_datetime
from unittest.mock import Mock

import httpx
import pytest

from cred_scan.backend.adapters.artifactory.common import (
    ArtifactoryBackend,
    ArtifactoryError,
)
from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend
from cred_scan.backend.adapters.artifactory.models import ArtifactoryBackendConfig
from cred_scan.backend.proto import BackendAdapter
from cred_scan.orch.models import WorkspaceConfig
from cred_scan.orch.workspace import Workspace


def run(coroutine):
    return asyncio.run(coroutine)


def make_backend(handler):
    backend = ArtifactoryDockerBackend(
        ArtifactoryBackendConfig(name="primary", base_url="https://example.invalid"),
        "synthetic-token",
        workspace=Workspace(
            WorkspaceConfig.model_validate({"workspace-dir": "workspace"})
        ),
    )

    async def replace_session():
        await backend.session.aclose()
        backend.session = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={
                "User-Agent": "cred-scan/0.1",
                "Authorization": "Bearer synthetic-token",
            },
            follow_redirects=True,
            timeout=120,
            trust_env=False,
        )

    run(replace_session())
    return backend


def test_async_backend_preserves_authentication_and_paginates_catalog():
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/artifactory/api/repositories":
            return httpx.Response(200, json=[{"key": "docker-local"}])
        if (
            request.url.path.endswith("/v2/_catalog")
            and request.url.params.get("page") is None
        ):
            return httpx.Response(
                200,
                json={"repositories": ["team/api"]},
                headers={
                    "Link": "<https://example.invalid/artifactory/api/docker/"
                    'docker-local/v2/_catalog?page=2>; rel="next"'
                },
            )
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"repositories": ["team/web"]})
        raise AssertionError(f"unexpected request: {request.url}")

    backend = make_backend(handler)
    try:
        repositories = run(backend.repositories())
        images = run(backend.list_images("docker-local"))
    finally:
        run(backend.aclose())

    assert repositories == [{"key": "docker-local"}]
    assert images == {"team/api", "team/web"}
    assert seen
    assert all(
        request.headers["Authorization"] == "Bearer synthetic-token"
        for request in seen
    )
    assert all(request.headers["User-Agent"] == "cred-scan/0.1" for request in seen)


def test_manifest_parses_digest_and_timestamp():
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept"]
        return httpx.Response(
            200,
            json={"schemaVersion": 2, "layers": []},
            headers={"Last-Modified": format_datetime(timestamp, usegmt=True)},
        )

    backend = make_backend(handler)
    try:
        digest, payload, parsed_timestamp = run(
            backend._manifest("docker-local", "team/api", "latest")
        )
    finally:
        run(backend.aclose())

    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    assert payload == {"schemaVersion": 2, "layers": []}
    assert parsed_timestamp == timestamp


def test_http_errors_are_converted_and_response_is_closed():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="permission denied")

    backend = make_backend(handler)
    try:
        with pytest.raises(ArtifactoryError, match="HTTP 403: permission denied"):
            run(backend.repositories())
    finally:
        run(backend.aclose())


def test_blob_response_is_async_context_managed():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"layer-data")

    backend = make_backend(handler)

    async def read_blob() -> bytes:
        async with backend.docker_blob(
            "docker-local", "team/api", "sha256:layer"
        ) as response:
            return await response.aread()

    try:
        assert run(read_blob()) == b"layer-data"
    finally:
        run(backend.aclose())


def test_artifactory_owns_config_and_name_without_a_backend_superclass(
    tmp_path, monkeypatch
):
    client = Mock()
    monkeypatch.setattr(httpx, "AsyncClient", client)
    config = ArtifactoryBackendConfig(
        name="primary", base_url="https://example.invalid"
    )
    backend: BackendAdapter = ArtifactoryDockerBackend(
        config,
        "synthetic-token",
        workspace=Workspace(WorkspaceConfig(workspace_dir=tmp_path)),
    )
    assert ArtifactoryBackend.__bases__ == (BackendAdapter,)
    assert backend.config is config
    assert backend.name == "primary"
    config.name = "renamed"
    assert backend.name == "renamed"  # Preserve the original live config/name behavior.
    assert backend.platform == "linux/amd64"
    assert client.call_args.kwargs["headers"]["Authorization"] == (
        "Bearer synthetic-token"
    )
    assert not list(tmp_path.iterdir())


def test_missing_token_still_raises_artifactory_error_before_client_creation(
    tmp_path, monkeypatch
):
    client = Mock()
    monkeypatch.setattr(httpx, "AsyncClient", client)
    with pytest.raises(ArtifactoryError, match="set ARTIFACTORY_ACCESS_TOKEN"):
        ArtifactoryDockerBackend(
            ArtifactoryBackendConfig(
                name="primary", base_url="https://example.invalid"
            ),
            "  ",
            workspace=Workspace(WorkspaceConfig(workspace_dir=tmp_path)),
        )
    client.assert_not_called()
