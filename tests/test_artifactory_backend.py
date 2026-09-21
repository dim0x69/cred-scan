import asyncio
from datetime import UTC, datetime
from email.utils import format_datetime
import httpx
import pytest

from cred_scan.backend.adapters.artifactory.common import (
    ArtifactoryBackend,
    ArtifactoryError,
)
from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend


def run(coroutine):
    return asyncio.run(coroutine)


def make_backend(handler):
    backend = object.__new__(ArtifactoryDockerBackend)
    ArtifactoryBackend.__init__(
        backend,
        "artifactory_docker",
        "https://example.invalid",
        "synthetic-token",
    )
    backend.platform = "linux/amd64"

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


@pytest.mark.parametrize(
    ("method", "field", "first_value", "second_value"),
    [
        ("images", "repositories", "team/api", "team/web"),
        ("tags", "tags", "old", "new"),
    ],
)
def test_relative_pagination_links_are_resolved(
    method, field, first_value, second_value
):
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={field: [second_value]})
        return httpx.Response(
            200,
            json={field: [first_value]},
            headers={"Link": '<?page=2>; rel="next"'},
        )

    backend = make_backend(handler)
    try:
        result = run(
            backend.list_images("docker-local")
            if method == "images"
            else backend.list_tags("docker-local", "team/api")
        )
    finally:
        run(backend.aclose())

    assert set(result) == {first_value, second_value}
    assert [request.url.params.get("page") for request in seen] == [None, "2"]
    assert all(request.url.is_absolute_url for request in seen)


def test_repeated_pagination_links_fail_without_repeating_the_request():
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={"repositories": ["team/api"]},
            headers={"Link": '<?page=2>; rel="next"'},
        )

    backend = make_backend(handler)
    try:
        with pytest.raises(ArtifactoryError, match="pagination loop"):
            run(backend.list_images("docker-local"))
    finally:
        run(backend.aclose())

    assert len(seen) == 2
    assert [request.url.params.get("page") for request in seen] == [None, "2"]


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


def test_missing_token_is_rejected():
    with pytest.raises(ArtifactoryError, match="set ARTIFACTORY_ACCESS_TOKEN"):
        backend = object.__new__(ArtifactoryDockerBackend)
        ArtifactoryBackend.__init__(
            backend,
            "artifactory_docker",
            "https://example.invalid",
            "  ",
        )
