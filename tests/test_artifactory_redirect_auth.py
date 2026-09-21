"""Artifactory credentials never cross the configured HTTP origin."""

import asyncio

import httpx
import pytest

from cred_scan.backend.adapters.artifactory.common import (
    ArtifactoryBackend,
    ArtifactoryError,
)


class RedirectBackend(ArtifactoryBackend):
    async def discover_boundaries(self):
        raise NotImplementedError

    def titus_scan_arguments(self, inventory, target):
        raise NotImplementedError

    def content_reader(self, scratch_dir):
        raise NotImplementedError

    async def inventory(self, boundary_id):
        raise NotImplementedError


def make_backend(monkeypatch, handler):
    client = httpx.AsyncClient

    def mock_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        kwargs["trust_env"] = False
        return client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", mock_client)
    return RedirectBackend(
        "artifactory_docker",
        "https://artifactory.example/artifactory",
        "synthetic-token",
    )


def test_same_origin_redirect_retains_bearer_token(monkeypatch):
    seen = []

    async def handler(request):
        seen.append(request)
        if request.url.path == "/artifactory/start":
            return httpx.Response(302, headers={"Location": "/artifactory/final"})
        return httpx.Response(200, content=b"ok")

    backend = make_backend(monkeypatch, handler)

    async def request():
        async with backend.session.stream(
            "GET", f"{backend.base_url}/start"
        ) as response:
            content = await response.aread()
        await backend.aclose()
        return content

    assert asyncio.run(request()) == b"ok"

    assert len(seen) == 2
    assert all(
        item.headers["Authorization"] == "Bearer synthetic-token"
        for item in seen
    )


def test_cross_origin_redirect_strips_bearer_token(monkeypatch):
    seen = []

    async def handler(request):
        seen.append(request)
        if request.url.host == "artifactory.example":
            return httpx.Response(
                302,
                headers={"Location": "https://downloads.example/layer"},
            )
        return httpx.Response(200, content=b"layer")

    backend = make_backend(monkeypatch, handler)

    async def request():
        response = await backend._get(f"{backend.base_url}/start")
        content = response.content
        await response.aclose()
        await backend.aclose()
        return content

    assert asyncio.run(request()) == b"layer"

    assert len(seen) == 2
    assert seen[0].headers["Authorization"] == "Bearer synthetic-token"
    assert "Authorization" not in seen[1].headers


def test_artifactory_requires_https():
    with pytest.raises(ArtifactoryError, match="base URL must use HTTPS"):
        RedirectBackend(
            "artifactory_docker",
            "http://artifactory.example/artifactory",
            "synthetic-token",
        )
