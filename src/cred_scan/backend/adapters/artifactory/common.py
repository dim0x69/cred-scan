"""Shared Artifactory transport and backend behavior."""

from __future__ import annotations

from typing import Any

import httpx

from cred_scan.backend.proto import BackendAdapter


class ArtifactoryError(RuntimeError):
    """An Artifactory transport or response error."""


class ArtifactoryBackend(BackendAdapter):
    """Common authenticated Artifactory backend behavior."""

    def __init__(
        self,
        name: str,
        base_url: str,
        token: str,
    ) -> None:
        self._name = name
        normalized = base_url.rstrip("/")
        self.base_url = (
            normalized
            if normalized.endswith("/artifactory")
            else f"{normalized}/artifactory"
        )
        if not token.strip():
            raise ArtifactoryError("set ARTIFACTORY_API_KEY")
        self.session = httpx.AsyncClient(
            headers={"User-Agent": "cred-scan/0.1", "X-JFrog-Art-Api": token},
            follow_redirects=True,
            timeout=120,
            trust_env=True,
        )

    @property
    def name(self) -> str:
        return self._name

    async def aclose(self) -> None:
        await self.session.aclose()

    async def _get(self, url: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self.session.get(url, timeout=120, **kwargs)
            await self._raise_for_status(response, url)
            return response
        except httpx.HTTPError as error:
            raise ArtifactoryError(f"GET {url} failed: {error}") from error

    async def _raise_for_status(self, response: httpx.Response, url: str) -> None:
        if response.is_success:
            return
        try:
            await response.aread()
            detail = response.text[:200]
        finally:
            await response.aclose()
        raise ArtifactoryError(
            f"GET {url} failed with HTTP {response.status_code}: {detail}"
        )

    async def repositories(self) -> list[dict[str, Any]]:
        """Return visible Artifactory repository metadata."""
        response = await self._get(f"{self.base_url}/api/repositories")
        try:
            payload = response.json()
        finally:
            await response.aclose()
        if not isinstance(payload, list):
            raise ArtifactoryError("Artifactory repository list was not an array")
        return [item for item in payload if isinstance(item, dict)]
