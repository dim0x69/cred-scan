"""Artifactory Docker discovery, scanning, and layer content access."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import tarfile
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import quote

import aiofiles
from pydantic import BaseModel
import httpx
from pydantic import computed_field

from cred_scan.backend.adapters.artifactory.common import ArtifactoryBackend, ArtifactoryError
from cred_scan.backend.base_models import ScanScope, _pin_hash

if TYPE_CHECKING:
    from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
    from cred_scan.backend.models import (
        ContentLocation,
        ContentRead,
        ScanBoundaryInventory,
        ScanBoundaryRef,
        ScanTarget,
    )
from cred_scan.backend.proto import (
    ContentReader,
    ScratchDirectory,
    UnsupportedTitusTargetError,
)

MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class DockerImageScanScope(ScanScope):
    """A Docker scan scope selected by the Artifactory Docker backend."""

    kind: Literal["docker"] = "docker"
    image: str
    digest: str
    platform: str
    root_digest: str
    tags: tuple[str, ...] = ()
    manifest_timestamp: datetime

    @computed_field
    @property
    def id(self) -> str:
        return self.image

    @computed_field
    @property
    def pin_id(self) -> str:
        return _pin_hash((self.digest,))

_LAYER_PROVENANCE_RE = re.compile(
    r"^docker://(?P<registry>[^/]+)/(?P<repository>[^/]+)/(?P<image>.+)"
    r"@(?P<manifest>sha256:[^/]+)/(?P<layer>sha256:[^:]+):(?P<path>.+)$"
)
_METADATA_PROVENANCE_RE = re.compile(
    r"^docker://(?P<registry>[^/]+)/(?P<repository>[^/]+)/(?P<image>.+)"
    r"@(?P<manifest>sha256:[^/]+)/(?P<path>manifest\.json|config\.json)$"
)

LOGGER = logging.getLogger(__name__)


def _parse_http_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


class LayerEvidenceError(RuntimeError):
    pass


class DockerLayerProvenance(BaseModel):
    """Docker adapter-internal interpretation of a layer locator."""

    kind: Literal["docker-layer"] = "docker-layer"
    raw_path: str
    registry: str
    repository: str
    image: str
    manifest: str
    layer: str
    path: str


class DockerMetadataProvenance(BaseModel):
    """Docker adapter-internal interpretation of metadata locators."""

    kind: Literal["docker-manifest", "docker-config"]
    raw_path: str
    registry: str
    repository: str
    image: str
    manifest: str
    path: Literal["manifest.json", "config.json"]


DockerProvenance = DockerLayerProvenance | DockerMetadataProvenance


def safe_member_path(value: str) -> str:
    normalized = value.replace("\\", "/").lstrip("/")
    parts = normalized.split("/")
    if not normalized or any(part in {"", ".", ".."} for part in parts):
        raise LayerEvidenceError("invalid or unsafe layer member path")
    result = str(PurePosixPath(normalized))
    if result in {"", "."} or result.startswith("../"):
        raise LayerEvidenceError("invalid or unsafe layer member path")
    return result


def parse_provenance(value: str) -> DockerProvenance:
    raw_path = value.strip()
    metadata = _METADATA_PROVENANCE_RE.fullmatch(raw_path)
    if metadata is not None:
        path = cast(Literal["manifest.json", "config.json"], metadata["path"])
        return DockerMetadataProvenance(
            kind="docker-manifest" if path == "manifest.json" else "docker-config",
            raw_path=raw_path,
            registry=metadata["registry"],
            repository=metadata["repository"],
            image=metadata["image"],
            manifest=metadata["manifest"],
            path=path,
        )

    layer = _LAYER_PROVENANCE_RE.fullmatch(raw_path)
    if layer is not None:
        return DockerLayerProvenance(
            raw_path=raw_path,
            registry=layer["registry"],
            repository=layer["repository"],
            image=layer["image"],
            manifest=layer["manifest"],
            layer=layer["layer"],
            path=safe_member_path(layer["path"]),
        )
    raise LayerEvidenceError(
        "invalid Titus Docker provenance path; expected a layer file, "
        "manifest.json, or config.json provenance"
    )


async def _read_archive[T](archive_path: Path, read: Callable[[], T]) -> T:
    """Join only the blocking archive worker before deleting its temporary input."""
    # An executor Future is not a separately cancellable asyncio Task. The caller
    # may be cancelled repeatedly, but its archive/scratch must outlive the worker.
    work = asyncio.get_running_loop().run_in_executor(None, read)
    try:
        return await asyncio.shield(work)
    finally:
        while not work.done():
            try:
                await asyncio.shield(work)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not work.cancelled():
            work.exception()  # Observe a worker failure even during cancellation.
        archive_path.unlink(missing_ok=True)


class ArtifactoryDockerReader(ContentReader):
    def __init__(
        self,
        backend: ArtifactoryDockerBackend,
        boundary: ScanBoundaryRef,
        *,
        scratch_dir: ScratchDirectory,
    ) -> None:
        self.backend = backend
        self.boundary = boundary
        self._closed = False
        self._locations: dict[str, ContentLocation] = {}
        self._reads: dict[tuple[str, str, str], ContentRead] = {}
        self._scratch_context = scratch_dir()
        self._scratch_dir = Path(self._scratch_context.__enter__())

    async def _manifest(self, provenance: DockerProvenance) -> dict[str, Any]:
        try:
            _, manifest, _ = await self.backend._manifest(
                provenance.repository, provenance.image, provenance.manifest
            )
        except ArtifactoryError as error:
            raise LayerEvidenceError(
                f"could not retrieve image manifest: {error}"
            ) from error
        return manifest

    async def _metadata_bytes(self, provenance: DockerMetadataProvenance) -> bytes:
        if provenance.path == "manifest.json":
            _, content, _ = await self.backend._manifest_bytes(
                provenance.repository, provenance.image, provenance.manifest
            )
            return content
        manifest = await self._manifest(provenance)
        config = manifest.get("config")
        if not isinstance(config, dict) or not isinstance(config.get("digest"), str):
            raise LayerEvidenceError("image manifest has no config blob digest")
        async with self._response(provenance, config["digest"]) as response:
            return await response.aread()

    @asynccontextmanager
    async def _response(
        self, provenance: DockerProvenance, digest: str
    ) -> AsyncIterator[Any]:
        try:
            async with self.backend.docker_blob(
                provenance.repository, provenance.image, digest
            ) as response:
                yield response
        except ArtifactoryError as error:
            raise LayerEvidenceError(
                f"could not retrieve image layer: {error}"
            ) from error

    async def _matching_layer(
        self, provenance: DockerLayerProvenance, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        raw_layers = manifest.get("layers")
        if not isinstance(raw_layers, list) or not raw_layers:
            raise LayerEvidenceError("image manifest contains no filesystem layers")
        layers = [item for item in raw_layers if isinstance(item, dict)]
        if len(layers) != len(raw_layers):
            raise LayerEvidenceError(
                "image manifest contains an invalid layer descriptor"
            )

        # Some provenance producers use the manifest blob digest directly.
        for layer in layers:
            if layer.get("digest") == provenance.layer:
                return layer

        config_descriptor = manifest.get("config")
        if not isinstance(config_descriptor, dict) or not isinstance(
            config_descriptor.get("digest"), str
        ):
            raise LayerEvidenceError(
                f"could not resolve requested Docker layer: {provenance.layer}"
            )
        try:
            async with self._response(
                provenance, config_descriptor["digest"]
            ) as response:
                config = json.loads(await response.aread())
            diff_ids = config.get("rootfs", {}).get("diff_ids")
            if not isinstance(diff_ids, list):
                raise LayerEvidenceError(
                    "image config contains no filesystem layer identities"
                )
            for index, diff_id in enumerate(diff_ids):
                if diff_id == provenance.layer:
                    if index >= len(layers):
                        break
                    return layers[index]
        except LayerEvidenceError:
            raise
        except (ValueError, TypeError, AttributeError) as error:
            raise LayerEvidenceError(
                f"could not resolve requested Docker layer: {provenance.layer}"
            ) from error
        raise LayerEvidenceError(
            f"requested Docker layer was not found: {provenance.layer}"
        )

    def _validate_boundary(self, provenance: DockerProvenance) -> None:
        if provenance.repository != self.boundary.name:
            raise LayerEvidenceError(
                "Titus provenance does not belong to this repository boundary"
            )

    def _temporary_path(self) -> Path:
        with NamedTemporaryFile(
            dir=self._scratch_dir, prefix="blob-", suffix=".tar", delete=False
        ) as temporary:
            return Path(temporary.name)

    async def _download_blob(self, provenance: DockerProvenance, digest: str) -> Path:
        path = self._temporary_path()
        try:
            async with self._response(provenance, digest) as response:
                async with aiofiles.open(path, mode="wb") as stream:
                    async for chunk in response.aiter_bytes(1024 * 1024):
                        await stream.write(chunk)
                    await stream.flush()
            return path
        except BaseException:
            await asyncio.to_thread(path.unlink, missing_ok=True)
            raise

    def _find_file_in_archive(
        self,
        archive_path: Path,
        provenance: DockerProvenance,
        digest: str,
    ) -> tuple[bytes, dict[str, Any]] | None:
        with archive_path.open("rb") as stream:
            with tarfile.open(fileobj=stream, mode="r|*") as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    try:
                        member_path = safe_member_path(member.name)
                    except LayerEvidenceError:
                        continue
                    if (
                        any(part.startswith(".wh.") for part in member_path.split("/"))
                        or member_path != provenance.path
                    ):
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        raise LayerEvidenceError(
                            f"could not read layer member: {member_path}"
                        )
                    with source:
                        content = source.read()
                    return (
                        content,
                        {
                            "path": member_path,
                            "layer": digest,
                            "size": member.size,
                        },
                    )
        return None

    async def _find_file(self, provenance: DockerProvenance) -> bytes:
        if isinstance(provenance, DockerMetadataProvenance):
            return await self._metadata_bytes(provenance)

        manifest = await self._manifest(provenance)
        descriptor = await self._matching_layer(provenance, manifest)
        digest = descriptor.get("digest")
        if not isinstance(digest, str):
            raise LayerEvidenceError("requested Docker layer has no blob digest")
        archive_path = await self._download_blob(provenance, digest)
        result = await _read_archive(
            archive_path,
            lambda: self._find_file_in_archive(archive_path, provenance, digest),
        )
        if result is None:
            raise LayerEvidenceError(f"file was not found: {provenance.path}")
        content, _ = result
        return content

    async def resolve_location(self, raw_path: str) -> ContentLocation:
        from cred_scan.backend.models import ContentLocation  # noqa: PLC0415

        key = raw_path.strip()
        cached = self._locations.get(key)
        if cached is not None:
            return cached

        try:
            provenance = parse_provenance(key)
        except LayerEvidenceError:
            LOGGER.exception("invalid Docker provenance raw_path=%s", raw_path)
            raise
        self._validate_boundary(provenance)
        source_path = provenance.path
        location = ContentLocation(
            locator=key,
            source_path=source_path,
            filename=PurePosixPath(source_path).name,
        )
        self._locations[key] = location
        return location

    async def read(self, location: ContentLocation | str) -> ContentRead:
        from cred_scan.backend.models import ContentRead  # noqa: PLC0415

        if isinstance(location, str):
            location = await self.resolve_location(location)

        key = (
            location.locator,
            location.source_path,
            location.filename,
        )
        cached = self._reads.get(key)
        if cached is not None:
            return cached

        provenance = parse_provenance(location.locator)
        self._validate_boundary(provenance)
        if location.source_path != provenance.path:
            raise LayerEvidenceError(
                "content location source path does not match locator"
            )
        if location.filename != PurePosixPath(provenance.path).name:
            raise LayerEvidenceError(
                "content location filename does not match locator"
            )

        result = ContentRead(
            content=await self._find_file(provenance),
            source_path=provenance.path,
            filename=PurePosixPath(provenance.path).name,
        )
        self._reads[key] = result
        return result

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._locations.clear()
        self._reads.clear()
        self._scratch_context.__exit__(None, None, None)


class ArtifactoryDockerBackend(ArtifactoryBackend):
    """Discover and read pinned Docker sources through Artifactory."""

    def __init__(
        self,
        name: str,
        base_url: str,
        platform: str,
        token: str,
    ) -> None:
        super().__init__(name, base_url, token)
        # Platform selection is a Docker concern, not common Artifactory setup.
        self.platform = platform

    async def _manifest_bytes(
        self, repository: str, image: str, reference: str
    ) -> tuple[str, bytes, datetime | None]:
        url = (
            f"{self.base_url}/api/docker/{quote(repository, safe='')}/v2/"
            f"{quote(image, safe='/')}/manifests/{quote(reference, safe=':@')}"
        )
        response = await self._get(url, headers={"Accept": MANIFEST_ACCEPT})
        try:
            digest = response.headers.get("Docker-Content-Digest")
            content = response.content
            if not digest:
                digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
            timestamp = _parse_http_timestamp(response.headers.get("Last-Modified"))
        finally:
            await response.aclose()
        return digest, content, timestamp

    async def _manifest(
        self, repository: str, image: str, reference: str
    ) -> tuple[str, dict[str, Any], datetime | None]:
        digest, content, timestamp = await self._manifest_bytes(
            repository, image, reference
        )
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as error:
            raise ArtifactoryError("manifest was not valid JSON") from error
        if not isinstance(payload, dict):
            raise ArtifactoryError("manifest was not an object")
        return digest, payload, timestamp

    @asynccontextmanager
    async def docker_blob(
        self, repository: str, image: str, digest: str
    ) -> AsyncIterator[httpx.Response]:
        url = (
            f"{self.base_url}/api/docker/{quote(repository, safe='')}/v2/"
            f"{quote(image, safe='/')}/blobs/{quote(digest, safe=':')}"
        )
        try:
            async with self.session.stream("GET", url, timeout=120) as response:
                await self._raise_for_status(response, url)
                yield response
        except httpx.HTTPError as error:
            raise ArtifactoryError(f"GET {url} failed: {error}") from error

    async def list_images(self, repository: str) -> set[str]:
        url = f"{self.base_url}/api/docker/{quote(repository, safe='')}/v2/_catalog"
        images: set[str] = set()
        next_url: str | None = url
        while next_url:
            response = await self._get(next_url)
            try:
                payload = response.json()
                next_url = response.links.get("next", {}).get("url")
            finally:
                await response.aclose()
            if isinstance(payload, dict):
                images.update(
                    str(item) for item in payload.get("repositories", []) if item
                )
        return images

    async def list_tags(self, repository: str, image: str) -> list[str]:
        url = (
            f"{self.base_url}/api/docker/{quote(repository, safe='')}/v2/"
            f"{quote(image, safe='/')}/tags/list"
        )
        response = await self._get(url)
        try:
            payload = response.json()
        finally:
            await response.aclose()
        tags = payload.get("tags", []) if isinstance(payload, dict) else []
        return sorted({str(tag) for tag in tags if tag})

    def titus_scan_arguments(
        self, inventory: ScanBoundaryInventory, target: ScanTarget
    ) -> tuple[str, ...]:
        scope = target.scope
        if not isinstance(scope, DockerImageScanScope):
            raise UnsupportedTitusTargetError(
                f"Titus Docker adapter does not support target scope "
                f"{type(scope).__name__}"
            )
        return (
            "--docker",
            "--artifactory-repository",
            inventory.boundary.name,
            f"{scope.image}@{scope.digest}",
        )

    def content_reader(
        self,
        boundary: ScanBoundaryRef,
        scratch_dir: ScratchDirectory,
    ) -> ArtifactoryDockerReader:
        return ArtifactoryDockerReader(
            self,
            boundary,
            scratch_dir=scratch_dir,
        )

    def _repository(self, name: str) -> ArtifactoryRepository:
        from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository  # noqa: PLC0415

        repository = ArtifactoryRepository(
            id=f"artifactory:{self.name}:{name}", name=name
        )
        return repository

    async def _platform_manifest(
        self, repository: str, image: str, reference: str, platform: str
    ) -> tuple[str, str, datetime | None]:
        root_digest, manifest, timestamp = await self._manifest(
            repository, image, reference
        )
        descriptors = manifest.get("manifests", [])
        media_type = str(manifest.get("mediaType", ""))
        if (
            not isinstance(descriptors, list)
            or not descriptors
            or not ("index" in media_type or "list" in media_type)
        ):
            return root_digest, root_digest, timestamp
        parts = platform.split("/")
        wanted_os, wanted_arch = parts[:2]
        wanted_variant = parts[2] if len(parts) > 2 else None
        for descriptor in descriptors:
            if not isinstance(descriptor, dict):
                continue
            descriptor_platform = descriptor.get("platform", {})
            if not isinstance(descriptor_platform, dict):
                continue
            if (
                descriptor_platform.get("os") != wanted_os
                or descriptor_platform.get("architecture") != wanted_arch
            ):
                continue
            if wanted_variant and descriptor_platform.get("variant") != wanted_variant:
                continue
            child = descriptor.get("digest")
            if not isinstance(child, str):
                continue
            child_digest, _, child_timestamp = await self._manifest(
                repository, image, child
            )
            return root_digest, child_digest, timestamp or child_timestamp
        raise ArtifactoryError(
            f"image {image}@{root_digest} has no {platform} manifest"
        )

    async def _select_latest(
        self, repository: str, image: str, platform: str
    ) -> DockerImageScanScope | None:
        candidates: list[tuple[datetime, str, str, str]] = []
        for tag in await self.list_tags(repository, image):
            root_digest, digest, timestamp = await self._platform_manifest(
                repository, image, tag, platform
            )
            if timestamp is not None:
                candidates.append((timestamp, tag, root_digest, digest))
        if not candidates:
            return None
        newest_timestamp = max(item[0] for item in candidates)
        newest = [item for item in candidates if item[0] == newest_timestamp]
        newest_digests = {item[3] for item in newest}
        if len(newest_digests) != 1:
            raise ArtifactoryError(
                f"multiple digests share newest timestamp for {image}"
            )
        digest = newest[0][3]
        aliases = tuple(sorted(item[1] for item in candidates if item[3] == digest))
        registry = (
            self.base_url.removeprefix("https://")
            .removeprefix("http://")
            .removesuffix("/artifactory")
        )
        return DockerImageScanScope(
            image=f"{registry}/{repository}/{image}",
            digest=digest,
            platform=platform,
            root_digest=newest[0][2],
            tags=aliases,
            manifest_timestamp=newest_timestamp,
        )

    async def inventory(self, boundary_id: str) -> ScanBoundaryInventory:
        from cred_scan.backend.models import (  # noqa: PLC0415
            ScanBoundaryInventory,
            ScanTarget,
            target_id_for,
        )

        generated_at = datetime.now(UTC)
        repositories = await self.repositories()
        for metadata in repositories:
            name = metadata.get("key") or metadata.get("name")
            if not isinstance(name, str):
                continue
            repository = self._repository(name)
            if repository.id != boundary_id:
                continue
            package_type = str(metadata.get("packageType", "")).lower()
            repository_type = str(
                metadata.get("type", metadata.get("rclass", ""))
            ).lower()
            if package_type != "docker" or repository_type not in {
                "local",
                "local-repo",
            }:
                LOGGER.warning(
                    "skipping unsupported Artifactory repository %s (%s/%s)",
                    name,
                    repository_type,
                    package_type,
                )
                continue
            try:
                images = sorted(await self.list_images(name))
                if not images:
                    LOGGER.info("skipping empty Artifactory repository %s", name)
                    return ScanBoundaryInventory(
                        generated_at=generated_at,
                        boundary=repository,
                    )
                targets: list[ScanTarget] = []
                for image_name in images:
                    scope = await self._select_latest(name, image_name, self.platform)
                    if scope is None:
                        continue
                    targets.append(
                        ScanTarget(
                            id=target_id_for(scope),
                            backend_id=self.name,
                            boundary=repository,
                            scope=scope,
                        )
                    )
                return ScanBoundaryInventory(
                    generated_at=generated_at,
                    boundary=repository,
                    targets=tuple(targets),
                )
            except Exception as error:
                message = str(error)
                return ScanBoundaryInventory(
                    generated_at=generated_at,
                    boundary=repository,
                    errors=(message,),
                )
        raise KeyError(f"boundary not found: {boundary_id}")
