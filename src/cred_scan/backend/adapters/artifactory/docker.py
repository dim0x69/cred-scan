"""Artifactory Docker discovery, scanning, and layer content access."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import tarfile
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.parse import quote

import aiofiles
import httpx

from cred_scan.backend.adapters.artifactory.common import ArtifactoryBackend, ArtifactoryError
from cred_scan.backend.adapters.artifactory.models import (
    ArtifactoryBackendConfig,
    ArtifactoryRepository,
    DockerImageScanScope,
)
from cred_scan.backend.models import (
    BackendConfig,
    FileContent,
    ResolvedProvenance,
    ScanBoundaryRef,
    ScanBoundaryInventory,
    ScanTarget,
    target_id_for,
)
from cred_scan.backend.proto import ContentReader, UnsupportedTitusTargetError
from cred_scan.common.proto import WorkspaceProtocol
from cred_scan.common.workspace import scratch_dir

MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)

_PROVENANCE_RE = re.compile(
    r"^docker://(?P<registry>[^/]+)/(?P<repository>[^/]+)/(?P<image>.+)"
    r"@(?P<manifest>sha256:[^/]+)/(?P<layer>sha256:[^:]+):(?P<path>.+)$"
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


@dataclass(frozen=True)
class DockerProvenance:
    registry: str
    repository: str
    image: str
    manifest: str
    layer: str
    path: str


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
    match = _PROVENANCE_RE.fullmatch(value.strip())
    if match is None:
        raise LayerEvidenceError("invalid Titus Docker provenance path")
    return DockerProvenance(
        registry=match["registry"],
        repository=match["repository"],
        image=match["image"],
        manifest=match["manifest"],
        layer=match["layer"],
        path=safe_member_path(match["path"]),
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
        targets: tuple[ScanTarget, ...],
        *,
        workspace: WorkspaceProtocol,
        max_directory_entries: int = 100,
    ) -> None:
        if not targets:
            raise ValueError("a content reader requires at least one target")
        if any(target.boundary.id != boundary.id for target in targets):
            raise ValueError("content-reader targets must belong to the boundary")
        self.backend = backend
        self.max_directory_entries = max_directory_entries
        self.boundary = boundary
        self.targets = targets
        self._cache: dict[str, bytes] = {}
        self._closed = False
        self._scratch_context = scratch_dir(
            workspace.boundary(boundary.id).scratch_parent
        )
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
        if not isinstance(manifest.get("layers"), list) or not manifest["layers"]:
            raise LayerEvidenceError("image manifest contains no filesystem layers")
        return manifest

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
        self, provenance: DockerProvenance, manifest: dict[str, Any]
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

    def _target_for_provenance(
        self, provenance: DockerProvenance, target_id: str | None = None
    ) -> ScanTarget:
        image = f"{provenance.registry}/{provenance.repository}/{provenance.image}"
        matches = [
            target
            for target in self.targets
            if target.boundary.id == self.boundary.id
            and isinstance(target.scope, DockerImageScanScope)
            and target.scope.image == image
            and target.scope.digest == provenance.manifest
        ]
        if target_id is not None:
            target = next((item for item in matches if item.id == target_id), None)
            if target is None:
                raise LayerEvidenceError(
                    "Titus provenance does not match the requested pinned target"
                )
            return target
        if len(matches) != 1:
            raise LayerEvidenceError(
                "Titus provenance does not identify exactly one pinned target"
            )
        return matches[0]

    def _validate_provenance(self, provenance: DockerProvenance) -> None:
        self._target_for_provenance(provenance)

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

    async def _find_file(self, provenance_value: str) -> tuple[bytes, dict[str, Any]]:
        provenance = parse_provenance(provenance_value)
        self._validate_provenance(provenance)
        cached = self._cache.get(provenance_value)
        if cached is not None:
            return cached, {
                "path": provenance.path,
                "layer": provenance.layer,
                "requested_provenance": provenance_value,
                "size": len(cached),
            }
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
        content, metadata = result
        self._cache[provenance_value] = content
        metadata["requested_provenance"] = provenance_value
        return content, metadata

    def _list_files_in_archive(
        self,
        archive_path: Path,
        prefix: str,
        seen: set[str],
    ) -> tuple[str, ...]:
        entries: list[str] = []
        with archive_path.open("rb") as stream:
            with tarfile.open(fileobj=stream, mode="r|*") as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    try:
                        path = safe_member_path(member.name)
                    except LayerEvidenceError:
                        continue
                    if (
                        path.startswith(prefix)
                        and path not in seen
                        and not any(part.startswith(".wh.") for part in path.split("/"))
                    ):
                        seen.add(path)
                        entries.append(path)
                        if len(seen) >= self.max_directory_entries:
                            return tuple(entries)
        return tuple(entries)

    @staticmethod
    def _file_locator(
        provenance: DockerProvenance, layer_digest: str, member_path: str
    ) -> str:
        locator = (
            f"docker://{provenance.registry}/{provenance.repository}/"
            f"{provenance.image}@{provenance.manifest}/"
            f"{layer_digest}:{member_path}"
        )
        # Keep the list/read contract local to the backend and fail closed if
        # malformed manifest data would produce an unreadable locator.
        parse_provenance(locator)
        return locator

    async def resolve_provenance(
        self, raw_path: str, *, target_id: str | None = None
    ) -> ResolvedProvenance:
        provenance = parse_provenance(raw_path)
        target = self._target_for_provenance(provenance, target_id)
        return ResolvedProvenance(
            target_id=target.id,
            provenance=raw_path,
            source_path=provenance.path,
            filename=PurePosixPath(provenance.path).name,
        )

    async def read_file(self, path: str) -> FileContent:
        content, _ = await self._find_file(path)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return FileContent(
                path=path,
                content=base64.b64encode(content).decode("ascii"),
                encoding="base64",
            )
        return FileContent(path=path, content=text, encoding="utf-8")

    async def list_files(self, directory: str) -> tuple[str, ...]:
        provenance = parse_provenance(directory)
        self._validate_provenance(provenance)
        prefix = provenance.path.rstrip("/") + "/"
        manifest = await self._manifest(provenance)
        entries: list[str] = []
        seen: set[str] = set()
        for descriptor in reversed(
            [item for item in manifest.get("layers", []) if isinstance(item, dict)]
        ):
            digest = descriptor.get("digest")
            if not isinstance(digest, str):
                continue
            archive_path = await self._download_blob(provenance, digest)
            layer_entries = await _read_archive(
                archive_path,
                lambda: self._list_files_in_archive(archive_path, prefix, seen),
            )
            entries.extend(
                self._file_locator(provenance, digest, path) for path in layer_entries
            )
            if len(entries) >= self.max_directory_entries:
                return tuple(entries)
        return tuple(entries)

    async def extract_file(self, path: str, destination: Path) -> Path:
        content, _ = await self._find_file(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp")
        async with aiofiles.open(temporary, mode="wb") as stream:
            await stream.write(content)
            await stream.flush()
        await asyncio.to_thread(temporary.replace, destination)
        return destination

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cache.clear()
        self._scratch_context.__exit__(None, None, None)


class ArtifactoryDockerBackend(ArtifactoryBackend):
    """Discover and read pinned Docker sources through Artifactory."""

    def __init__(
        self,
        config: ArtifactoryBackendConfig,
        token: str,
        *,
        workspace: WorkspaceProtocol,
        max_directory_entries: int = 100,
    ) -> None:
        super().__init__(config, token, workspace=workspace)
        # Platform selection is a Docker concern, not common Artifactory setup.
        self.platform = config.platform
        self.max_directory_entries = max_directory_entries

    async def _manifest(
        self, repository: str, image: str, reference: str
    ) -> tuple[str, dict[str, Any], datetime | None]:
        url = (
            f"{self.base_url}/api/docker/{quote(repository, safe='')}/v2/"
            f"{quote(image, safe='/')}/manifests/{quote(reference, safe=':@')}"
        )
        response = await self._get(url, headers={"Accept": MANIFEST_ACCEPT})
        try:
            digest = response.headers.get("Docker-Content-Digest")
            if not digest:
                digest = f"sha256:{hashlib.sha256(response.content).hexdigest()}"
            payload = response.json()
            if not isinstance(payload, dict):
                raise ArtifactoryError(f"manifest was not an object: {url}")
            timestamp = _parse_http_timestamp(response.headers.get("Last-Modified"))
        finally:
            await response.aclose()
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
        self, boundary: ScanBoundaryRef, targets: tuple[ScanTarget, ...]
    ) -> ArtifactoryDockerReader:
        return ArtifactoryDockerReader(
            self,
            boundary,
            targets,
            workspace=self.workspace,
            max_directory_entries=self.max_directory_entries,
        )

    def _repository(self, name: str) -> ArtifactoryRepository:
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

    async def inventory(self) -> list[ScanBoundaryInventory]:
        generated_at = datetime.now(UTC)
        reports: list[ScanBoundaryInventory] = []
        repositories = await self.repositories()
        for metadata in repositories:
            name = metadata.get("key") or metadata.get("name")
            if not isinstance(name, str):
                continue
            repository = self._repository(name)
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
                    reports.append(
                        ScanBoundaryInventory(
                            generated_at=generated_at,
                            backend=BackendConfig(name=self.name),
                            boundary=repository,
                        )
                    )
                    continue
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
                reports.append(
                    ScanBoundaryInventory(
                        generated_at=generated_at,
                        backend=BackendConfig(name=self.name),
                        boundary=repository,
                        targets=tuple(targets),
                    )
                )
            except Exception as error:
                message = str(error)
                reports.append(
                    ScanBoundaryInventory(
                        generated_at=generated_at,
                        backend=BackendConfig(name=self.name),
                        boundary=repository,
                        errors=(message,),
                    )
                )
        return reports
