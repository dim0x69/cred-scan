"""Boundary-scoped storage, locking, and backend lifetime."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import AbstractContextManager, asynccontextmanager, contextmanager
from pathlib import Path
from typing import TypeVar
from urllib.parse import quote, unquote

from pydantic import BaseModel

from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend
from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.backend.proto import BackendAdapter
from cred_scan.common.models import BoundaryPaths, WorkspaceConfig
from cred_scan.common.workspace import WorkspaceBusyError, fsync_directory
from cred_scan.judge.dspy_adapter import DspyFindingJudge
from cred_scan.orch.boundary import Boundary
from cred_scan.orch.models import AppConfig
from cred_scan.scan.exclusions import load_exclusions
from cred_scan.scan.models import CredentialsDocument, ExclusionPolicy, TitusReport
from cred_scan.scan.titus import TitusScannerPool

DocumentT = TypeVar("DocumentT", bound=BaseModel)


@contextmanager
def _operation_lock(path: Path) -> Iterator[int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise WorkspaceBusyError(
                f"boundary operation already active: {path.parent}"
            ) from error
        # Titus children inherit this descriptor and keep the lock after parent death.
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _exclusive_lock(directory: Path) -> Iterator[None]:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


class Workspace:
    """Own one backend and provide storage for one boundary at a time."""

    def __init__(self, config: AppConfig | WorkspaceConfig) -> None:
        if isinstance(config, AppConfig):
            self.config: AppConfig | None = config
            self._workspace_dir = config.workspace.workspace_dir
        else:
            self.config = None
            self._workspace_dir = config.workspace_dir
        self._backend: BackendAdapter | None = None
        self._policy: ExclusionPolicy | None = None
        self._judge: DspyFindingJudge | None = None
        self._active_boundary: Boundary | None = None
        self._closed = False

    async def __aenter__(self) -> "Workspace":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    @property
    def workspace_dir(self) -> Path:
        return self._workspace_dir

    @property
    def selector(self) -> BoundarySelector:
        return BoundarySelector(self)

    @property
    def backend(self) -> BackendAdapter:
        if self._backend is None:
            if self.config is None:
                raise RuntimeError("backend access requires application configuration")
            self._backend = ArtifactoryDockerBackend(
                self.config.backend,
                self.config.artifactory_api_key or "",
                workspace=self,
            )
        return self._backend

    def boundary(self, boundary_id: str) -> BoundaryPaths:
        return BoundaryPaths(
            boundary_id=boundary_id,
            boundary_dir=self._workspace_dir / quote(boundary_id, safe=""),
        )

    def inventory_boundaries(self) -> Iterator[BoundaryPaths]:
        for inventory in sorted(
            self._workspace_dir.glob("*/inventory.json"),
            key=lambda path: unquote(path.parent.name),
        ):
            paths = self.boundary(unquote(inventory.parent.name))
            if paths.inventory != inventory:
                raise ValueError(f"noncanonical boundary directory: {inventory.parent}")
            yield paths

    def operation_lock(self) -> AbstractContextManager[int]:
        """Lock the workspace for offline maintenance tools."""
        return _operation_lock(self._workspace_dir / ".operation.lock")

    def read(self, path: Path, model_type: type[DocumentT]) -> DocumentT | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        return model_type.model_validate(payload)

    def write(
        self,
        path: Path,
        document: DocumentT,
        model_type: type[DocumentT],
    ) -> None:
        if not isinstance(document, model_type):
            raise TypeError(
                f"expected {model_type.__name__}, got {type(document).__name__}"
            )
        validated = model_type.model_validate(document.model_dump(mode="json"))
        payload = validated.model_dump(mode="json")
        path.parent.mkdir(parents=True, exist_ok=True)
        with _exclusive_lock(path.parent):
            temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
            try:
                with temporary.open("w", encoding="utf-8") as stream:
                    json.dump(payload, stream, indent=2, sort_keys=True)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.replace(path)
                fsync_directory(path.parent)
            finally:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    @asynccontextmanager
    async def boundary_session(
        self,
        boundary_id: str,
    ) -> AsyncIterator[Boundary]:
        """Load and exclusively own exactly one persisted boundary."""
        paths = self.boundary(boundary_id)
        paths.boundary_dir.mkdir(parents=True, exist_ok=True)
        with _operation_lock(paths.operation_lock) as lock_fd:
            boundary = self._build_boundary(paths, lock_fd)
            self._active_boundary = boundary
            try:
                yield boundary
            finally:
                self._active_boundary = None


    def _build_boundary(self, paths: BoundaryPaths, lock_fd: int) -> Boundary:
        inventory, document, report = self._documents(paths)
        if self.config is None:
            raise RuntimeError("boundary sessions require application configuration")
        backend = self.backend
        if inventory.backend.name != backend.name:
            raise ValueError("boundary inventory belongs to another configured backend")
        if self._policy is None:
            self._policy = load_exclusions(self.config.exclusions)
        return Boundary(
            inventory=inventory,
            workspace=self,
            paths=paths,
            backend=backend,
            document=document,
            report=report,
            scanners=TitusScannerPool(
                self.config.titus,
                inventory,
                backend,
                concurrency=self.config.scan_concurrency,
                boundary_lock_fd=lock_fd,
                environment={
                    "ARTIFACTORY_PASSWORD": self.config.artifactory_api_key or "",
                    "ARTIFACTORY_TOKEN": self.config.artifactory_api_key or "",
                    "ARTIFACTORY_API_KEY": self.config.artifactory_api_key or "",
                },
            ),
            judge=self._judge_for(),
            policy=self._policy,
        )

    def _documents(
        self,
        paths: BoundaryPaths,
    ) -> tuple[ScanBoundaryInventory, CredentialsDocument | None, TitusReport | None]:
        inventory = self.read(paths.inventory, ScanBoundaryInventory)
        if inventory is None or inventory.boundary.id != paths.boundary_id:
            raise ValueError(
                f"missing or mismatched boundary inventory: {paths.inventory}"
            )
        document = self.read(paths.credentials, CredentialsDocument)
        report = self.read(paths.report, TitusReport)
        return inventory, document, report

    def _judge_for(self) -> DspyFindingJudge:
        if self.config is None:
            raise RuntimeError("judge requires application configuration")
        if self._judge is None:
            self._judge = DspyFindingJudge(self.config)
        return self._judge

    def checkpoint(self, boundary: Boundary) -> None:
        """Persist the current in-memory boundary aggregate."""
        if self._active_boundary is not boundary:
            raise RuntimeError("boundary is not owned by this workspace session")
        self.write(boundary.paths.inventory, boundary.inventory, ScanBoundaryInventory)
        if boundary.report is not None:
            self.write(boundary.paths.report, boundary.report, TitusReport)
        if boundary.document is not None:
            self.write(
                boundary.paths.credentials,
                boundary.document,
                CredentialsDocument,
            )

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        backend = self._backend
        self._backend = None
        if backend is None:
            return
        cleanup = asyncio.create_task(backend.aclose())
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError


class BoundarySelector:
    """Select one eligible boundary while holding its live lock."""

    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace

    @asynccontextmanager
    async def next_scan(self) -> AsyncIterator[Boundary | None]:
        async with self._next(Boundary.needs_scan) as boundary:
            yield boundary

    @asynccontextmanager
    async def next_judge(self) -> AsyncIterator[Boundary | None]:
        async with self._next(Boundary.needs_judge) as boundary:
            yield boundary

    @asynccontextmanager
    async def next_extract(self) -> AsyncIterator[Boundary | None]:
        async with self._next(Boundary.needs_extract) as boundary:
            yield boundary

    @asynccontextmanager
    async def _next(
        self,
        eligible: Callable[[Boundary], bool],
    ) -> AsyncIterator[Boundary | None]:
        for paths in self.workspace.inventory_boundaries():
            try:
                with _operation_lock(paths.operation_lock) as lock_fd:
                    boundary = self.workspace._build_boundary(paths, lock_fd)
                    if not eligible(boundary):
                        continue
                    self.workspace._active_boundary = boundary
                    try:
                        yield boundary
                    finally:
                        self.workspace._active_boundary = None
                    return
            except WorkspaceBusyError:
                continue
        yield None
