"""One fully loaded boundary's inventory, scan, judgment, and evidence operations."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar
from urllib.parse import unquote

from pydantic import BaseModel

if TYPE_CHECKING:
    from cred_scan.orch.workspace import Workspace

from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import ContentLocation, ContentRead, ScanBoundaryInventory
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.common.models import BoundaryPaths
from cred_scan.common.filesystem import (
    ResourceBusyError,
    fsync_directory,
    scratch_dir as create_scratch_dir,
)
from cred_scan.judge.dspy_adapter import DspyFindingJudge
from cred_scan.judge.evidence import (
    EvidenceConflictError,
    evidence_path,
    retain_first_evidence,
)
from cred_scan.judge.proto import FatalJudgeError
from cred_scan.orch.credentials import merge_scan
from cred_scan.scan.credentials import deduplicate_report
from cred_scan.scan.models import (
    CredentialsDocument,
    ExclusionPolicy,
    ExtractionResult,
    JudgmentResult,
    TitusReport,
)
from cred_scan.scan.titus import TitusScannerPool

LOGGER = logging.getLogger(__name__)
DocumentT = TypeVar("DocumentT", bound=BaseModel)


@contextmanager
def _boundary_lock(path: Path) -> Iterator[None]:
    """Own a boundary with an atomically created sentinel file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as stream:
            stream.write("locked\n")
    except FileExistsError as error:
        raise ResourceBusyError(
            f"boundary operation already active: {path.parent}"
        ) from error

    try:
        yield
    finally:
        path.unlink(missing_ok=True)


class ReadSession:
    """Reuse bytes for one credential's judgment session."""

    def __init__(self, reader: ContentReader) -> None:
        self.reader = reader
        self._cache: dict[tuple[str, str, str, str], ContentRead] = {}
        self._closed = False

    @property
    def boundary_id(self) -> str:
        explicit = getattr(self.reader, "boundary_id", None)
        if isinstance(explicit, str):
            return explicit
        boundary = getattr(self.reader, "boundary", None)
        if boundary is not None and isinstance(boundary.id, str):
            return boundary.id
        raise AttributeError("backend reader does not expose a boundary ID")

    async def resolve_location(self, raw_path: str) -> ContentLocation:
        return await self.reader.resolve_location(raw_path)

    async def read(self, location: ContentLocation | str) -> ContentRead:
        if self._closed:
            raise RuntimeError("content session is closed")
        if isinstance(location, str):
            location = await self.resolve_location(location)
        key = (
            location.target_id,
            location.locator,
            location.source_path,
            location.filename,
        )
        cached = self._cache.get(key)
        if cached is None:
            result = await self.reader.read(location)
            if isinstance(result, bytes):
                result = ContentRead(
                    content=result,
                    source_path=location.source_path,
                    filename=location.filename,
                )
            self._cache[key] = result
            cached = result
        return cached

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cache.clear()
        await self.reader.aclose()


class Boundary:
    """Fully loaded mutable aggregate for one persisted report boundary."""

    def __init__(self, workspace: Workspace, path: Path) -> None:
        self.workspace = workspace
        self.boundary_id = unquote(path.name)
        self.paths = BoundaryPaths(
            boundary_id=self.boundary_id,
            boundary_dir=path,
        )

        # Construction reads one consistent boundary snapshot. The lock is a
        # simple sentinel because Workspace is the sole process owner.
        with _boundary_lock(self.paths.operation_lock):
            inventory = self._read(
                self.paths.inventory,
                ScanBoundaryInventory,
            )
            if inventory is None:
                raise ValueError(
                    f"missing boundary inventory: {self.paths.inventory}"
                )
            if inventory.boundary.id != self.boundary_id:
                raise ValueError(
                    "boundary inventory does not match boundary path: "
                    f"{self.paths.inventory}"
                )
            if inventory.backend.name != workspace.backend.name:
                raise ValueError(
                    "boundary inventory belongs to another configured backend"
                )

            report = self._read(self.paths.report, TitusReport)
            if report is not None and report.boundary_id != self.boundary_id:
                raise ValueError(
                    f"report belongs to another boundary: {self.paths.report}"
                )

            credentials = self._read(
                self.paths.credentials,
                CredentialsDocument,
            )
            if (
                credentials is not None
                and credentials.boundary_id != self.boundary_id
            ):
                raise ValueError(
                    "credentials belong to another boundary: "
                    f"{self.paths.credentials}"
                )

            self.inventory: ScanBoundaryInventory = inventory
            self.report: TitusReport = report or TitusReport(
                boundary_id=self.boundary_id,
                generated_at="",
                incomplete=True,
            )
            self.credentials: CredentialsDocument = credentials or (
                CredentialsDocument(
                    boundary_id=self.boundary_id,
                    report_generated_at="",
                    incomplete=True,
                )
            )
            self._has_report = report is not None
            self._has_credentials = credentials is not None

        self.backend: BackendAdapter = workspace.backend
        self.policy: ExclusionPolicy = workspace.policy
        self.judge_service = DspyFindingJudge(workspace.config)
        self.scanners = TitusScannerPool(
            workspace.config.titus,
            self.inventory,
            self.backend,
            concurrency=workspace.config.scan_concurrency,
            environment={
                "ARTIFACTORY_PASSWORD": (
                    workspace.config.artifactory_api_key or ""
                ),
                "ARTIFACTORY_TOKEN": (
                    workspace.config.artifactory_api_key or ""
                ),
                "ARTIFACTORY_API_KEY": (
                    workspace.config.artifactory_api_key or ""
                ),
            },
            scratch_dir=self.scratch_dir,
        )
        self._operation_active = False

    @staticmethod
    def _read(
        path: Path,
        model_type: type[DocumentT],
    ) -> DocumentT | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        return model_type.model_validate(payload)

    def _write(
        self,
        path: Path,
        document: DocumentT,
        model_type: type[DocumentT],
    ) -> None:
        """Atomically write one document while this boundary owns its lock."""
        if not self._operation_active:
            raise RuntimeError(
                "boundary document write requires the boundary operation"
            )
        if not isinstance(document, model_type):
            raise TypeError(
                f"expected {model_type.__name__}, got {type(document).__name__}"
            )

        validated = model_type.model_validate(
            document.model_dump(mode="json")
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(
                    validated.model_dump(mode="json"),
                    stream,
                    indent=2,
                    sort_keys=True,
                )
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

    @contextmanager
    def scratch_dir(self) -> Iterator[Path]:
        """Own one temporary scratch child for this boundary."""
        with create_scratch_dir(self.paths.scratch_parent) as directory:
            yield directory

    @contextmanager
    def operation(self) -> Iterator[Boundary]:
        """Own this boundary for one serialized operation."""
        if self._operation_active:
            raise RuntimeError(
                f"boundary operation already active: {self.boundary_id}"
            )

        self._operation_active = True
        try:
            with _boundary_lock(self.paths.operation_lock):
                yield self
        finally:
            self._operation_active = False

    def checkpoint(self) -> None:
        """Persist this boundary's current aggregate."""
        if not self._operation_active:
            raise RuntimeError(
                "boundary checkpoint requires the boundary operation"
            )

        self._write(
            self.paths.inventory,
            self.inventory,
            ScanBoundaryInventory,
        )
        if self._has_report:
            self._write(self.paths.report, self.report, TitusReport)
        if self._has_credentials:
            self._write(
                self.paths.credentials,
                self.credentials,
                CredentialsDocument,
            )

    def needs_scan(self) -> bool:
        if self.inventory.lifecycle == "stale":
            return False
        return not self._has_report or not self._has_credentials or any(
            target.lifecycle == "current"
            and target.scope.lifecycle == "active"
            and (
                target.result.status in {"pending", "running"}
                or (
                    target.result.status in {"failed", "partial"}
                    and target.result.retryable
                )
            )
            for target in self.inventory.targets
        )

    def needs_judge(self) -> bool:
        return any(
            credential.judgment.verdict in {"PENDING", "ERROR"}
            for credential in self.credentials.credentials.values()
        )

    def needs_extract(self) -> bool:
        return any(
            credential.judgment.verdict == "VALID"
            and (
                credential.extraction is None
                or credential.extraction.status == "ERROR"
            )
            for credential in self.credentials.credentials.values()
        )

    async def refresh_inventory(self) -> bool:
        with self.operation():
            try:
                discovered = await self.backend.inventory(self.boundary_id)
            except KeyError:
                self.inventory.lifecycle = "stale"
                self.inventory.stale_reason = (
                    "boundary absent from authoritative inventory"
                )
                self.checkpoint()
                return True

            if discovered.boundary.id != self.boundary_id:
                raise ValueError(
                    "backend returned inventory for another boundary"
                )

            self.inventory = merge_inventory(self.inventory, discovered)
            self.scanners.inventory = self.inventory
            self.checkpoint()
            return True

    async def scan(self) -> bool:
        with self.operation():
            if not self.needs_scan():
                return False
            await self._scan()
            return True

    async def _scan(self) -> None:
        if self.inventory.lifecycle == "stale":
            raise ValueError("cannot scan a stale boundary")

        self.scanners.inventory = self.inventory
        interrupted = [
            target
            for target in self.inventory.targets
            if target.result.status == "running"
        ]
        for target in interrupted:
            target.result.status = "pending"
        if interrupted:
            self.checkpoint()

        eligible = tuple(
            target
            for target in self.inventory.targets
            if target.lifecycle == "current"
            and target.scope.lifecycle == "active"
            and (
                target.result.status in {"pending", "running"}
                or (
                    target.result.status in {"failed", "partial"}
                    and target.result.retryable
                )
            )
        )
        for target in eligible:
            target.result.status = "running"
            target.result.errors = ()
            target.result.return_code = None
            target.result.started_at = datetime.now(UTC)
            target.result.finished_at = None
        if eligible:
            self.checkpoint()

        LOGGER.info(
            "scanning boundary=%s targets=%d concurrency=%d",
            self.boundary_id,
            len(eligible),
            self.scanners.concurrency,
        )
        results = await self.scanners.scan(
            tuple(target.model_copy(deep=True) for target in eligible),
            self.paths.datastore,
            self.policy,
        )
        for target in results:
            self.inventory.complete_target(target)
            self.checkpoint()
            LOGGER.info(
                "scanned target=%s status=%s retryable=%s",
                target.id,
                target.result.status,
                target.result.retryable,
            )
            if target.result.errors:
                LOGGER.error(
                    "scan target=%s errors=%s",
                    target.id,
                    "; ".join(target.result.errors),
                )

        active_targets = tuple(
            target
            for target in self.inventory.targets
            if target.lifecycle == "current"
            and target.scope.lifecycle == "active"
        )
        incomplete = bool(self.inventory.errors) or any(
            target.result.status != "scanned" for target in active_targets
        )

        if not self.inventory.targets:
            generated_at = datetime.now(UTC).isoformat()
            self.report = TitusReport(
                boundary_id=self.boundary_id,
                generated_at=generated_at,
                incomplete=True,
                errors=self.inventory.errors,
            )
            self.credentials = CredentialsDocument(
                boundary_id=self.boundary_id,
                report_generated_at=generated_at,
                incomplete=True,
                errors=self.inventory.errors,
            )
            self._has_report = True
            self._has_credentials = True
            self.checkpoint()
        else:
            report = await self.scanners.export_report(self.paths.datastore)
            self.report = report.model_copy(
                update={
                    "incomplete": report.incomplete or incomplete,
                    "errors": tuple(report.errors) + self.inventory.errors,
                }
            )
            self._has_report = True
            self.checkpoint()

            resolver = self.backend.content_reader(
                self.inventory.boundary,
                self.inventory.targets,
                self.scratch_dir,
            )
            try:
                candidates = await deduplicate_report(
                    self.report,
                    self.inventory,
                    self.policy,
                    resolver,
                )
            finally:
                await resolver.aclose()

            self.credentials = merge_scan(self.credentials, candidates)
            self._has_credentials = True
            self.checkpoint()

        LOGGER.info(
            "scan complete boundary=%s candidates=%d incomplete=%s",
            self.boundary_id,
            len(self.credentials.credentials),
            self.credentials.incomplete,
        )

    async def judge(self) -> int:
        with self.operation():
            if not self.needs_judge():
                return 0
            return await self._judge()

    async def _judge(self) -> int:
        judged = 0
        for credential in tuple(self.credentials.credentials.values()):
            if credential.judgment.verdict not in {"PENDING", "ERROR"}:
                continue

            judged += 1
            reader: ReadSession | None = None
            try:
                try:
                    reader = ReadSession(
                        self.backend.content_reader(
                            self.inventory.boundary,
                            self.inventory.targets,
                            self.scratch_dir,
                        )
                    )
                    result = await self.judge_service.judge(
                        credential,
                        reader,
                    )
                except FatalJudgeError:
                    raise
                except Exception as error:
                    LOGGER.exception(
                        "judgment failed boundary=%s credential=%s",
                        self.boundary_id,
                        credential.credential_id,
                    )
                    result = JudgmentResult(
                        verdict="ERROR",
                        reasoning=str(error)[:500],
                    )

                credential.judgment = result
                self.checkpoint()
            finally:
                if reader is not None:
                    await reader.aclose()
        return judged

    async def extract(self) -> int:
        with self.operation():
            if not self.needs_extract():
                return 0
            return await self._extract()

    async def _extract(self) -> int:
        retained = 0
        for credential in tuple(self.credentials.credentials.values()):
            if credential.judgment.verdict != "VALID":
                continue
            if not (
                credential.extraction is None
                or credential.extraction.status == "ERROR"
            ):
                continue

            reader: ReadSession | None = None
            try:
                try:
                    reader = ReadSession(
                        self.backend.content_reader(
                            self.inventory.boundary,
                            self.inventory.targets,
                            self.scratch_dir,
                        )
                    )
                    location = await reader.resolve_location(
                        credential.occurrences[0].locator
                    )
                    content = await reader.read(location)
                    destination = evidence_path(
                        self.paths.boundary_dir,
                        credential.credential_id,
                        content.filename,
                    )
                    _, size, sha256 = await retain_first_evidence(
                        content.content,
                        destination,
                    )
                    extraction = ExtractionResult(
                        status="RETAINED",
                        output_path=destination.relative_to(
                            self.paths.boundary_dir
                        ).as_posix(),
                        size=size,
                        sha256=sha256,
                    )
                    retained += 1
                except EvidenceConflictError:
                    raise
                except Exception as error:
                    LOGGER.exception(
                        "evidence extraction failed boundary=%s credential=%s",
                        self.boundary_id,
                        credential.credential_id,
                    )
                    extraction = ExtractionResult(
                        status="ERROR",
                        error=str(error)[:500],
                    )

                credential.extraction = extraction
                self.checkpoint()
            finally:
                if reader is not None:
                    await reader.aclose()
        return retained
