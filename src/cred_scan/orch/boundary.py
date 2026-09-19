"""One fully loaded boundary's inventory, scan, judgment, and evidence operations."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypeVar
from urllib.parse import unquote

from pydantic import BaseModel

from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import ScanBoundaryInventory, ScanTarget
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.orch.fsync import fsync_directory
from cred_scan.orch.models import BoundaryPaths
from cred_scan.judge.dspy_adapter import DspyFindingJudge
from cred_scan.judge.evidence import (
    EvidenceConflictError,
    EvidenceExtractor,
)
from cred_scan.judge.proto import FatalJudgeError
from cred_scan.orch.credentials import merge_scan
from cred_scan.scan.credentials import deduplicate_report
from cred_scan.scan.models import (
    CredentialsDocument,
    ExtractionResult,
    JudgmentResult,
    TitusReport,
)
from cred_scan.scan.titus import TitusCliScanner

LOGGER = logging.getLogger(__name__)
DocumentT = TypeVar("DocumentT", bound=BaseModel)


class BoundaryBusyError(FileExistsError):
    """Another operation owns this boundary's persisted sentinel."""


class Boundary:
    """Fully loaded mutable aggregate for one persisted report boundary."""

    def __init__(self, backend: BackendAdapter, path: Path) -> None:
        self.boundary_id = unquote(path.name)
        self.paths = BoundaryPaths(
            boundary_id=self.boundary_id,
            boundary_dir=path,
        )

        # Construction reads one consistent boundary snapshot.
        with self._lock():
            inventory = self._read(
                self.paths.inventory,
                ScanBoundaryInventory,
            )
            if inventory is None:
                raise ValueError(f"missing boundary inventory: {self.paths.inventory}")
            if inventory.boundary.id != self.boundary_id:
                raise ValueError(
                    "boundary inventory does not match boundary path: "
                    f"{self.paths.inventory}"
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
            if credentials is not None and credentials.boundary_id != self.boundary_id:
                raise ValueError(
                    f"credentials belong to another boundary: {self.paths.credentials}"
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

        self.backend = backend
        self.reader: ContentReader = self.backend.content_reader(
            self.scratch_dir,
        )
        self.judge_service = DspyFindingJudge()
        self.scanner = TitusCliScanner(self.inventory, self.backend)
        self._operation_active = False
        self._operation_lock = asyncio.Lock()
        self.extractor = EvidenceExtractor(self.paths.boundary_dir)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        """Own this boundary with an atomically created sentinel file."""
        path = self.paths.operation_lock
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            stream = path.open("x", encoding="utf-8")
        except FileExistsError as error:
            raise BoundaryBusyError(f"boundary busy: {self.boundary_id}") from error

        try:
            with stream:
                stream.write("locked\n")
            yield
        finally:
            path.unlink(missing_ok=True)

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

        validated = model_type.model_validate(document.model_dump(mode="json"))
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

    async def aclose(self) -> None:
        """Close the boundary reader and release its scratch context."""
        await self.reader.aclose()

    @contextmanager
    def scratch_dir(self) -> Iterator[Path]:
        """Own one temporary scratch child for this boundary."""
        parent = self.paths.scratch_parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            with TemporaryDirectory(prefix="scratch-", dir=parent) as directory:
                yield Path(directory)
        finally:
            try:
                parent.rmdir()
            except OSError:
                pass

    @asynccontextmanager
    async def operation(self) -> AsyncIterator[Boundary]:
        """Serialize this boundary's stages without blocking other boundaries."""
        async with self._operation_lock:
            with self._lock():
                self._operation_active = True
                try:
                    yield self
                finally:
                    self._operation_active = False

    def checkpoint(self) -> None:
        """Persist this boundary's current aggregate."""
        if not self._operation_active:
            raise RuntimeError("boundary checkpoint requires the boundary operation")

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
        return (
            not self._has_report
            or not self._has_credentials
            or any(
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
                credential.extraction is None or credential.extraction.status == "ERROR"
            )
            for credential in self.credentials.credentials.values()
        )

    async def refresh_inventory(self) -> bool:
        async with self.operation():
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
                raise ValueError("backend returned inventory for another boundary")

            await self.reader.aclose()
            self.inventory = merge_inventory(self.inventory, discovered)
            self.reader = self.backend.content_reader(
                self.scratch_dir,
            )
            self.scanner.inventory = self.inventory
            self.checkpoint()
            return True

    async def scan(self) -> bool:
        async with self.operation():
            if not self.needs_scan():
                return False
            await self._scan()
            return True

    async def _scan(self) -> None:
        if self.inventory.lifecycle == "stale":
            raise ValueError("cannot scan a stale boundary")

        self.scanner.inventory = self.inventory
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
        LOGGER.info("scanning boundary=%s targets=%d", self.boundary_id, len(eligible))
        for target in eligible:
            target.result.status = "running"
            target.result.errors = ()
            target.result.return_code = None
            target.result.started_at = datetime.now(UTC)
            target.result.finished_at = None
            self.checkpoint()
            result = await self._scan_target(target.model_copy(deep=True))
            self.inventory.complete_target(result)
            self.checkpoint()
            LOGGER.info(
                "scanned target=%s status=%s retryable=%s",
                result.id,
                result.result.status,
                result.result.retryable,
            )
            if result.result.errors:
                LOGGER.error(
                    "scan target=%s errors=%s",
                    result.id,
                    "; ".join(result.result.errors),
                )

        active_targets = tuple(
            target
            for target in self.inventory.targets
            if target.lifecycle == "current" and target.scope.lifecycle == "active"
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
            report = await self.scanner.export_report(self.paths.datastore)
            self.report = report.model_copy(
                update={
                    "incomplete": report.incomplete or incomplete,
                    "errors": tuple(report.errors) + self.inventory.errors,
                }
            )
            self._has_report = True
            self.checkpoint()

            candidates = await deduplicate_report(
                self.report,
                self.inventory,
                self.reader,
            )

            self.credentials = merge_scan(self.credentials, candidates)
            self._has_credentials = True
            self.checkpoint()

        LOGGER.info(
            "scan complete boundary=%s candidates=%d incomplete=%s",
            self.boundary_id,
            len(self.credentials.credentials),
            self.credentials.incomplete,
        )

    async def _scan_target(self, target: ScanTarget) -> ScanTarget:
        """Own one target's scratch and all attempts on the same scanner."""
        with self.scratch_dir() as work_dir:
            for attempt in range(3):
                LOGGER.info("scanning target=%s attempt=%d/3", target.id, attempt + 1)
                target = await self.scanner.scan(
                    target, work_dir, self.paths.datastore
                )
                if (
                    target.result.status == "scanned"
                    or not target.result.retryable
                    or attempt == 2
                ):
                    return target
                target.result.status = "running"
        raise AssertionError("scan attempts finished without a result")

    async def judge(self) -> int:
        async with self.operation():
            if not self.needs_judge():
                return 0
            return await self._judge()

    async def _judge(self) -> int:
        judged = 0
        for credential in tuple(self.credentials.credentials.values()):
            if credential.judgment.verdict not in {"PENDING", "ERROR"}:
                continue

            judged += 1
            try:
                result = await self.judge_service.judge(
                    credential,
                    self.reader,
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
        return judged

    async def extract(self) -> int:
        async with self.operation():
            if not self.needs_extract():
                return 0
            return await self._extract()

    async def _extract(self) -> int:
        retained = 0
        for credential in tuple(self.credentials.credentials.values()):
            if credential.judgment.verdict != "VALID":
                continue
            if not (
                credential.extraction is None or credential.extraction.status == "ERROR"
            ):
                continue

            try:
                extraction = await self.extractor.extract(credential, self.reader)
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
        return retained
