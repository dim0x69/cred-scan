"""One exclusively owned boundary's inventory, scan, judgment, and evidence."""

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
from cred_scan.backend.models import BoundaryRecord, ScanTargetInventory, ScanTarget
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.orch.fsync import fsync_directory
from cred_scan.orch.locking import boundary_lock
from cred_scan.orch.models import BoundaryPaths
from cred_scan.judge.dspy_adapter import DspyFindingJudge
from cred_scan.extract.evidence import (
    EvidenceConflictError,
    EvidenceExtractor,
    evidence_exists,
)
from cred_scan.judge.proto import FatalJudgeError
from cred_scan.orch.credentials import merge_scan
from cred_scan.scan.credentials import deduplicate_report
from cred_scan.extract.models import ExtractionResult
from cred_scan.scan.models import (
    CredentialsDocument,
    JudgmentResult,
    TitusReport,
)
from cred_scan.scan.titus import TitusCliScanner

LOGGER = logging.getLogger(__name__)
DocumentT = TypeVar("DocumentT", bound=BaseModel)


class Boundary:
    """Mutable aggregate loaded only while its boundary is exclusively owned."""

    def __init__(self, backend: BackendAdapter, path: Path) -> None:
        self.boundary_id = unquote(path.name)
        self.paths = BoundaryPaths(
            boundary_id=self.boundary_id,
            boundary_dir=path,
        )

        self.backend = backend
        self.reader: ContentReader | None = None
        self.judge_service: DspyFindingJudge | None = None
        self.scanner: TitusCliScanner | None = None
        self._operation_lock = asyncio.Lock()
        self.extractor: EvidenceExtractor | None = None

    def _load(self) -> None:
        """Load the aggregate while holding boundary ownership."""
        record = self._read(self.paths.record, BoundaryRecord)
        if record is None:
            raise ValueError(f"missing boundary record: {self.paths.record}")
        if record.boundary.id != self.boundary_id:
            raise ValueError(
                "boundary record does not match boundary path: "
                f"{self.paths.record}"
            )
        if record.backend_id != self.backend.name:
            raise ValueError(
                "boundary record belongs to another backend: "
                f"{self.paths.record}"
            )
        if record.availability != "available":
            raise ValueError(f"boundary is not available: {self.boundary_id}")
        inventory = self._read(
            self.paths.scan_targets,
            ScanTargetInventory,
        )
        if inventory is None:
            raise ValueError(
                f"missing boundary scan targets: {self.paths.scan_targets}"
            )
        if inventory.boundary.id != self.boundary_id:
            raise ValueError(
                "boundary scan targets do not match boundary path: "
                f"{self.paths.scan_targets}"
            )
        self.record = record
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

        self.inventory: ScanTargetInventory = inventory
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
        """Close an active reader, if command cleanup was interrupted."""
        if self.reader is not None:
            await self.reader.aclose()
            self.reader = None

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
        """Own one boundary from state load through command cleanup."""
        async with self._operation_lock:
            with boundary_lock(self.paths.operation_lock) as descriptor:
                self._load()
                try:
                    self._start_services(descriptor)
                    yield self
                finally:
                    await self._stop_services()

    def _start_services(self, descriptor: int) -> None:
        self.reader = self.backend.content_reader(self.scratch_dir)
        self.scanner = TitusCliScanner(self.inventory, self.backend)
        self.scanner.lock_fd = descriptor
        self.judge_service = DspyFindingJudge()
        self.extractor = EvidenceExtractor(self.paths.boundary_dir)

    async def _stop_services(self) -> None:
        if self.scanner is not None:
            self.scanner.lock_fd = None
        if self.reader is not None:
            await self.reader.aclose()
        self.reader = None
        self.judge_service = None
        self.scanner = None
        self.extractor = None

    def checkpoint(self) -> None:
        """Persist this boundary's current aggregate."""
        self._write(
            self.paths.scan_targets,
            self.inventory,
            ScanTargetInventory,
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
        if self.inventory.publication_pending:
            return True
        if not self.inventory.targets:
            return False
        return (
            not self._has_report
            or not self._has_credentials
            or any(
                (
                    target.result.status in {"pending", "running"}
                    or (
                        target.result.status in {"failed", "partial"}
                        and target.result.retryable
                    )
                )
                for target in self.inventory.targets
            )
        )

    async def refresh_inventory(self) -> bool:
        async with self._operation_lock:
            with boundary_lock(self.paths.operation_lock):
                current = self._read(
                    self.paths.scan_targets,
                    ScanTargetInventory,
                )
                if current is not None and current.boundary.id != self.boundary_id:
                    raise ValueError(
                        "boundary scan targets do not match boundary path: "
                        f"{self.paths.scan_targets}"
                    )
                discovered = await self.backend.inventory(self.boundary_id)
                if discovered.boundary.id != self.boundary_id:
                    raise ValueError("backend returned inventory for another boundary")
                merged = merge_inventory(current, discovered)
                record = BoundaryRecord(
                    backend_id=self.backend.name,
                    boundary=merged.boundary,
                )
                self._write(
                    self.paths.scan_targets,
                    merged,
                    ScanTargetInventory,
                )
                self._write(
                    self.paths.record,
                    record,
                    BoundaryRecord,
                )
                self.record = record
                self.inventory = merged
                return True

    async def mark_absent(self) -> bool:
        async with self._operation_lock:
            with boundary_lock(self.paths.operation_lock):
                record = self._read(self.paths.record, BoundaryRecord)
                if record is None:
                    raise ValueError(f"missing boundary record: {self.paths.record}")
                if record.boundary.id != self.boundary_id:
                    raise ValueError(
                        "boundary record does not match boundary path: "
                        f"{self.paths.record}"
                    )
                if record.backend_id != self.backend.name:
                    raise ValueError(
                        "boundary record belongs to another backend: "
                        f"{self.paths.record}"
                    )
                absent = record.model_copy(
                    update={"availability": "absent"}
                )
                self._write(self.paths.record, absent, BoundaryRecord)
                self.paths.scan_targets.unlink(missing_ok=True)
                fsync_directory(self.paths.boundary_dir)
                self.record = absent
                return True

    async def scan(self) -> bool:
        async with self.operation():
            if not self.needs_scan():
                return False
            await self._scan()
            return True

    async def _scan(self) -> None:
        scanner = self.scanner
        reader = self.reader
        assert scanner is not None
        assert reader is not None
        self.inventory.publication_pending = True
        self.checkpoint()
        scanner.inventory = self.inventory
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
            if (
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
            await self._scan_target(target)
            self.checkpoint()
            LOGGER.info(
                "scanned target=%s status=%s retryable=%s",
                target.id,
                target.result.status,
                target.result.retryable,
            )
            self._log_scan_errors(target)

        incomplete = bool(self.inventory.errors) or any(
            target.result.status != "scanned" for target in self.inventory.targets
        )

        report = await scanner.export_report(self.paths.datastore)
        report.incomplete = report.incomplete or incomplete
        report.errors = tuple(report.errors) + self.inventory.errors
        self.report = report
        self._has_report = True
        self.checkpoint()

        candidates = await deduplicate_report(
            self.report,
            self.inventory,
            reader,
        )

        self.credentials = merge_scan(self.credentials, candidates)
        self._has_credentials = True
        self.checkpoint()
        # Clear only after the report and merged credentials are durable.
        self.inventory.publication_pending = False
        self.checkpoint()

        LOGGER.info(
            "scan complete boundary=%s candidates=%d incomplete=%s",
            self.boundary_id,
            len(self.credentials.credentials),
            self.credentials.incomplete,
        )

    def _log_scan_errors(self, target: ScanTarget) -> None:
        if target.result.errors:
            LOGGER.error(
                "scan target=%s errors=%s",
                target.id,
                "; ".join(target.result.errors),
            )

    async def _scan_target(self, target: ScanTarget) -> None:
        """Own one target's scratch and all attempts on the same scanner."""
        scanner = self.scanner
        assert scanner is not None
        with self.scratch_dir() as work_dir:
            for attempt in range(3):
                LOGGER.info("scanning target=%s attempt=%d/3", target.id, attempt + 1)
                await scanner.scan(target, work_dir, self.paths.datastore)
                if (
                    target.result.status == "scanned"
                    or not target.result.retryable
                    or attempt == 2
                ):
                    return
                target.result.status = "running"

    async def judge(self) -> int:
        async with self.operation():
            return await self._judge()

    async def _judge(self) -> int:
        judge_service = self.judge_service
        reader = self.reader
        assert judge_service is not None
        assert reader is not None
        selected = tuple(
            credential
            for credential in self.credentials.credentials.values()
            if credential.judgment.verdict in {"PENDING", "ERROR"}
        )
        for credential in selected:
            try:
                result = await judge_service.judge(
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
        return len(selected)

    async def extract(self) -> int:
        async with self.operation():
            return await self._extract()

    async def _extract(self) -> int:
        extractor = self.extractor
        reader = self.reader
        assert extractor is not None
        assert reader is not None
        credentials = tuple(self.credentials.credentials.values())
        for credential in credentials:
            if credential.extraction is not None and credential.extraction.status == "RETAINED":
                if not evidence_exists(
                    self.paths.boundary_dir, credential.credential_id, credential.extraction
                ):
                    LOGGER.error(
                        "retained evidence missing boundary=%s credential=%s path=%s; "
                        "automatic replacement disabled",
                        self.boundary_id,
                        credential.credential_id,
                        credential.extraction.output_path,
                    )

        selected = tuple(
            credential
            for credential in credentials
            if credential.judgment.verdict in {"VALID", "UNKNOWN"}
            and (
                credential.extraction is None
                or credential.extraction.status == "ERROR"
            )
        )
        for credential in selected:
            try:
                extraction = await extractor.extract(credential, reader)
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
        return len(selected)
