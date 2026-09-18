"""One boundary's inventory, scan, judgment, and evidence operations."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cred_scan.orch.workspace import Workspace

from cred_scan.backend.models import ContentLocation, ContentRead, ScanBoundaryInventory
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.common.models import BoundaryPaths
from cred_scan.judge.evidence import (
    EvidenceConflictError,
    evidence_path,
    retain_first_evidence,
)
from cred_scan.judge.proto import FatalJudgeError, FindingJudge
from cred_scan.backend.inventory import merge_inventory
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


class ReadSession:
    """Reuse bytes for one credential's judgment and immediate evidence only."""

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
    """Mutable aggregate for one report boundary."""

    def __init__(
        self,
        inventory: ScanBoundaryInventory,
        workspace: Workspace,
        *,
        paths: BoundaryPaths,
        backend: BackendAdapter,
        document: CredentialsDocument | None,
        report: TitusReport | None,
        scanners: TitusScannerPool,
        judge: FindingJudge,
        policy: ExclusionPolicy,
    ) -> None:
        self.inventory = inventory
        self.workspace = workspace
        self.paths = paths
        self.backend = backend
        self.document = document
        self.report = report
        self.scanners = scanners
        self.judge_service = judge
        self.policy = policy
        if document is not None:
            self._validate_document_boundary(document)

    @property
    def boundary_id(self) -> str:
        return self.inventory.boundary.id


    def needs_scan(self) -> bool:
        if self.inventory.lifecycle == "stale":
            return False
        return self.report is None or self.document is None or any(
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
        return self.document is not None and any(
            credential.judgment.verdict in {"PENDING", "ERROR"}
            for credential in self.document.credentials.values()
        )

    def needs_extract(self) -> bool:
        return self.document is not None and any(
            credential.judgment.verdict == "VALID"
            and (
                credential.extraction is None
                or credential.extraction.status == "ERROR"
            )
            for credential in self.document.credentials.values()
        )

    def checkpoint(self) -> None:
        self.workspace.checkpoint(self)

    async def refresh_inventory(self) -> None:
        """Refresh this boundary's pins and persist the in-memory aggregate."""
        try:
            discovered = await self.backend.inventory(self.boundary_id)
        except KeyError:
            self.inventory.lifecycle = "stale"
            self.inventory.stale_reason = "boundary absent from authoritative inventory"
            self.checkpoint()
            return
        if discovered.boundary.id != self.boundary_id:
            raise ValueError("backend returned inventory for another boundary")
        self.inventory = merge_inventory(self.inventory, discovered)
        self.checkpoint()

    async def scan(self) -> None:
        """Scan this boundary and publish its final credential checkpoint."""
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
            self.paths.scratch_parent,
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
            self.document = CredentialsDocument(
                boundary_id=self.boundary_id,
                report_generated_at=generated_at,
                incomplete=True,
                errors=self.inventory.errors,
            )
            self.checkpoint()
        else:
            report = await self.scanners.export_report(self.paths.datastore)
            self.report = report.model_copy(
                update={
                    "incomplete": report.incomplete or incomplete,
                    "errors": tuple(report.errors) + self.inventory.errors,
                }
            )
            self.checkpoint()
            resolver = self.backend.content_reader(
                self.inventory.boundary, self.inventory.targets
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
            self.document = merge_scan(self.document, candidates)
            self.checkpoint()

        LOGGER.info(
            "scan complete boundary=%s candidates=%d incomplete=%s",
            self.boundary_id,
            len(self.document.credentials) if self.document is not None else 0,
            self.document.incomplete if self.document is not None else True,
        )

    def _validate_document_boundary(self, document: CredentialsDocument) -> None:
        if document.boundary_id != self.boundary_id:
            raise ValueError("credentials document belongs to another boundary")

    @staticmethod
    def _error_result(error: BaseException) -> JudgmentResult:
        return JudgmentResult(verdict="ERROR", reasoning=str(error)[:500])

    async def judge(self) -> int:
        """Judge pending and failed candidates without extracting evidence."""
        if self.document is None:
            raise RuntimeError("boundary has no published credentials")
        self._validate_document_boundary(self.document)
        judged = 0
        for credential in tuple(self.document.credentials.values()):
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
                        )
                    )
                    result = await self.judge_service.judge(credential, reader)
                except FatalJudgeError:
                    raise
                except Exception as error:
                    LOGGER.exception(
                        "judgment failed boundary=%s credential=%s",
                        self.boundary_id,
                        credential.credential_id,
                    )
                    result = self._error_result(error)
                credential.judgment = result
                self.checkpoint()
            finally:
                if reader is not None:
                    await reader.aclose()
        return judged

    async def extract(self) -> int:
        """Retain evidence for VALID candidates with missing or failed extraction."""
        if self.document is None:
            raise RuntimeError("boundary has no published credentials")
        self._validate_document_boundary(self.document)
        retained = 0
        for credential in tuple(self.document.credentials.values()):
            if credential.judgment.verdict != "VALID" or not (
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
