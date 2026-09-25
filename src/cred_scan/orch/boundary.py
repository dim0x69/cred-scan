"""Boundary stage execution and final-write phase handoffs."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypeVar
from urllib.parse import unquote

from pydantic import BaseModel

from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import (
    BoundaryRecord,
    ScanTargetInventory,
    ScanTarget,
    BoundaryPhase,
    SourceStage,
    PHASE_ORDER,
)
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.orch.fsync import fsync_directory
from cred_scan.orch.json_io import write_json_atomic
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
    """Mutable aggregate selected by phase under the single-writer operating rule."""

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
        self.extractor: EvidenceExtractor | None = None

    def _load(self) -> bool:
        """Load available state after stage selection.

        Return false for a registered but absent boundary; its scan-target
        document is intentionally absent and no source state should be loaded.
        """
        record = self._read(self.paths.record, BoundaryRecord)
        if record is None:
            raise ValueError(f"missing boundary record: {self.paths.record}")
        self.record = record
        if record.availability == "absent":
            return False
        inventory = self._read(
            self.paths.scan_targets,
            ScanTargetInventory,
        )
        if inventory is None:
            raise ValueError(
                f"missing boundary scan targets: {self.paths.scan_targets}"
            )
        self.record = record
        report = self._read(self.paths.report, TitusReport)

        credentials = self._read(
            self.paths.credentials,
            CredentialsDocument,
        )
        if record.phase != "scan" and (report is None or credentials is None):
            raise ValueError(
                f"phase {record.phase} requires published report and credentials: "
                f"{self.paths.boundary_dir}"
            )

        self.inventory: ScanTargetInventory = inventory
        self.report: TitusReport = report or TitusReport(
            boundary_id=self.boundary_id,
            generated_at="",
        )
        self.credentials: CredentialsDocument = credentials or (
            CredentialsDocument(
                boundary_id=self.boundary_id,
                report_generated_at="",
            )
        )
        self._has_report = report is not None
        self._has_credentials = credentials is not None
        return True

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
        """Atomically write one complete boundary document."""
        if not isinstance(document, model_type):
            raise TypeError(
                f"expected {model_type.__name__}, got {type(document).__name__}"
            )

        validated = model_type.model_validate(document.model_dump(mode="json"))
        write_json_atomic(path, validated.model_dump(mode="json"))

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

    def eligible(self, stage: SourceStage, *, failed: bool = False) -> bool:
        """Whether this boundary belongs in the requested command's finite batch.

        Workspace calls this while selecting boundaries once at invocation start;
        operation() rechecks it before loading the selected boundary's state.
        Read boundary.json first, so unfinished upstream work is excluded before
        reading inventory or credentials. Absent boundaries are always excluded.

        A matching phase permits normal processing, even with no pending items:
        the stage may still need to finish publication or its phase handoff.
        Extract also includes done boundaries for read-only evidence auditing.
        With failed=True, saved failures can additionally make a later-phase
        boundary eligible for explicit re-entry, never an earlier-phase one.

        This only reads persisted state; it creates no services, requeues no
        items, and changes no phase. operation() handles any requested retries.
        Eligibility does not acquire ownership: the one-instance-per-stage
        operating rule and human coordination of explicit re-entry still apply.
        """
        record = self._read(self.paths.record, BoundaryRecord)
        if record is None:
            raise ValueError(f"missing boundary record: {self.paths.record}")
        # Historical results remain stored for absent boundaries, but no source
        # processing or retained-evidence audit runs for them.
        if record.availability == "absent":
            return False
        # Done is included for auditing even without --failed. operation() only
        # reopens extraction if --failed actually finds failed extraction items.
        if record.phase == stage or (stage == "extract" and record.phase == "done"):
            return True
        # Ordinary commands never reopen a later phase. Even explicit retries
        # cannot let judge bypass scan, or extract bypass scan/judge.
        if not failed or PHASE_ORDER.index(record.phase) < PHASE_ORDER.index(stage):
            return False
        # Only explicit retries in a later phase reach here. Inspect the owning
        # document to avoid reopening a boundary with no saved stage failures.
        if stage == "scan":
            inventory = self._read(self.paths.scan_targets, ScanTargetInventory)
            if inventory is None:
                raise ValueError(f"missing scan targets: {self.paths.scan_targets}")
            return any(target.result.status == "failed" for target in inventory.targets)
        # Only judge remains: extract on done already qualified for its audit.
        # Completed invalid/unknown assessments are decisions, not failed work.
        credentials = self._read(self.paths.credentials, CredentialsDocument)
        return credentials is not None and any(
            credential.judgment.status == "failed"
            for credential in credentials.credentials.values()
        )

    @asynccontextmanager
    async def operation(
        self,
        stage: SourceStage,
        *,
        failed: bool = False,
    ) -> AsyncIterator[Boundary | None]:
        """Load selected work, optionally reopen failed work, then own services."""
        if not self.eligible(stage, failed=failed) or not self._load():
            yield None
            return
        results = (
            [target.result for target in self.inventory.targets]
            if stage == "scan"
            else [
                getattr(item, "judgment" if stage == "judge" else "extraction")
                for item in self.credentials.credentials.values()
            ]
        )
        retries = [result for result in results if failed and result.status == "failed"]
        if retries:
            # Explicit re-entry happens only while this boundary is idle.
            self.record.phase = stage
            self._write(self.paths.record, self.record, BoundaryRecord)
            for result in retries:
                result.status = "pending"
            self.checkpoint()
        if self.record.phase != stage:
            # An extract invocation can audit done boundaries without services/writes.
            yield self
            return
        try:
            self._start_services()
            yield self
        finally:
            await self._stop_services()

    def _start_services(self) -> None:
        self.reader = self.backend.content_reader(self.scratch_dir)
        self.scanner = TitusCliScanner(self.inventory, self.backend)
        self.judge_service = DspyFindingJudge()
        self.extractor = EvidenceExtractor(self.paths.boundary_dir)

    async def _stop_services(self) -> None:
        if self.reader is not None:
            await self.reader.aclose()
        self.reader = None
        self.judge_service = None
        self.scanner = None
        self.extractor = None

    def _advance(self, phase: BoundaryPhase) -> None:
        """Publish readiness after result writes and service cleanup have finished."""
        self.record.phase = phase
        self._write(self.paths.record, self.record, BoundaryRecord)

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

    async def enroll_inventory(self) -> bool:
        """Enroll only previously unregistered boundaries; inventory runs alone."""
        existing = self._read(self.paths.record, BoundaryRecord)
        if existing is not None:
            return False
        return await self._refresh_inventory(existing)

    async def refresh_inventory(self) -> bool:
        return await self._refresh_inventory(self._read(self.paths.record, BoundaryRecord))

    async def _refresh_inventory(self, existing: BoundaryRecord | None) -> bool:
        current = self._read(
            self.paths.scan_targets,
            ScanTargetInventory,
        )

        discovered = await self.backend.inventory(self.boundary_id)
        if discovered is None:
            if existing is None:
                return False
            existing.availability = "absent"
            absent = existing
            self._write(
                self.paths.record,
                absent,
                BoundaryRecord,
            )
            self.paths.scan_targets.unlink(missing_ok=True)
            fsync_directory(self.paths.boundary_dir)
            self.record = absent
            return True

        merged = merge_inventory(current, discovered)
        record = BoundaryRecord(
            backend_id=self.backend.name,
            boundary=merged.boundary,
            phase=(
                existing.phase
                if existing is not None
                and current is not None
                and existing.availability == "available"
                and {target.id for target in current.targets}
                == {target.id for target in merged.targets}
                else "scan"
            ),
        )
        reopening = (
            existing is not None
            and existing.availability == "available"
            and existing.phase != record.phase
        )
        if reopening:
            # Inventory runs alone. Revoke downstream readiness before changing
            # targets, so an interrupted refresh cannot strand new scan work.
            self._write(self.paths.record, record, BoundaryRecord)
        self._write(
            self.paths.scan_targets,
            merged,
            ScanTargetInventory,
        )
        if not reopening:
            self._write(self.paths.record, record, BoundaryRecord)
        self.record = record
        self.inventory = merged
        return True

    async def scan(self, *, failed: bool = False) -> bool:
        async with self.operation("scan", failed=failed) as owned:
            if owned is None:
                return False
            await self._scan()
        self._advance("judge")
        return True

    async def _scan(self) -> None:
        scanner = self.scanner
        reader = self.reader
        assert scanner is not None
        assert reader is not None
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
            if target.result.status == "pending"
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
                "scanned target=%s status=%s",
                target.id,
                target.result.status,
            )
            self._log_scan_errors(target)

        if self.paths.datastore.exists():
            report = await scanner.export_report(self.paths.datastore)
        elif not self.inventory.targets:
            report = TitusReport(
                boundary_id=self.boundary_id,
                generated_at=datetime.now(UTC).isoformat(),
            )
        else:
            # Failure to export remains a stage failure; never publish fake results.
            report = await scanner.export_report(self.paths.datastore)
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

        LOGGER.info(
            "scan complete boundary=%s candidates=%d",
            self.boundary_id,
            len(self.credentials.credentials),
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
            await scanner.scan(target, work_dir, self.paths.datastore)

    async def judge(self, *, failed: bool = False) -> int:
        async with self.operation("judge", failed=failed) as owned:
            if owned is None:
                return 0
            count = await self._judge()
        self._advance("extract")
        return count

    async def _judge(self) -> int:
        judge_service = self.judge_service
        reader = self.reader
        assert judge_service is not None
        assert reader is not None
        selected = tuple(
            credential
            for credential in self.credentials.credentials.values()
            if credential.judgment.status == "pending"
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
                    status="failed",
                    error=(str(error) or type(error).__name__)[:500],
                )

            credential.judgment = result
            self.checkpoint()
        return len(selected)

    async def extract(self, *, failed: bool = False) -> int:
        async with self.operation("extract", failed=failed) as owned:
            if owned is None:
                return 0
            self._audit_evidence()
            if self.record.phase == "done":
                return 0
            count = await self._extract()
        self._advance("done")
        return count

    def _audit_evidence(self) -> None:
        credentials = tuple(self.credentials.credentials.values())
        for credential in credentials:
            if credential.extraction.status == "retained":
                if not evidence_exists(
                    self.paths.boundary_dir,
                    credential.credential_id,
                    credential.extraction,
                ):
                    LOGGER.error(
                        "retained evidence missing boundary=%s credential=%s path=%s; "
                        "automatic replacement disabled",
                        self.boundary_id,
                        credential.credential_id,
                        credential.extraction.output_path,
                    )

    async def _extract(self) -> int:
        extractor = self.extractor
        reader = self.reader
        assert extractor is not None
        assert reader is not None
        selected = tuple(
            credential
            for credential in self.credentials.credentials.values()
            if credential.extraction.status == "pending"
        )
        attempted = 0
        for credential in selected:
            if credential.judgment.verdict not in {"valid", "unknown"}:
                credential.extraction = ExtractionResult(
                    status="skipped",
                    reason=(
                        "judgment failed"
                        if credential.judgment.status == "failed"
                        else "credential judged invalid"
                    ),
                    error=credential.extraction.error,
                )
                self.checkpoint()
                continue
            attempted += 1
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
                    status="failed",
                    error=(str(error) or type(error).__name__)[:500],
                )
            credential.extraction = extraction
            self.checkpoint()
        return attempted
