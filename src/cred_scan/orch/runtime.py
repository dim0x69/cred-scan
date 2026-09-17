"""Report-boundary lifecycle and local scan/judge scheduling."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from cred_scan.backend.models import ScanBoundaryInventory, ScanTarget
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.common.proto import WorkspaceProtocol
from cred_scan.common.workspace import Workspace, scratch_dir
from cred_scan.judge.dspy_adapter import DspyFindingJudge
from cred_scan.judge.evidence import evidence_matches, evidence_path, retain_first_evidence
from cred_scan.judge.proto import FatalJudgeError, FindingJudge
from cred_scan.scan.credentials import deduplicate_report
from cred_scan.scan.exclusions import load_exclusions
from cred_scan.scan.models import (
    Credential,
    CredentialsDocument,
    ExclusionPolicy,
    ExtractionResult,
    JudgmentResult,
    TitusReport,
    credential_source_fingerprint,
)
from cred_scan.scan.proto import CredentialScanner
from cred_scan.scan.titus import TitusCliScanner

from cred_scan.orch.credentials import merge_scan, with_extraction, with_judgment
from cred_scan.orch.inventory import build_backend, run_inventory
from cred_scan.orch.models import AppConfig

LOGGER = logging.getLogger(__name__)
JUDGEABLE_VERDICTS = frozenset({"PENDING", "ERROR"})
EVIDENCE_VERDICTS = frozenset({"VALID"})


class ReportBoundary:
    """Coordinate one complete scan boundary under exclusive ownership."""

    def __init__(
        self,
        inventory: ScanBoundaryInventory,
        workspace: WorkspaceProtocol,
        *,
        backend: BackendAdapter,
    ) -> None:
        self.inventory = inventory
        self.workspace = workspace
        self.paths = workspace.boundary(inventory.boundary.id)
        self.backend = backend

    @property
    def boundary_id(self) -> str:
        return self.inventory.boundary.id

    async def scan(
        self, scanner: CredentialScanner, policy: ExclusionPolicy
    ) -> CredentialsDocument:
        """Scan eligible pins once, then persist raw report and merged credentials."""
        interrupted = [
            t for t in self.inventory.targets if t.result.status == "running"
        ]
        if interrupted:
            for target in interrupted:
                target.result.status = "pending"
            self.workspace.write(
                self.paths.inventory, self.inventory, ScanBoundaryInventory
            )
        LOGGER.info(
            "scanning boundary=%s targets=%d",
            self.boundary_id,
            len(self.inventory.targets),
        )
        # Inventory cannot refresh while this boundary is owned. Snapshot once so
        # a still-retryable failure is not reclaimed repeatedly in the same run.
        eligible = tuple(
            target
            for target in self.inventory.targets
            if target.lifecycle == "current"
            and target.scope.lifecycle == "active"
            and (
                target.result.status == "pending"
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
            self.workspace.write(
                self.paths.inventory, self.inventory, ScanBoundaryInventory
            )
            with scratch_dir(self.paths.scratch_parent) as work_dir:
                for attempt in range(3):
                    LOGGER.info(
                        "scanning target=%s attempt=%d/3",
                        target.id,
                        attempt + 1,
                    )
                    target = await scanner.scan(
                        target, work_dir, self.paths.datastore, policy
                    )
                    if target.result.status == "scanned" or attempt == 2:
                        break
                    target.result.status = "running"
            self.inventory.complete_target(target)
            self.workspace.write(
                self.paths.inventory, self.inventory, ScanBoundaryInventory
            )
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
            report = TitusReport(
                boundary_id=self.boundary_id,
                generated_at=datetime.now(UTC).isoformat(),
                incomplete=True,
                errors=self.inventory.errors,
            )
            # Error-only inventories have no pinned source for a reader. They
            # still publish a diagnostic report and an incomplete empty result.
            self.workspace.write(self.paths.report, report, TitusReport)
            document = CredentialsDocument(
                boundary_id=self.boundary_id,
                report_generated_at=report.generated_at,
                incomplete=True,
                errors=report.errors,
            )
        else:
            report = await scanner.export_report(self.paths.datastore)
            report = report.model_copy(
                update={
                    "incomplete": report.incomplete or incomplete,
                    "errors": tuple(report.errors) + self.inventory.errors,
                }
            )

            # Publish the complete boundary-wide export before candidate
            # conversion. Excluded credentials may produce an empty document,
            # and a later conversion error must not discard the raw report.
            self.workspace.write(self.paths.report, report, TitusReport)
            resolver = self.backend.content_reader(
                self.inventory.boundary, self.inventory.targets
            )
            try:
                document = await deduplicate_report(
                    report, self.inventory, policy, resolver
                )
            finally:
                await resolver.aclose()
        document = merge_scan(
            self.workspace.read(self.paths.credentials, CredentialsDocument), document
        )
        self.workspace.write(self.paths.credentials, document, CredentialsDocument)
        LOGGER.info(
            "scan complete boundary=%s candidates=%d incomplete=%s",
            self.boundary_id,
            len(document.credentials),
            document.incomplete,
        )
        return document

    def _validate_document_targets(
        self, document: CredentialsDocument
    ) -> dict[str, ScanTarget]:
        if document.boundary_id != self.boundary_id:
            raise ValueError("credentials document belongs to another boundary")
        targets = {target.id: target for target in self.inventory.targets}
        for credential in document.credentials.values():
            for occurrence in credential.occurrences:
                if occurrence.target_id not in targets:
                    raise ValueError(
                        "credential references an unknown target: "
                        f"{occurrence.target_id}"
                    )
        return targets

    def _targets_for_credential(
        self, credential: Credential, targets: dict[str, ScanTarget]
    ) -> tuple[ScanTarget, ...]:
        target_ids = dict.fromkeys(
            occurrence.target_id for occurrence in credential.occurrences
        )
        return tuple(targets[target_id] for target_id in target_ids)

    @staticmethod
    def _error_result(error: BaseException) -> JudgmentResult:
        return JudgmentResult(verdict="ERROR", reasoning=str(error)[:500])

    @asynccontextmanager
    async def _content_session(
        self,
        credential: Credential,
        targets: dict[str, ScanTarget],
    ) -> AsyncIterator[ContentReader]:
        """Keep one boundary reader alive for judgment or extraction."""
        reader = self.backend.content_reader(
            self.inventory.boundary,
            self._targets_for_credential(credential, targets),
        )
        try:
            yield reader
        finally:
            await reader.aclose()

    @asynccontextmanager
    async def _judgment_session(
        self,
        credential: Credential,
        targets: dict[str, ScanTarget],
        judge: FindingJudge,
    ) -> AsyncIterator[tuple[JudgmentResult, ContentReader | None]]:
        reader: ContentReader | None = None
        try:
            try:
                reader = self.backend.content_reader(
                    self.inventory.boundary,
                    self._targets_for_credential(credential, targets),
                )
            except FatalJudgeError:
                raise
            except Exception as error:
                LOGGER.exception(
                    "content reader failed boundary=%s credential=%s",
                    self.boundary_id,
                    credential.credential_id,
                )
                yield self._error_result(error), None
                return
            try:
                result = await judge.judge(credential, reader)
            except FatalJudgeError:
                raise
            except Exception as error:
                LOGGER.exception(
                    "judgment failed credential=%s", credential.credential_id
                )
                result = self._error_result(error)
            yield result, reader
        finally:
            if reader is not None:
                await reader.aclose()

    async def _extract_with_reader(
        self, credential: Credential, reader: ContentReader
    ) -> ExtractionResult:
        source_fingerprint = credential_source_fingerprint(credential)
        location = credential.occurrences[0].locations[0]
        try:
            destination = evidence_path(
                self.paths.boundary_dir, credential.credential_id, location.filename
            )
            _, size, sha256 = await retain_first_evidence(
                credential, location, reader, destination
            )
            output_path = destination.relative_to(self.paths.boundary_dir).as_posix()
            LOGGER.info(
                "evidence retained boundary=%s credential=%s output=%s",
                self.boundary_id,
                credential.credential_id,
                output_path,
            )
            return ExtractionResult(
                status="RETAINED",
                source_fingerprint=source_fingerprint,
                output_path=output_path,
                size=size,
                sha256=sha256,
            )
        except Exception as error:
            LOGGER.exception(
                "evidence extraction failed boundary=%s credential=%s",
                self.boundary_id,
                credential.credential_id,
            )
            return ExtractionResult(
                status="ERROR",
                source_fingerprint=source_fingerprint,
                error=str(error)[:500],
            )

    async def _ensure_evidence(
        self,
        credential: Credential,
        targets: dict[str, ScanTarget],
        reader: ContentReader | None = None,
    ) -> bool:
        """Reuse verified evidence or extract and checkpoint once; return newly retained."""
        if (
            credential.extraction is not None
            and credential.extraction.status == "RETAINED"
        ):
            if evidence_matches(
                self.paths.boundary_dir, credential.credential_id, credential.extraction
            ):
                return False
            # Integrity failures must escape, not become a replacement ERROR record.
            raise RuntimeError(
                "retained evidence is missing or corrupt: "
                f"boundary={self.boundary_id} credential={credential.credential_id}; "
                "restore the verified artifact before retrying"
            )
        LOGGER.info(
            "extracting evidence boundary=%s credential=%s",
            self.boundary_id,
            credential.credential_id,
        )
        if reader is not None:
            extraction = await self._extract_with_reader(credential, reader)
        else:
            try:
                async with self._content_session(credential, targets) as content:
                    extraction = await self._extract_with_reader(credential, content)
            except Exception as error:
                LOGGER.exception(
                    "content reader failed during extraction boundary=%s credential=%s",
                    self.boundary_id,
                    credential.credential_id,
                )
                extraction = ExtractionResult(
                    status="ERROR",
                    source_fingerprint=credential_source_fingerprint(credential),
                    error=str(error)[:500],
                )
        LOGGER.info(
            "extraction complete boundary=%s credential=%s status=%s",
            self.boundary_id,
            credential.credential_id,
            extraction.status,
        )
        latest = self.workspace.read(self.paths.credentials, CredentialsDocument)
        if latest is None:
            raise ValueError("cannot record extraction without a credential document")
        self.workspace.write(
            self.paths.credentials,
            with_extraction(latest, credential.credential_id, extraction),
            CredentialsDocument,
        )
        return extraction.status == "RETAINED"

    async def judge(
        self,
        document: CredentialsDocument,
        judge: FindingJudge,
        *,
        extract_valid: bool = False,
    ) -> int:
        """Judge published candidates; optionally extract VALID results in the same session."""
        targets = self._validate_document_targets(document)
        LOGGER.info(
            "judging boundary=%s candidates=%d eligible=%d",
            self.boundary_id,
            len(document.credentials),
            sum(
                c.judgment.verdict in JUDGEABLE_VERDICTS
                for c in document.credentials.values()
            ),
        )
        if extract_valid:
            LOGGER.info(
                "extracting boundary=%s valid=%d",
                self.boundary_id,
                sum(
                    c.judgment.verdict in EVIDENCE_VERDICTS
                    for c in document.credentials.values()
                ),
            )
        judged_count = 0
        for credential_id, credential in document.credentials.items():
            if credential.judgment.verdict in JUDGEABLE_VERDICTS:
                judged_count += 1
                LOGGER.info(
                    "judging credential=%s boundary=%s", credential_id, self.boundary_id
                )
                async with self._judgment_session(credential, targets, judge) as (
                    result,
                    reader,
                ):
                    latest = self.workspace.read(
                        self.paths.credentials, CredentialsDocument
                    )
                    if latest is None:
                        raise ValueError(
                            "cannot judge without a published scan document"
                        )
                    saved = with_judgment(latest, credential_id, result)
                    self.workspace.write(
                        self.paths.credentials, saved, CredentialsDocument
                    )
                    if extract_valid and result.verdict in EVIDENCE_VERDICTS:
                        await self._ensure_evidence(
                            saved.credentials[credential_id], targets, reader
                        )
                LOGGER.info(
                    "judged credential=%s verdict=%s boundary=%s",
                    credential_id,
                    result.verdict,
                    self.boundary_id,
                )
            elif extract_valid and credential.judgment.verdict in EVIDENCE_VERDICTS:
                await self._ensure_evidence(credential, targets)
        LOGGER.info(
            "judgment complete boundary=%s candidates=%d judged=%d",
            self.boundary_id,
            len(document.credentials),
            judged_count,
        )
        return judged_count

    async def extract(self, document: CredentialsDocument) -> int:
        """Recover evidence for published VALID credentials; return newly retained count."""
        targets = self._validate_document_targets(document)
        credentials = tuple(
            c
            for c in document.credentials.values()
            if c.judgment.verdict in EVIDENCE_VERDICTS
        )
        LOGGER.info(
            "extracting boundary=%s valid=%d", self.boundary_id, len(credentials)
        )
        retained_count = 0
        for credential in credentials:
            retained_count += await self._ensure_evidence(credential, targets)
        return retained_count


class LocalRuntime:
    """Compose local services and schedule exclusively owned boundaries."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.workspace = Workspace(config.workspace)
        self._backends: dict[str, BackendAdapter] = {}

    def backend_for(self, name: str) -> BackendAdapter:
        cached = self._backends.get(name)
        if cached is not None:
            return cached
        backend_config = next(
            (backend for backend in self.config.backends if backend.name == name), None
        )
        if backend_config is None:
            raise KeyError(f"backend not configured: {name}")
        backend = build_backend(self.config, backend_config, self.workspace)
        self._backends[name] = backend
        return backend

    async def inventory(self) -> int:
        with self.workspace.operation_lock():
            return await run_inventory(self.config, self.workspace)

    def _make_boundary(self, inventory: ScanBoundaryInventory) -> ReportBoundary:
        return ReportBoundary(
            inventory, self.workspace, backend=self.backend_for(inventory.backend.name)
        )

    def _make_scanner(self, boundary: ReportBoundary) -> CredentialScanner:
        return TitusCliScanner(
            self.config.titus,
            boundary.inventory,
            boundary.backend,
            environment={
                "ARTIFACTORY_PASSWORD": self.config.artifactory_api_key or "",
                "ARTIFACTORY_TOKEN": self.config.artifactory_api_key or "",
                "ARTIFACTORY_API_KEY": self.config.artifactory_api_key or "",
            },
        )

    def boundaries(self) -> Iterator[ReportBoundary]:
        for paths in self.workspace.inventory_boundaries():
            inventory = self.workspace.read(paths.inventory, ScanBoundaryInventory)
            if inventory is None or inventory.lifecycle == "stale":
                continue
            if not any(
                target.lifecycle == "current" and target.scope.lifecycle == "active"
                for target in inventory.targets
            ):
                continue
            yield self._make_boundary(inventory)

    async def _process_existing(self, *, judge: bool) -> int:
        count = 0
        judger = None
        eligible_verdicts = JUDGEABLE_VERDICTS if judge else EVIDENCE_VERDICTS
        try:
            for paths in self.workspace.inventory_boundaries():
                inventory = self.workspace.read(paths.inventory, ScanBoundaryInventory)
                document = self.workspace.read(paths.credentials, CredentialsDocument)
                if (
                    inventory is None
                    or inventory.lifecycle == "stale"
                    or document is None
                    or not any(
                        c.judgment.verdict in eligible_verdicts
                        for c in document.credentials.values()
                    )
                ):
                    continue
                boundary = self._make_boundary(inventory)
                if judge:
                    if judger is None:
                        judger = DspyFindingJudge(self.config)
                    count += await boundary.judge(document, judger)
                else:
                    count += await boundary.extract(document)
            return count
        finally:
            await self._close_backends()

    async def judge(self) -> int:
        with self.workspace.operation_lock():
            return await self._process_existing(judge=True)

    async def scan(self) -> int:
        """Scan persisted targets, judge findings, and retain evidence."""
        with self.workspace.operation_lock():
            try:
                policy = load_exclusions(self.config.exclusions)
                boundaries = self.boundaries()
                queue: asyncio.Queue[
                    tuple[ReportBoundary, CredentialsDocument] | None
                ] = asyncio.Queue(maxsize=1)

                async def scan_worker() -> None:
                    for boundary in boundaries:
                        document = await boundary.scan(
                            self._make_scanner(boundary), policy
                        )
                        await queue.put((boundary, document))

                async def scan_boundaries() -> None:
                    async with asyncio.TaskGroup() as group:
                        for _ in range(self.config.scan_concurrency):
                            group.create_task(scan_worker())
                    await queue.put(None)

                completed = 0
                judge = None
                async with asyncio.TaskGroup() as group:
                    group.create_task(scan_boundaries())
                    while (work := await queue.get()) is not None:
                        boundary, document = work
                        if judge is None:
                            judge = DspyFindingJudge(self.config)
                        await boundary.judge(document, judge, extract_valid=True)
                        completed += 1
                return completed
            finally:
                await self._close_backends()

    async def run(self) -> int:
        """Compatibility alias for the normal scan workflow."""
        return await self.scan()

    async def extract(self) -> int:
        with self.workspace.operation_lock():
            return await self._process_existing(judge=False)

    async def _close_backends(self) -> None:
        backends = tuple(self._backends.values())
        self._backends.clear()
        for backend in backends:
            await backend.aclose()
