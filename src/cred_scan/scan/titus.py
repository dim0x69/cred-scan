"""Async Titus subprocess adapter for the shared boundary datastore."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from cred_scan.backend.models import ScanBoundaryInventory, ScanTarget
from cred_scan.backend.proto import (
    BackendAdapter,
    ScratchDirectory,
    UnsupportedTitusTargetError,
)
from cred_scan.scan.credentials import report_from_export
from cred_scan.scan.models import ExclusionPolicy, TitusReport
from cred_scan.scan.proto import CredentialScanner


LOGGER = logging.getLogger(__name__)


class TitusError(RuntimeError):
    pass


_PERMANENT_ERROR_MARKERS = (
    "BLOB_UNKNOWN",
    "MANIFEST_UNKNOWN",
    "NAME_UNKNOWN",
    "UNAUTHORIZED",
    "FORBIDDEN",
    "DENIED",
    "HTTP 401",
    "HTTP 403",
    "HTTP 404",
    "STATUS 401",
    "STATUS 403",
    "STATUS 404",
    "TOKEN FAILED VERIFICATION",
    "INVALID TOKEN",
)


def _is_permanent_titus_error(line: str) -> bool:
    upper = line.upper()
    return any(marker in upper for marker in _PERMANENT_ERROR_MARKERS)


class TitusCliScanner(CredentialScanner):
    def __init__(
        self,
        config: Any,
        inventory: ScanBoundaryInventory,
        backend: BackendAdapter,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.config = config
        self.inventory = inventory
        self.backend = backend
        self.environment = dict(environment or {})

    async def scan(
        self,
        target: ScanTarget,
        work_dir: Path,
        datastore: Path,
        exclusions: ExclusionPolicy,
    ) -> ScanTarget:
        # Return a new target: Boundary keeps the stored target running
        # until complete_target() installs this terminal result.
        try:
            source_arguments = self.backend.titus_scan_arguments(
                self.inventory, target
            )
        except UnsupportedTitusTargetError as error:
            LOGGER.error(
                "unsupported Titus target target=%s error=%s",
                target.id,
                error,
            )
            return target.model_copy(
                update={
                    "result": target.result.model_copy(
                        update={
                            "status": "failed",
                            "errors": (str(error),),
                            "retryable": False,
                        }
                    )
                }
            )
        work_dir.mkdir(parents=True, exist_ok=True)
        command = [
            self.config.executable,
            "--quiet",
            "scan",
            *source_arguments,
            "--output",
            str(datastore),
            "--incremental",
            "--ignore",
            str(exclusions.path_file),
            "--workers",
            str(self.config.internal_workers),
            *self.config.arguments,
        ]
        environment = os.environ.copy()
        environment.update(self.environment)
        started = datetime.now(UTC)
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=work_dir,
                env=environment,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as error:
            LOGGER.exception("Titus process could not start target=%s", target.id)
            return target.model_copy(
                update={
                    "result": target.result.model_copy(
                        update={
                            "status": "failed",
                            "errors": (str(error),),
                            "started_at": started,
                            "finished_at": datetime.now(UTC),
                        }
                    )
                }
            )
        warnings = 0
        permanent_failure = False
        try:
            assert process.stderr is not None
            async for raw_line in process.stderr:
                line = raw_line.decode(errors="replace")
                if line.lstrip().startswith("[warn]"):
                    warnings += 1
                else:
                    LOGGER.info("titus: %s", line.rstrip())
                    permanent_failure = (
                        permanent_failure or _is_permanent_titus_error(line)
                    )
            return_code = await process.wait()
        finally:
            # Do not release boundary ownership or scratch with a live Titus child.
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.kill()
                await process.communicate()
        errors = (
            () if return_code == 0 else (f"Titus exited with status {return_code}",)
        )
        if return_code == 0 and not datastore.exists():
            errors = ("Titus succeeded without creating the datastore",)
        if warnings:
            errors = errors + (f"suppressed Titus warnings: {warnings}",)
        if errors:
            LOGGER.error(
                "Titus scan failed target=%s return_code=%s errors=%s",
                target.id,
                return_code,
                "; ".join(errors),
            )
        result = target.result.model_copy(
            update={
                "status": "scanned" if not errors else "failed",
                "return_code": return_code,
                "errors": errors,
                "retryable": not permanent_failure,
                "started_at": started,
                "finished_at": datetime.now(UTC),
            }
        )
        return target.model_copy(update={"result": result})

    async def export_report(self, datastore: Path) -> TitusReport:
        try:
            process = await asyncio.create_subprocess_exec(
                self.config.executable,
                "report",
                "--datastore",
                str(datastore),
                "--format",
                "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError:
            LOGGER.exception("Titus report process could not start datastore=%s", datastore)
            raise
        try:
            stdout, stderr = await process.communicate()
        finally:
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.kill()
                await process.communicate()
        if process.returncode != 0:
            detail = stderr.decode(errors="replace").strip()[:500]
            LOGGER.error(
                "Titus report failed datastore=%s return_code=%s detail=%s",
                datastore,
                process.returncode,
                detail or "<no stderr>",
            )
            raise TitusError(f"Titus report failed: {detail}")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            LOGGER.exception("Titus report returned invalid JSON datastore=%s", datastore)
            raise TitusError("Titus report was not valid JSON") from None
        if not isinstance(payload, list):
            raise TitusError("Titus report was not a JSON array")
        return report_from_export(
            [item for item in payload if isinstance(item, dict)],
            self.inventory,
        )


class TitusScannerPool:
    """Run bounded concurrent Titus invocations for one boundary."""

    def __init__(
        self,
        config: Any,
        inventory: ScanBoundaryInventory,
        backend: BackendAdapter,
        *,
        concurrency: int,
        environment: Mapping[str, str],
        scratch_dir: ScratchDirectory,
    ) -> None:
        if concurrency < 1:
            raise ValueError("Titus scanner concurrency must be positive")
        self.config = config
        self.inventory = inventory
        self.backend = backend
        self.concurrency = concurrency
        self.environment = dict(environment)
        self.scratch_dir = scratch_dir

    def _scanner(self) -> TitusCliScanner:
        return TitusCliScanner(
            self.config,
            self.inventory,
            self.backend,
            environment=self.environment,
        )

    async def _scan_one(
        self,
        target: ScanTarget,
        datastore: Path,
        exclusions: ExclusionPolicy,
    ) -> ScanTarget:
        scanner = self._scanner()
        with self.scratch_dir() as work_dir:
            current = target
            for attempt in range(3):
                LOGGER.info(
                    "scanning target=%s attempt=%d/3",
                    target.id,
                    attempt + 1,
                )
                current = await scanner.scan(
                    current,
                    work_dir,
                    datastore,
                    exclusions,
                )
                if current.result.status == "scanned" or attempt == 2:
                    return current
                current.result.status = "running"
        raise AssertionError("Titus scan worker returned without a result")

    async def scan(
        self,
        targets: Sequence[ScanTarget],
        datastore: Path,
        exclusions: ExclusionPolicy,
    ) -> tuple[ScanTarget, ...]:
        semaphore = asyncio.Semaphore(self.concurrency)

        async def run(target: ScanTarget) -> ScanTarget:
            async with semaphore:
                return await self._scan_one(
                    target,
                    datastore,
                    exclusions,
                )

        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(run(target)) for target in targets]
        return tuple(task.result() for task in tasks)

    async def export_report(self, datastore: Path) -> TitusReport:
        return await self._scanner().export_report(datastore)
