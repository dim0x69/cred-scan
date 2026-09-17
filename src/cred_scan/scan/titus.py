"""Async Titus subprocess adapter for the shared boundary datastore."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from cred_scan.backend.models import ScanBoundaryInventory, ScanTarget
from cred_scan.backend.proto import BackendAdapter, UnsupportedTitusTargetError
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
        # Return a new target: ReportBoundary keeps the stored target running
        # until _update_target() installs this terminal result.
        try:
            source_arguments = self.backend.titus_scan_arguments(
                self.inventory, target
            )
        except UnsupportedTitusTargetError as error:
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
        try:
            stdout, stderr = await process.communicate()
        finally:
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.kill()
                await process.communicate()
        if process.returncode != 0:
            raise TitusError(
                f"Titus report failed: {stderr.decode(errors='replace').strip()[:500]}"
            )
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise TitusError("Titus report was not valid JSON") from error
        if not isinstance(payload, list):
            raise TitusError("Titus report was not a JSON array")
        return report_from_export(
            [item for item in payload if isinstance(item, dict)],
            self.inventory,
        )
