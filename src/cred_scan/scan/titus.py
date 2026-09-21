"""Async Titus subprocess adapter for the shared boundary datastore."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cred_scan.backend.models import ScanTargetInventory, ScanTarget
from cred_scan.backend.proto import (
    BackendAdapter,
    UnsupportedTitusTargetError,
)
from cred_scan.scan.credentials import report_from_export
from cred_scan.scan.models import TitusReport
from cred_scan.scan.proto import CredentialScanner
from cred_scan.orch.global_config import get_config, get_exclusions


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


async def _reap(process: asyncio.subprocess.Process) -> None:
    """Finish child cleanup even if the owner receives repeated cancellation."""
    if process.returncode is not None:
        return
    with suppress(ProcessLookupError):
        process.kill()
    cleanup = asyncio.create_task(process.communicate())
    cancelled = False
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            cancelled = True
    cleanup.result()
    if cancelled:
        raise asyncio.CancelledError


async def _spawn(*args: str, **kwargs: Any) -> asyncio.subprocess.Process:
    """Keep ownership until a cancelled process launch is settled and reaped."""
    launch = asyncio.create_task(asyncio.create_subprocess_exec(*args, **kwargs))
    try:
        return await asyncio.shield(launch)
    except asyncio.CancelledError:
        while not launch.done():
            try:
                await asyncio.shield(launch)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not launch.cancelled() and launch.exception() is None:
            await _reap(launch.result())
        raise


class TitusCliScanner(CredentialScanner):
    def __init__(
        self,
        inventory: ScanTargetInventory,
        backend: BackendAdapter,
    ) -> None:
        self.lock_fd: int | None = None
        self.config = get_config().titus
        self.inventory = inventory
        self.backend = backend
        secret = get_config().artifactory_access_token
        access_token = secret.get_secret_value() if secret is not None else ""
        self.environment = {
            "ARTIFACTORY_PASSWORD": access_token,
            "ARTIFACTORY_TOKEN": access_token,
            "ARTIFACTORY_API_KEY": access_token,
        }

    async def scan(
        self,
        target: ScanTarget,
        work_dir: Path,
        datastore: Path,
    ) -> None:
        # Update the boundary-owned target; Boundary checkpoints after retries.
        try:
            source_arguments = self.backend.titus_scan_arguments(self.inventory, target)
        except UnsupportedTitusTargetError as error:
            LOGGER.error(
                "unsupported Titus target target=%s error=%s",
                target.id,
                error,
            )
            target.result.status = "failed"
            target.result.errors = (str(error),)
            target.result.retryable = False
            return
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
            str(get_exclusions().path_file),
            "--workers",
            str(self.config.internal_workers),
            *self.config.arguments,
        ]
        environment = os.environ.copy()
        environment.update(self.environment)
        started = datetime.now(UTC)
        try:
            process = await _spawn(
                *command,
                cwd=work_dir,
                env=environment,
                stderr=asyncio.subprocess.PIPE,
                pass_fds=() if self.lock_fd is None else (self.lock_fd,),
            )
        except OSError as error:
            LOGGER.exception("Titus process could not start target=%s", target.id)
            target.result.status = "failed"
            target.result.errors = (str(error),)
            target.result.started_at = started
            target.result.finished_at = datetime.now(UTC)
            return
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
                    permanent_failure = permanent_failure or _is_permanent_titus_error(
                        line
                    )
            return_code = await process.wait()
        finally:
            # Do not release boundary ownership or scratch with a live Titus child.
            await _reap(process)
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
        target.result.status = "scanned" if not errors else "failed"
        target.result.return_code = return_code
        target.result.errors = errors
        target.result.retryable = not permanent_failure
        target.result.started_at = started
        target.result.finished_at = datetime.now(UTC)

    async def export_report(self, datastore: Path) -> TitusReport:
        try:
            process = await _spawn(
                self.config.executable,
                "report",
                "--datastore",
                str(datastore),
                "--format",
                "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                pass_fds=() if self.lock_fd is None else (self.lock_fd,),
            )
        except OSError:
            LOGGER.exception(
                "Titus report process could not start datastore=%s", datastore
            )
            raise
        try:
            stdout, stderr = await process.communicate()
        finally:
            await _reap(process)
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
            LOGGER.exception(
                "Titus report returned invalid JSON datastore=%s", datastore
            )
            raise TitusError("Titus report was not valid JSON") from None
        if not isinstance(payload, list):
            raise TitusError("Titus report was not a JSON array")
        return report_from_export(
            [item for item in payload if isinstance(item, dict)],
            self.inventory,
        )
