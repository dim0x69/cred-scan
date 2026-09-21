"""Scan-stage protocols."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cred_scan.backend.models import ScanTarget
from cred_scan.scan.models import TitusReport


class CredentialScanner(Protocol):
    """One boundary's scanner, called sequentially for targets and final export.

    The boundary owns scan-target retries and scratch. Each call finishes its
    Titus subprocess, including cancelled startup and cleanup, before returning.
    Parallel work inside Titus is independent of this sequential interface.
    """

    async def scan(
        self,
        target: ScanTarget,
        work_dir: Path,
        datastore: Path,
    ) -> None:
        """Update the owned target after its subprocess finishes or stops."""
        ...

    async def export_report(self, datastore: Path) -> TitusReport: ...
