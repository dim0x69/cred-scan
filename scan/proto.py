"""Scan-stage protocols."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from backend.models import ScanTarget
from scan.models import ExclusionPolicy, TitusReport


class CredentialScanner(Protocol):
    """Scan targets and export one final report for a datastore boundary."""

    async def scan(
        self,
        target: ScanTarget,
        work_dir: Path,
        datastore: Path,
        exclusions: ExclusionPolicy,
    ) -> ScanTarget:
        """Finish or stop the target's subprocess before returning or raising."""
        ...

    async def export_report(self, datastore: Path) -> TitusReport: ...
