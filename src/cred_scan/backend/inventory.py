"""Backend-owned inventory merge policy."""

from __future__ import annotations

from cred_scan.backend.models import ScanTargetInventory, ScanTargetResult


def merge_inventory(
    current: ScanTargetInventory | None,
    discovered: ScanTargetInventory,
) -> ScanTargetInventory:
    """Keep only discovered scan targets, reusing results for unchanged versions."""
    if discovered.errors:
        raise ValueError(
            "incomplete inventory discovery: " + "; ".join(discovered.errors)
        )

    known = {target.id: target for target in current.targets} if current else {}
    for target in discovered.targets:
        target.result = (
            known[target.id].result if target.id in known else ScanTargetResult()
        )
    discovered.errors = ()
    return discovered
