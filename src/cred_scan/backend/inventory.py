"""Backend-owned inventory merge policy."""

from __future__ import annotations

from cred_scan.backend.models import ScanBoundaryInventory, ScanTargetResult


def merge_inventory(
    current: ScanBoundaryInventory | None,
    discovered: ScanBoundaryInventory,
) -> ScanBoundaryInventory:
    """Keep only discovered scan targets, reusing results for unchanged versions."""
    if current is not None and current.boundary != discovered.boundary:
        raise ValueError("inventory belongs to another boundary")
    if discovered.errors:
        raise ValueError("incomplete inventory discovery: " + "; ".join(discovered.errors))

    known = {target.id: target for target in current.targets} if current else {}
    for target in discovered.targets:
        target.result = known[target.id].result if target.id in known else ScanTargetResult()
    discovered.lifecycle = "active"
    discovered.stale_reason = None
    discovered.errors = ()
    return discovered
