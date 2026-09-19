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
    targets = tuple(
        target.model_copy(update={
            "result": known[target.id].result.model_copy(deep=True)
            if target.id in known else ScanTargetResult(),
        })
        for target in discovered.targets
    )
    return discovered.model_copy(update={
        "targets": targets, "lifecycle": "active", "stale_reason": None, "errors": (),
    })
