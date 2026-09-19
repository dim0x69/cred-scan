"""Backend-owned inventory merge policy."""

from __future__ import annotations

from cred_scan.backend.models import ScanBoundaryInventory, ScanTargetResult


def merge_inventory(
    current: ScanBoundaryInventory | None,
    discovered: ScanBoundaryInventory,
) -> ScanBoundaryInventory:
    """Append immutable pins; only authoritative discovery changes lifecycle."""
    if current is not None:
        if current.boundary != discovered.boundary:
            raise ValueError("inventory belongs to another boundary")

    existing_targets = current.targets if current is not None else ()
    if discovered.errors:
        raise ValueError("incomplete inventory discovery: " + "; ".join(discovered.errors))

    known = {target.id: target for target in existing_targets}
    selected = {target.scope.id: target.id for target in discovered.targets}
    for fresh in discovered.targets:
        if fresh.id not in known:
            known[fresh.id] = fresh.model_copy(update={"result": ScanTargetResult()})

    targets = []
    for target in known.values():
        selected_id = selected.get(target.scope.id)
        lifecycle = target.lifecycle
        if selected_id is not None:
            lifecycle = "current" if target.id == selected_id else "superseded"
        targets.append(
            target.model_copy(
                update={
                    "lifecycle": lifecycle,
                    "scope": target.scope.model_copy(
                        update={
                            "lifecycle": "active" if selected_id is not None else "stale"
                        }
                    ),
                }
            )
        )

    return discovered.model_copy(
        update={
            "targets": tuple(targets),
            "lifecycle": "active",
            "stale_reason": None,
            "errors": (),
        }
    )
