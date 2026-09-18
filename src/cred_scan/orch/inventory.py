"""Boundary-scoped inventory orchestration."""

from cred_scan.orch.boundary import Boundary


async def run_inventory(boundary: Boundary) -> None:
    """Refresh and checkpoint one boundary's inventory."""
    await boundary.refresh_inventory()
