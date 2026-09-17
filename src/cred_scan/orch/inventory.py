"""Backend discovery and report-boundary inventory persistence."""

from __future__ import annotations

import logging

from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend
from cred_scan.backend.adapters.artifactory.models import ArtifactoryBackendConfig
from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.common.proto import WorkspaceProtocol
from cred_scan.orch.models import AppConfig


LOGGER = logging.getLogger(__name__)


def build_backend(
    config: AppConfig,
    backend_config: ArtifactoryBackendConfig,
    workspace: WorkspaceProtocol,
) -> ArtifactoryDockerBackend:
    return ArtifactoryDockerBackend(
        backend_config,
        config.artifactory_api_key or "",
        workspace=workspace,
        max_directory_entries=config.judge.layer_tools.max_directory_entries,
    )


async def run_inventory(
    config: AppConfig,
    workspace: WorkspaceProtocol,
) -> int:
    """Discover and persist one complete inventory per active report boundary."""
    completed = 0
    for backend_config in config.backends:
        backend = build_backend(config, backend_config, workspace)
        try:
            discovered = await backend.inventory()
            authoritative = not any(item.errors for item in discovered)
            seen_boundaries = {item.boundary.id for item in discovered}
            for inventory in discovered:
                paths = workspace.boundary(inventory.boundary.id)
                current = workspace.read(paths.inventory, ScanBoundaryInventory)
                merged = merge_inventory(current, inventory)
                if not merged.targets and not merged.errors:
                    if current is None:
                        LOGGER.info(
                            "skipping empty inventory boundary=%s",
                            merged.boundary.id,
                        )
                        continue
                    if not current.targets and not current.errors:
                        continue
                workspace.write(paths.inventory, merged, ScanBoundaryInventory)
                completed += 1
                LOGGER.info(
                    "inventory boundary=%s targets=%d errors=%d lifecycle=%s",
                    merged.boundary.id,
                    len(merged.targets),
                    len(merged.errors),
                    merged.lifecycle,
                )

            if authoritative:
                for paths in workspace.inventory_boundaries():
                    current = workspace.read(paths.inventory, ScanBoundaryInventory)
                    if (
                        current is None
                        or current.backend.name != backend_config.name
                        or current.boundary.id in seen_boundaries
                        or current.lifecycle == "stale"
                    ):
                        continue
                    stale = current.model_copy(
                        update={
                            "lifecycle": "stale",
                            "stale_reason": "boundary absent from authoritative inventory",
                        }
                    )
                    workspace.write(paths.inventory, stale, ScanBoundaryInventory)
                    LOGGER.warning("stale inventory boundary=%s", stale.boundary.id)
        finally:
            await backend.aclose()
    return completed
