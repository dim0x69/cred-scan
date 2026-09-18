"""One-boundary command coordination with optional live selection."""

from cred_scan.orch.models import AppConfig
from cred_scan.orch.workspace import Workspace


class LocalRuntime:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    async def inventory(self, boundary_id: str) -> None:
        async with Workspace(self.config) as workspace:
            async with workspace.boundary_session(boundary_id) as boundary:
                await boundary.refresh_inventory()

    async def scan(self, boundary_id: str | None = None) -> int:
        async with Workspace(self.config) as workspace:
            if boundary_id is not None:
                async with workspace.boundary_session(boundary_id) as boundary:
                    await boundary.scan()
                    return 1
            async with workspace.selector.next_scan() as boundary:
                if boundary is None:
                    return 0
                await boundary.scan()
                return 1

    async def judge(self, boundary_id: str | None = None) -> int:
        async with Workspace(self.config) as workspace:
            if boundary_id is not None:
                async with workspace.boundary_session(boundary_id) as boundary:
                    return await boundary.judge()
            async with workspace.selector.next_judge() as boundary:
                if boundary is None:
                    return 0
                return await boundary.judge()

    async def extract(self, boundary_id: str | None = None) -> int:
        async with Workspace(self.config) as workspace:
            if boundary_id is not None:
                async with workspace.boundary_session(boundary_id) as boundary:
                    return await boundary.extract()
            async with workspace.selector.next_extract() as boundary:
                if boundary is None:
                    return 0
                return await boundary.extract()
