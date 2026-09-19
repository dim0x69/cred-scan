"""Concurrent boundary command coordination."""

from cred_scan.orch.models import AppConfig
from cred_scan.orch.workspace import Workspace


class LocalRuntime:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    async def inventory(self) -> int:
        async with Workspace(self.config) as workspace:
            return await workspace.inventory()

    async def scan(self) -> int:
        async with Workspace(self.config) as workspace:
            return await workspace.scan()

    async def judge(self) -> int:
        async with Workspace(self.config) as workspace:
            return await workspace.judge()

    async def extract(self) -> int:
        async with Workspace(self.config) as workspace:
            return await workspace.extract()
