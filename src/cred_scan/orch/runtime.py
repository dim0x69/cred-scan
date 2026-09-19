"""Concurrent boundary command coordination."""

from cred_scan.orch.global_config import set_config
from cred_scan.orch.models import AppConfig
from cred_scan.orch.workspace import Workspace


class LocalRuntime:
    def __init__(self, config: AppConfig) -> None:
        set_config(config)

    async def inventory(self) -> int:
        async with Workspace() as workspace:
            return await workspace.inventory()

    async def scan(self) -> int:
        async with Workspace() as workspace:
            return await workspace.scan()

    async def judge(self) -> int:
        async with Workspace() as workspace:
            return await workspace.judge()

    async def extract(self) -> int:
        async with Workspace() as workspace:
            return await workspace.extract()
