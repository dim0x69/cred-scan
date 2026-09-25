import asyncio
import pytest
from unittest.mock import AsyncMock, Mock

from cred_scan.orch import runtime as runtime_module
from cred_scan.orch.runtime import LocalRuntime


def test_all_backend_batches_selected_before_any_work(app_config, monkeypatch):
    events = []

    class Workspace:
        def __init__(self, name):
            self.name = name
            self.ready = [name]

        def select(self, stage, *, failed):
            events.append(("select", self.name, stage, failed))
            return tuple(self.ready)

        async def run_selected(self, stage, selected, *, failed):
            events.append(("run", self.name, selected))
            second.ready.append("became-ready")
            return len(selected)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def close(self):
            pass

    first, second = Workspace("first"), Workspace("second")
    monkeypatch.setattr(
        runtime_module, "iter_persisted_workspaces", lambda *_: iter([first, second])
    )
    assert asyncio.run(LocalRuntime(app_config).judge(failed=True)) == 2
    assert events == [
        ("select", "first", "judge", True),
        ("select", "second", "judge", True),
        ("run", "first", ("first",)),
        ("run", "second", ("second",)),
    ]


def test_selection_failure_closes_created_backends(app_config, monkeypatch):
    workspace = Mock(close=AsyncMock())
    workspace.select.side_effect = ValueError("invalid record")
    monkeypatch.setattr(
        runtime_module, "iter_persisted_workspaces", lambda *_: iter([workspace])
    )
    with pytest.raises(ValueError, match="invalid record"):
        asyncio.run(LocalRuntime(app_config).scan())
    workspace.close.assert_awaited_once()


def test_cleanup_failure_still_closes_other_selected_workspaces(
    app_config, monkeypatch
):
    first = Mock(select=Mock(return_value=()), close=AsyncMock())
    second = Mock(
        select=Mock(side_effect=ValueError("selection failed")),
        close=AsyncMock(side_effect=RuntimeError("cleanup failed")),
    )
    monkeypatch.setattr(
        runtime_module, "iter_persisted_workspaces", lambda *_: iter([first, second])
    )
    with pytest.raises(RuntimeError, match="cleanup failed"):
        asyncio.run(LocalRuntime(app_config).scan())
    first.close.assert_awaited_once()
    second.close.assert_awaited_once()
