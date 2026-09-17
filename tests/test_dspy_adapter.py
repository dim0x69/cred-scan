import asyncio
import json
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import dspy
import pytest

from cred_scan.judge.dspy_adapter import (
    DspyFindingJudge,
    _is_fatal_judge_error,
    _is_rate_limit_error,
    _judge_input,
)
from cred_scan.judge.proto import FatalJudgeError
from cred_scan.orch.models import AppConfig
from cred_scan.scan.models import CredentialLocation


class APIConnectionError(Exception):
    pass


class AuthenticationError(Exception):
    pass


class RateLimitError(Exception):
    pass


class UnauthorizedError(Exception):
    status_code = 401


def test_connection_and_authentication_failures_are_fatal() -> None:
    assert _is_fatal_judge_error(APIConnectionError())
    assert _is_fatal_judge_error(AuthenticationError())
    assert _is_fatal_judge_error(UnauthorizedError())
    assert not _is_fatal_judge_error(RateLimitError())


def test_rate_limit_detection_remains_retryable() -> None:
    assert _is_rate_limit_error(RateLimitError("rate limit exceeded"))
    assert not _is_rate_limit_error(RuntimeError("model response could not parse"))


def test_judge_input_contains_only_bounded_value_and_paths(credential) -> None:
    occurrence = credential.occurrences[0].model_copy(
        update={
            "locations": tuple(
                CredentialLocation(
                    provenance=f"path-{index}",
                    source_path=f"path-{index}",
                    filename=f"path-{index}",
                )
                for index in range(100)
            )
        }
    )
    expanded = credential.model_copy(update={"occurrences": (occurrence,)})

    serialized = _judge_input(expanded)

    assert len(serialized) <= 120_000
    payload = json.loads(serialized)
    assert set(payload) == {"credential", "paths"}
    assert len(payload["paths"]) == 100


def test_missing_judge_configuration_is_fatal(app_config: AppConfig) -> None:
    with pytest.raises(FatalJudgeError, match="AZURE_OPENAI_API_KEY"):
        DspyFindingJudge(app_config)._configuration()


def test_judge_uses_native_async_dspy_and_content_tools(
    app_config: AppConfig, credential, monkeypatch
) -> None:
    config = app_config.model_copy(
        update={
            "azure_openai_api_key": "synthetic-key",
            "judge": app_config.judge.model_copy(
                update={"base_url": "https://example.invalid/openai/v1"}
            ),
        }
    )
    content = Mock()
    content.read_file = AsyncMock(
        return_value=SimpleNamespace(
            path="docker://source/file", encoding="utf-8", content="SECRET"
        )
    )
    content.list_files = AsyncMock(return_value=("etc/app.env",))
    captured: dict[str, object] = {}

    class Program:
        async def acall(self, **kwargs):
            captured["kwargs"] = kwargs
            tools = captured["tools"]
            assert isinstance(tools, (list, tuple))
            read_file, list_files = tools
            assert await read_file("docker://source/file") == {
                "path": "docker://source/file",
                "encoding": "utf-8",
                "content": "SECRET",
            }
            assert await list_files("docker://source/etc") == ["etc/app.env"]
            return SimpleNamespace(verdict="VALID", reason="synthetic judgment")

    def make_react(_signature, *, tools, max_iters):
        captured["tools"] = tools
        captured["max_iters"] = max_iters
        return Program()

    monkeypatch.setattr(dspy, "LM", Mock(return_value=object()))
    monkeypatch.setattr(dspy, "context", lambda **_kwargs: nullcontext())
    monkeypatch.setattr(dspy, "ReAct", make_react)

    judged = asyncio.run(DspyFindingJudge(config).judge(credential, content))

    assert judged.verdict == "VALID"
    assert judged.reasoning == "synthetic judgment"
    assert captured["max_iters"] == config.judge.max_iterations
    assert content.read_file.await_count == 1
    assert content.list_files.await_count == 1
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert "credential_json" in kwargs
