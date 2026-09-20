"""DSPy judgment adapter with exact repository-bound content tools."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from typing import Any, Literal

import dspy
from cred_scan.backend.proto import ContentReader
from cred_scan.scan.models import Credential, JudgmentResult

from cred_scan.judge.proto import FatalJudgeError, FindingJudge
from cred_scan.orch.global_config import get_config


LOGGER = logging.getLogger(__name__)

_MAX_JUDGE_INPUT_CHARS = 120_000
_MAX_PATH_CHARS = 2_048

_FATAL_EXCEPTION_NAMES = frozenset(
    {
        "APIConnectionError",
        "AuthenticationError",
        "ConnectError",
        "ConnectionError",
        "ConnectionRefusedError",
        "LMAuthError",
        "LMConfigurationError",
        "LMNotConfiguredError",
        "LMTransportError",
    }
)


def _is_rate_limit_error(error: BaseException) -> bool:
    text = f"{type(error).__name__}: {error}".lower()
    return "ratelimit" in text or "rate limit" in text or "too many requests" in text


def _error_status(error: BaseException) -> int | None:
    status = getattr(error, "status_code", None)
    if status is None:
        status = getattr(error, "status", None)
    if status is None:
        response = getattr(error, "response", None)
        status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def _judge_input(
    credential: Credential,
) -> tuple[str, dict[str, str]]:
    """Build bounded input and a registry of opaque source locators."""
    locations: list[dict[str, str]] = []
    registry: dict[str, str] = {}
    seen: dict[str, str] = {}
    for occurrence in credential.occurrences:
        locator = occurrence.locator
        location_id = seen.get(locator)
        if location_id is None:
            location_id = f"location-{len(registry)}"
            seen[locator] = location_id
            registry[location_id] = locator
        descriptor = {
            "id": location_id,
            "path": locator[:_MAX_PATH_CHARS],
        }
        candidate = [*locations, descriptor]
        serialized = json.dumps(
            {"credential": credential.credential, "locations": candidate},
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(serialized) > _MAX_JUDGE_INPUT_CHARS:
            break
        locations.append(descriptor)
    return (
        json.dumps(
            {"credential": credential.credential, "locations": locations},
            sort_keys=True,
        ),
        registry,
    )


def _is_fatal_judge_error(error: BaseException) -> bool:
    """Classify fatal configuration, authentication, and transport failures.

    DSPy 3.2.1 does not expose its newer structured LM exceptions, so this
    compatibility boundary uses exception classes and HTTP status metadata
    without matching human-readable error messages.
    """
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if type(current).__name__ in _FATAL_EXCEPTION_NAMES:
            return True
        if _error_status(current) in {401, 403}:
            return True
        current = current.__cause__ or current.__context__
    return False


class DspyFindingJudge(FindingJudge):
    def __init__(self) -> None:
        self.model = get_config().judge.model
        self._rate_limit_until = 0.0

    def _configuration(self) -> tuple[str, str, str | None]:
        config = get_config()
        if config.judge.provider.lower() != "azure":
            raise FatalJudgeError(
                f"unsupported judge provider: {config.judge.provider}"
            )
        secret = config.azure_openai_api_key
        api_key = secret.get_secret_value() if secret is not None else ""
        if not api_key.strip():
            raise FatalJudgeError("set AZURE_OPENAI_API_KEY")
        base_url = config.judge.base_url
        if not base_url:
            raise FatalJudgeError("set judge.base-url in config.yml")
        return api_key, base_url, config.judge.api_version

    async def judge(
        self, credential: Credential, content: ContentReader
    ) -> JudgmentResult:
        """Run one native asynchronous DSPy judgment."""
        try:
            api_key, base_url, api_version = self._configuration()

            class Signature(dspy.Signature):
                """Classify whether a credential appears real rather than an example."""

                credential_json: str = dspy.InputField(
                    desc=(
                        "JSON with exactly the detected credential value and "
                        "source locations. Use each location id with the content "
                        "tools to inspect source bytes; decide whether the value "
                        "appears real rather than an example."
                    )
                )
                verdict: Literal["VALID", "INVALID", "UNKNOWN"] = dspy.OutputField()
                reason: str = dspy.OutputField()

            input_data, location_registry = _judge_input(credential)

            async def read(location_id: str) -> dict[str, str]:
                locator = location_registry[location_id]
                LOGGER.info(
                    "judge tool call credential=%s tool=read location=%s",
                    credential.credential_id,
                    location_id,
                )
                location = await content.resolve_location(locator)
                content_bytes = (await content.read(location)).content
                try:
                    decoded = content_bytes.decode("utf-8")
                    encoding = "utf-8"
                except UnicodeDecodeError:
                    decoded = base64.b64encode(content_bytes).decode("ascii")
                    encoding = "base64"
                LOGGER.info(
                    "judge tool result credential=%s tool=read encoding=%s bytes=%d",
                    credential.credential_id,
                    encoding,
                    len(content_bytes),
                )
                return {
                    "path": location.source_path,
                    "encoding": encoding,
                    "content": decoded,
                }

            kwargs: dict[str, Any] = {
                "api_key": api_key,
                "api_base": base_url,
                "cache": False,
                # Rate-limit retries are handled below with explicit backoff.
                "num_retries": 0,
            }

            if api_version:
                kwargs["api_version"] = api_version
            deployment = self.model.removeprefix("azure/").removeprefix("openai/")
            provider = "openai" if "/openai/v1" in base_url.rstrip("/") else "azure"
            lm = dspy.LM(f"{provider}/{deployment}", **kwargs)
            with dspy.context(lm=lm, disable_history=True):
                if get_config().judge.layer_tools.enabled:
                    program = dspy.ReAct(
                        Signature,
                        tools=[read],
                        max_iters=get_config().judge.max_iterations,
                    )
                else:
                    program = dspy.Predict(Signature)
                prediction = None
                for attempt in range(3):
                    cooldown = self._rate_limit_until - time.monotonic()
                    if cooldown > 0:
                        LOGGER.info(
                            "rate-limit cooldown %.1fs before credential=%s",
                            cooldown,
                            credential.credential_id,
                        )
                        await asyncio.sleep(cooldown)
                    try:
                        prediction = await program.acall(credential_json=input_data)
                        break
                    except Exception as error:
                        if not _is_rate_limit_error(error) or attempt == 2:
                            raise
                        delay = float(2**attempt)
                        self._rate_limit_until = max(
                            self._rate_limit_until,
                            time.monotonic() + delay,
                        )
                        LOGGER.warning(
                            "LLM rate limit for credential=%s; retrying in %.1fs",
                            credential.credential_id,
                            delay,
                        )
                assert prediction is not None
                verdict = str(prediction.verdict).upper()
                if verdict not in {"VALID", "INVALID", "UNKNOWN"}:
                    verdict = "UNKNOWN"
                result = JudgmentResult(
                    verdict=verdict,
                    reasoning=str(prediction.reason),
                )

        except FatalJudgeError:
            raise
        except Exception as error:
            if _is_fatal_judge_error(error):
                raise FatalJudgeError(str(error)[:500]) from error
            LOGGER.exception("judgment failed credential=%s", credential.credential_id)
            result = JudgmentResult(
                verdict="ERROR",
                reasoning=str(error)[:500],
            )
        return result
