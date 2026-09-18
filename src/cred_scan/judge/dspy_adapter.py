"""DSPy judgment adapter with exact repository-bound content tools."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Literal

import dspy
from cred_scan.backend.models import ContentProvenance
from cred_scan.backend.proto import ContentReader
from cred_scan.scan.models import Credential, JudgmentResult

from cred_scan.judge.proto import FatalJudgeError, FindingJudge


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
) -> tuple[str, dict[str, ContentProvenance], dict[str, str]]:
    """Build bounded input and a session registry of typed source locations."""
    locations: list[dict[str, str]] = []
    registry: dict[str, ContentProvenance] = {}
    seen: dict[str, str] = {}
    directories: dict[str, str] = {}
    for occurrence in credential.occurrences:
        for location in occurrence.locations:
            provenance = location.provenance
            key = provenance.model_dump_json()
            location_id = seen.get(key)
            if location_id is None:
                location_id = f"location-{len(registry)}"
                seen[key] = location_id
                registry[location_id] = provenance
            directory_id = _register_parent_directory(
                provenance, location_id, registry, directories
            )
            descriptor = {
                "id": location_id,
                "kind": provenance.kind,
                "path": provenance.raw_path[:_MAX_PATH_CHARS],
            }
            if directory_id is not None:
                descriptor["directory_id"] = directory_id
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
        directories,
    )


def _register_parent_directory(
    provenance: ContentProvenance,
    location_id: str,
    registry: dict[str, ContentProvenance],
    directories: dict[str, str],
) -> str | None:
    path = provenance.path.rsplit("/", 1)
    if len(path) != 2 or not path[0]:
        return None
    directory_id = f"{location_id}-directory"
    if directory_id not in registry:
        parent = provenance.model_copy(
            update={
                "raw_path": provenance.raw_path.removesuffix(provenance.path)
                + path[0],
                "path": path[0],
            }
        )
        registry[directory_id] = parent
    directories[location_id] = directory_id
    return directory_id


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
    def __init__(self, config: Any) -> None:
        self.config = config
        self.model = config.judge.model
        self._rate_limit_until = 0.0

    def _configuration(self) -> tuple[str, str, str | None]:
        if self.config.judge.provider.lower() != "azure":
            raise FatalJudgeError(
                f"unsupported judge provider: {self.config.judge.provider}"
            )
        api_key = self.config.azure_openai_api_key or ""
        if not api_key.strip():
            raise FatalJudgeError("set AZURE_OPENAI_API_KEY")
        base_url = self.config.judge.base_url
        if not base_url:
            raise FatalJudgeError("set judge.base-url in config.yml")
        return api_key, base_url, self.config.judge.api_version

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

            input_data, location_registry, directory_registry = _judge_input(credential)

            async def read_file(location_id: str) -> dict[str, str]:
                provenance = location_registry[location_id]
                LOGGER.info(
                    "judge tool call credential=%s tool=read_file location=%s kind=%s",
                    credential.credential_id,
                    location_id,
                    provenance.kind,
                )
                result = await content.read_file(provenance)
                LOGGER.info(
                    "judge tool result credential=%s tool=read_file encoding=%s",
                    credential.credential_id,
                    result.encoding,
                )
                return {
                    "path": result.path,
                    "encoding": result.encoding,
                    "content": result.content,
                }

            async def list_files(location_id: str) -> list[dict[str, str]]:
                directory_id = directory_registry.get(location_id, location_id)
                provenance = location_registry[directory_id]
                LOGGER.info(
                    "judge tool call credential=%s tool=list_files location=%s kind=%s",
                    credential.credential_id,
                    location_id,
                    provenance.kind,
                )
                result = list(await content.list_files(provenance))
                entries = []
                for item in result:
                    next_id = f"location-{len(location_registry)}"
                    location_registry[next_id] = item
                    directory_id = _register_parent_directory(
                        item, next_id, location_registry, directory_registry
                    )
                    entry = {
                        "id": next_id,
                        "kind": item.kind,
                        "path": item.raw_path,
                    }
                    if directory_id is not None:
                        entry["directory_id"] = directory_id
                    entries.append(entry)
                LOGGER.info(
                    "judge tool result credential=%s tool=list_files entries=%d",
                    credential.credential_id,
                    len(entries),
                )
                return entries

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
                if self.config.judge.layer_tools.enabled:
                    program = dspy.ReAct(
                        Signature,
                        tools=[read_file, list_files],
                        max_iters=self.config.judge.max_iterations,
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
