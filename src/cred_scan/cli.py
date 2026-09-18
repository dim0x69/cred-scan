"""Thin local CLI for one-boundary workflow operations."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

import typer

from cred_scan.orch.configuration import YamlConfigLoader
from cred_scan.orch.runtime import LocalRuntime

LOGGER = logging.getLogger(__name__)

app = typer.Typer(
    help="Backend-agnostic credential scanner; each invocation advances one boundary.",
    add_completion=False,
    no_args_is_help=True,
)


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def _existing_config(config: Path) -> Path:
    path = config.expanduser().resolve()
    if not path.is_file():
        raise typer.BadParameter(
            f"config file not found: {path}", param_hint="--config"
        )
    return path


def _run(
    command: str,
    config: Path,
    operation: Callable[[LocalRuntime], Awaitable[int]],
    output: str,
) -> None:
    config = _existing_config(config)
    _configure_logging()
    LOGGER.info("starting command=%s config=%s", command, config)

    async def execute() -> None:
        loaded = await YamlConfigLoader().load(config)
        count = await operation(LocalRuntime(loaded))
        typer.echo(output.format(count=count))

    try:
        asyncio.run(execute())
    except Exception:
        LOGGER.error("command failed command=%s config=%s", command, config)
        raise typer.Exit(1)


@app.command()
def inventory(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Refresh the next persisted boundary inventory."""
    _run(
        "inventory",
        config,
        lambda runtime: runtime.inventory(),
        "refreshed inventory for {count} boundary(ies)",
    )


@app.command()
def scan(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Scan the next boundary with pending targets."""
    _run(
        "scan",
        config,
        lambda runtime: runtime.scan(),
        "scanned {count} boundary(ies)",
    )


@app.command()
def judge(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Judge credentials in the next boundary with pending judgments."""
    _run(
        "judge",
        config,
        lambda runtime: runtime.judge(),
        "judged {count} credential(s)",
    )


@app.command()
def extract(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Extract evidence in the next boundary with eligible credentials."""
    _run(
        "extract",
        config,
        lambda runtime: runtime.extract(),
        "extracted {count} credential(s)",
    )


if __name__ == "__main__":
    app()
