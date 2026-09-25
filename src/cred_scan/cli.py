"""Thin local CLI for backend and boundary workflow operations."""

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
    help="Backend-agnostic credential scanner; commands process boundaries concurrently.",
    add_completion=False,
    no_args_is_help=True,
)
inventory_app = typer.Typer(
    help="Enroll or refresh backend boundary inventories.",
    add_completion=False,
    no_args_is_help=True,
)
app.add_typer(inventory_app, name="inventory")


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
        LOGGER.exception("command failed command=%s", command)
        raise typer.Exit(1)


ConfigOption = Annotated[
    Path, typer.Option("--config", "-c", help="Central configuration file.")
]
BackendOption = Annotated[str | None, typer.Option("--backend", help="Backend name.")]


@inventory_app.command("add")
def inventory_add(
    backend: BackendOption = None,
    new_count: Annotated[
        int | None,
        typer.Option("--new-count", min=0, help="Maximum new boundaries to add."),
    ] = None,
    config: ConfigOption = Path("config.yml"),
) -> None:
    """Enroll new backend boundaries without refreshing existing ones."""
    _run(
        "inventory add",
        config,
        lambda runtime: runtime.inventory_add(backend, new_count),
        "added {count} boundary(ies)",
    )


@inventory_app.command("update")
def inventory_update(
    backend: BackendOption = None,
    config: ConfigOption = Path("config.yml"),
) -> None:
    """Refresh registered boundaries and reconcile their availability."""
    _run(
        "inventory update",
        config,
        lambda runtime: runtime.inventory_update(backend),
        "updated {count} boundary(ies)",
    )


@app.command()
def scan(
    backend: BackendOption = None,
    failed: Annotated[
        bool, typer.Option("--failed", help="Also retry saved failures in this stage.")
    ] = False,
    config: ConfigOption = Path("config.yml"),
) -> None:
    """Scan persisted boundaries, optionally restricted to one backend."""
    _run(
        "scan",
        config,
        lambda runtime: runtime.scan(backend, failed=failed),
        "scanned {count} boundary(ies)",
    )


@app.command()
def judge(
    backend: BackendOption = None,
    failed: Annotated[
        bool, typer.Option("--failed", help="Also retry saved failures in this stage.")
    ] = False,
    config: ConfigOption = Path("config.yml"),
) -> None:
    """Judge pending credentials, optionally restricted to one backend."""
    _run(
        "judge",
        config,
        lambda runtime: runtime.judge(backend, failed=failed),
        "judged {count} credential(s)",
    )


@app.command()
def extract(
    backend: BackendOption = None,
    failed: Annotated[
        bool, typer.Option("--failed", help="Also retry saved failures in this stage.")
    ] = False,
    config: ConfigOption = Path("config.yml"),
) -> None:
    """Extract eligible evidence, optionally restricted to one backend."""
    _run(
        "extract",
        config,
        lambda runtime: runtime.extract(backend, failed=failed),
        "extracted {count} credential(s)",
    )


if __name__ == "__main__":
    app()
