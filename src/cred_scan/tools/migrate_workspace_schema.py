"""Offline inventory 7 -> 8 upgrade.

The tool only validates and upgrades inventory documents. Runtime commands use
inventory, report, and credential checkpoints directly; no execution checkpoint
or scheduler state is required.
"""

import argparse
import json
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.common.models import WorkspaceConfig
from cred_scan.orch.workspace import Workspace
from cred_scan.scan.models import CredentialsDocument, TitusReport

DocumentT = TypeVar("DocumentT", bound=BaseModel)


def _payload(path: Path, versions: set[int]) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") not in versions:
        raise ValueError(f"{path}: expected schema version in {sorted(versions)}")
    return value


def _validate(path: Path, model: type[DocumentT], payload: dict[str, Any]) -> DocumentT:
    try:
        return model.model_validate(payload)
    except ValueError:
        # Model errors may contain credential input values. Report only location.
        raise ValueError(f"{path}: invalid {model.__name__}") from None


def _optional(path: Path, version: int, model: type[DocumentT]) -> DocumentT | None:
    if not path.exists():
        return None
    return _validate(path, model, _payload(path, {version}))


def migrate_workspace(workspace_dir: Path, *, apply: bool = False) -> int:
    """Preflight all boundaries under the maintenance lock; dry-run by default."""
    if not workspace_dir.is_dir():
        raise ValueError(f"{workspace_dir}: workspace directory does not exist")
    store = Workspace(WorkspaceConfig(workspace_dir=workspace_dir))
    pending: list[tuple[Any, ScanBoundaryInventory]] = []
    with store.operation_lock():
        for paths in store.inventory_boundaries():
            original = _payload(paths.inventory, {7, 8})
            inventory = _validate(
                paths.inventory,
                ScanBoundaryInventory,
                {**original, "schema_version": 8},
            )
            if paths.boundary_id != inventory.boundary.id:
                raise ValueError(
                    f"{paths.inventory}: boundary directory does not match inventory"
                )
            _optional(paths.report, 2, TitusReport)
            _optional(paths.credentials, 8, CredentialsDocument)
            if original["schema_version"] == 7:
                pending.append((paths, inventory))
        if apply:
            for paths, inventory in pending:
                store.write(paths.inventory, inventory, ScanBoundaryInventory)
    return len(pending)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace_dir", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    count = migrate_workspace(args.workspace_dir, apply=args.apply)
    action = "upgraded" if args.apply else "would upgrade"
    print(f"{action} {count} boundary(ies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
