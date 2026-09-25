"""Offline migration of the existing backend workspaces to boundary phases.

Run with all commands and Titus children stopped. Document backups are written
before changes; datastore and evidence files are never opened for writing.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from pydantic import BaseModel

from cred_scan.backend.models import (
    PHASE_ORDER,
    BackendWorkspaceRecord,
    BoundaryPhase,
    BoundaryRecord,
    ScanTargetInventory,
)
from cred_scan.orch.fsync import fsync_directory
from cred_scan.orch.json_io import write_json_atomic
from cred_scan.scan.models import CredentialsDocument, TitusReport


def _read(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected a document")
    return payload


def _validate(path: Path, model: type[BaseModel], payload: dict[str, Any]) -> BaseModel:
    try:
        return model.model_validate(payload)
    except ValueError:
        raise ValueError(
            f"{path}: invalid {model.__name__}; inspect the document before migration"
        ) from None


def _convert_credentials(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != 8:
        raise ValueError("expected credentials schema 8")
    payload["schema_version"] = 9
    payload.pop("incomplete", None)
    for credential in payload["credentials"].values():
        judgment = credential["judgment"]
        verdict = judgment["verdict"]
        if verdict in {"VALID", "INVALID", "UNKNOWN"}:
            judgment.update(status="completed", verdict=verdict.lower(), error=None)
        elif verdict == "PENDING":
            judgment.update(status="pending", verdict=None, error=None)
        elif verdict == "ERROR":
            judgment.update(
                status="failed",
                verdict=None,
                error=judgment.get("reasoning") or "legacy judgment failed",
                reasoning="",
            )
        else:
            raise ValueError("unrecognized legacy judgment verdict")
        extraction = credential.get("extraction")
        if extraction is None:
            credential["extraction"] = {"status": "pending"}
        elif extraction["status"] in {"RETAINED", "ERROR"}:
            extraction["status"] = {"RETAINED": "retained", "ERROR": "failed"}[
                extraction["status"]
            ]
        else:
            raise ValueError("unrecognized legacy extraction status")
    return payload


def _initial_phase(
    record: dict[str, Any],
    inventory: dict[str, Any] | None,
    report: dict[str, Any] | None,
    credentials: dict[str, Any] | None,
) -> BoundaryPhase:
    if record["availability"] == "absent":
        return "scan"  # Restoration inventories the boundary again before work.
    if inventory is None:
        raise ValueError("available boundary has no scan targets")
    if inventory.get("publication_pending") or any(
        target["result"]["status"] in {"pending", "running"}
        for target in inventory["targets"]
    ):
        return "scan"
    if report is None and credentials is None:
        return "scan"
    if (
        report is None
        or credentials is None
        or report["generated_at"] != credentials["report_generated_at"]
    ):
        raise ValueError("ambiguous publication; provide an explicit --phase override")
    if any(
        item["judgment"]["status"] == "pending"
        for item in credentials["credentials"].values()
    ):
        return "judge"
    if any(
        item["extraction"]["status"] == "pending"
        for item in credentials["credentials"].values()
    ):
        return "extract"
    return "done"


def migrate_workspace(
    workspace_dir: Path,
    *,
    apply: bool = False,
    phases: dict[str, BoundaryPhase] | None = None,
) -> int:
    """Preflight every document; back up originals and migrate records last."""
    if not workspace_dir.is_dir():
        raise ValueError(f"workspace directory does not exist: {workspace_dir}")
    phases = phases or {}
    known = set()
    pending: list[list[tuple[Path, bytes, BaseModel]]] = []
    markers = sorted(workspace_dir.glob("*/backend.json"))
    if not markers:
        raise ValueError("no backend workspaces found")
    for marker in markers:
        backend = _validate(marker, BackendWorkspaceRecord, _read(marker))
        backend_name = backend.model_dump()["name"]
        if unquote(marker.parent.name) != backend_name:
            raise ValueError(f"{marker}: backend identity mismatch")
        for record_path in sorted(
            (marker.parent / "boundaries").glob("*/boundary.json")
        ):
            record = _read(record_path)
            boundary_id = record["boundary"]["id"]
            known.add(boundary_id)
            if (
                boundary_id != unquote(record_path.parent.name)
                or record["backend_id"] != backend_name
            ):
                raise ValueError(f"{record_path}: boundary identity mismatch")
            if record.get("schema_version") == 2:
                _validate(record_path, BoundaryRecord, record)
                continue
            if record.get("schema_version") != 1:
                raise ValueError(f"{record_path}: expected boundary schema 1")
            documents = {}
            originals = {record_path: record_path.read_bytes()}
            for name in ("scantargets.json", "report.json", "credentials.json"):
                path = record_path.parent / name
                if path.exists():
                    originals[path] = path.read_bytes()
                    documents[name] = _read(path)
                else:
                    documents[name] = None
            inventory = documents["scantargets.json"]
            report = documents["report.json"]
            credentials = documents["credentials.json"]
            if record["availability"] == "available" and inventory is None:
                raise ValueError(
                    f"{record_path}: available boundary is missing inventory"
                )
            if record["availability"] == "absent" and inventory is not None:
                raise ValueError(f"{record_path}: absent boundary still has inventory")
            if credentials is not None:
                try:
                    _convert_credentials(credentials)
                except (KeyError, ValueError):
                    raise ValueError(
                        f"{record_path.parent}: invalid legacy credentials"
                    ) from None
            try:
                phase = phases.get(boundary_id)
                # An explicit conservative rescan resolves ambiguous publication.
                if phase != "scan":
                    required = _initial_phase(record, inventory, report, credentials)
                    if phase is not None and PHASE_ORDER.index(
                        phase
                    ) > PHASE_ORDER.index(required):
                        raise ValueError("phase override bypasses pending work")
                    phase = phase or required
            except (KeyError, ValueError) as error:
                raise ValueError(f"{record_path.parent}: {error}") from None
            record.update(schema_version=2, phase=phase)
            writes = []
            if inventory is not None:
                if inventory.get("schema_version") != 11:
                    raise ValueError(
                        f"{record_path.parent}: expected scan-target schema 11"
                    )
                inventory.update(schema_version=12)
                inventory.pop("publication_pending", None)
                for target in inventory["targets"]:
                    target["result"].pop("retryable", None)
                    if target["result"]["status"] == "partial":
                        target["result"]["status"] = "failed"
            if report is not None:
                if report.get("schema_version") != 2:
                    raise ValueError(f"{record_path.parent}: expected report schema 2")
                report.update(schema_version=3)
                report.pop("incomplete", None)
            for name, model in (
                ("scantargets.json", ScanTargetInventory),
                ("report.json", TitusReport),
                ("credentials.json", CredentialsDocument),
            ):
                payload = documents[name]
                if payload is None:
                    continue
                identity = (
                    payload["boundary"]["id"]
                    if name == "scantargets.json"
                    else payload["boundary_id"]
                )
                if identity != boundary_id:
                    raise ValueError(
                        f"{record_path.parent / name}: boundary identity mismatch"
                    )
                path = record_path.parent / name
                writes.append((path, originals[path], _validate(path, model, payload)))
            writes.append(
                (
                    record_path,
                    originals[record_path],
                    _validate(record_path, BoundaryRecord, record),
                )
            )
            pending.append(writes)
    if phases.keys() - known:
        raise ValueError("phase override references an unknown boundary")
    if apply:
        # No source documents change until all validation and backups succeed.
        backup_root = workspace_dir / ".phase-migration-backup"
        for writes in pending:
            for path, original, _ in writes:
                if path.read_bytes() != original:
                    raise ValueError(f"document changed during migration: {path}")
                backup = backup_root / path.relative_to(workspace_dir)
                backup.parent.mkdir(parents=True, exist_ok=True)
                if backup.exists():
                    if backup.read_bytes() != original:
                        raise ValueError(
                            f"backup differs; resolve interrupted migration: {backup}"
                        )
                    continue
                with backup.open("xb") as stream:
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
                fsync_directory(backup.parent)
        for writes in pending:
            for path, _, document in writes:
                write_json_atomic(path, document.model_dump(mode="json"))
    return len(pending)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace_dir", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--phase", action="append", default=[], metavar="BOUNDARY_ID=PHASE"
    )
    args = parser.parse_args()
    phases = {}
    for item in args.phase:
        boundary_id, separator, phase = item.rpartition("=")
        if not separator or phase not in {"scan", "judge", "extract", "done"}:
            parser.error("--phase requires BOUNDARY_ID=scan|judge|extract|done")
        phases[boundary_id] = phase
    count = migrate_workspace(args.workspace_dir, apply=args.apply, phases=phases)
    print(f"{'migrated' if args.apply else 'would migrate'} {count} boundary(ies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
