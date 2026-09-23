"""Small durable atomic JSON writes for workspace documents."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cred_scan.orch.fsync import fsync_directory


def write_json_atomic(path: Path, payload: Any) -> None:
    """Write one JSON value with an atomic same-directory replacement."""
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path: Path | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        fsync_directory(path.parent)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
