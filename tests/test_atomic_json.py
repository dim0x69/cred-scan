import json
from pathlib import Path

import pytest

from cred_scan.orch import json_io
from cred_scan.orch.json_io import write_json_atomic


def test_write_json_atomic_creates_parent_and_serializes_stably(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "document.json"

    write_json_atomic(destination, {"z": 1, "a": {"value": True}})

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "a": {"value": True},
        "z": 1,
    }
    assert destination.read_text(encoding="utf-8").endswith("\n")
    assert tuple(destination.parent.glob(".document.json.*.tmp")) == ()


def test_write_json_atomic_cleans_temporary_file_if_replace_fails(
    tmp_path: Path, monkeypatch
) -> None:
    destination = tmp_path / "document.json"
    destination.write_text("previous", encoding="utf-8")

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(json_io.os, "replace", fail_replace)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_json_atomic(destination, {"value": "new"})

    assert destination.read_text(encoding="utf-8") == "previous"
    assert tuple(tmp_path.glob(".document.json.*.tmp")) == ()


def test_write_json_atomic_rejects_non_json_before_creating_destination(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "nested" / "document.json"

    with pytest.raises(TypeError):
        write_json_atomic(destination, {"value": object()})

    assert not destination.parent.exists()
