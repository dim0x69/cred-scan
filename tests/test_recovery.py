"""Exercise the real scheduler/checkpoints with fresh runtimes and fake services."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, create_autospec

import pytest

from cred_scan.backend.models import ResolvedProvenance, ScanBoundaryInventory, target_id_for
from cred_scan.backend.proto import BackendAdapter, ContentReader
from cred_scan.common.workspace import Workspace, WorkspaceBusyError
from cred_scan.judge.proto import FindingJudge
from cred_scan.orch import runtime
from cred_scan.orch.runtime import LocalRuntime
from cred_scan.scan.models import (
    CredentialsDocument,
    ExclusionPolicy,
    JudgmentResult,
    TitusReport,
)
from cred_scan.scan.proto import CredentialScanner


@pytest.fixture
def harness(app_config, repository_inventory, credential, monkeypatch):
    workspace = Workspace(app_config.workspace)
    scanner = create_autospec(CredentialScanner, instance=True)
    judge = create_autospec(FindingJudge, instance=True)
    judge.judge.return_value = JudgmentResult(verdict="VALID")
    readers, backends = [], []

    def seed(inventory, candidate):
        paths = workspace.boundary(inventory.boundary.id)
        workspace.write(paths.inventory, inventory, ScanBoundaryInventory)
        workspace.write(
            paths.report,
            TitusReport(
                boundary_id=inventory.boundary.id,
                generated_at="old",
                findings=({"historical": True},),
            ),
            TitusReport,
        )
        workspace.write(
            paths.credentials,
            CredentialsDocument(
                boundary_id=inventory.boundary.id,
                report_generated_at="old",
                credentials={candidate.credential_id: candidate},
            ),
            CredentialsDocument,
        )
        return paths

    paths = seed(repository_inventory, credential)

    def build(*_args):
        backend = create_autospec(BackendAdapter, instance=True)
        backend.name = "primary"
        backends.append(backend)

        def content_reader(boundary, targets):
            reader = create_autospec(ContentReader, instance=True)
            reader.boundary_id = boundary.id

            async def resolve(raw_path, *, target_id=None):
                reader.aclose.assert_not_awaited()
                return ResolvedProvenance(
                    target_id=target_id or targets[0].id,
                    provenance=raw_path,
                    source_path="etc/app.env",
                    filename="app.env",
                )

            async def extract_file(_provenance, destination):
                reader.aclose.assert_not_awaited()
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"synthetic evidence")
                return destination

            reader.resolve_provenance.side_effect = resolve
            reader.extract_file.side_effect = extract_file
            readers.append(reader)
            return reader

        backend.content_reader.side_effect = content_reader
        return backend

    async def scan(target, work_dir, datastore, policy):
        assert work_dir.parent == datastore.parent / "scratch"
        return target.model_copy(
            update={"result": target.result.model_copy(update={"status": "scanned"})}
        )

    async def export(datastore):
        inventory = workspace.read(
            datastore.parent / "inventory.json", ScanBoundaryInventory
        )
        assert inventory is not None
        return TitusReport(boundary_id=inventory.boundary.id, generated_at="new")

    scanner.scan.side_effect = scan
    scanner.export_report.side_effect = export
    policy = Mock(return_value=ExclusionPolicy(path_file=app_config.exclusions.paths))
    monkeypatch.setattr(runtime, "build_backend", build)
    monkeypatch.setattr(runtime, "TitusCliScanner", Mock(return_value=scanner))
    monkeypatch.setattr(runtime, "DspyFindingJudge", Mock(return_value=judge))
    monkeypatch.setattr(runtime, "load_exclusions", policy)
    return SimpleNamespace(
        config=app_config,
        inventory=repository_inventory,
        credential=credential,
        workspace=workspace,
        paths=paths,
        scanner=scanner,
        judge=judge,
        readers=readers,
        backends=backends,
        seed=seed,
        policy=policy,
    )


def test_claim_interrupt_restarts_from_disk_without_rescanning_completed_pin(
    harness, monkeypatch
):
    h = harness
    original = h.scanner.scan.side_effect
    first = h.inventory.targets[0].model_copy(deep=True)
    first.result.status = "scanned"
    scope = first.scope.model_copy(update={"digest": "sha256:new-pin"})
    second = first.model_copy(
        update={
            "id": target_id_for(scope),
            "scope": scope,
            "result": first.result.model_copy(update={"status": "pending"}),
        }
    )
    inventory = h.inventory.model_copy(update={"targets": (first, second)})
    h.workspace.write(h.paths.inventory, inventory, ScanBoundaryInventory)

    async def interrupt(target, work_dir, *_):
        assert target.id == second.id
        saved = Workspace(h.config.workspace).read(
            h.paths.inventory, ScanBoundaryInventory
        )
        assert saved is not None
        assert [t.result.status for t in saved.targets] == ["scanned", "running"]
        (work_dir / "partial").write_text("temporary")
        raise RuntimeError("interrupted after claim")

    h.scanner.scan.side_effect = interrupt
    with pytest.raises(ExceptionGroup):
        asyncio.run(LocalRuntime(h.config).scan())
    assert not h.paths.scratch_parent.exists()
    h.judge.judge.assert_not_awaited()
    assert all(b.aclose.await_count == 1 for b in h.backends)

    writes = []
    original_write = Workspace.write

    def record(self, path, document, model_type):
        if path == h.paths.inventory:
            writes.append(tuple(t.result.status for t in document.targets))
        return original_write(self, path, document, model_type)

    monkeypatch.setattr(Workspace, "write", record)
    h.scanner.scan.reset_mock()
    h.scanner.scan.side_effect = original
    assert asyncio.run(LocalRuntime(h.config).scan()) == 1
    assert writes == [
        ("scanned", "pending"),
        ("scanned", "running"),
        ("scanned", "scanned"),
    ]
    assert h.scanner.scan.await_count == 1
    assert h.scanner.scan.call_args.args[0].id == second.id
    h.judge.judge.assert_awaited_once()


def test_three_attempts_share_scratch_and_datastore_with_only_target_checkpoints(
    harness, monkeypatch
):
    h = harness
    calls, writes = [], []
    original_write = Workspace.write

    def record(self, path, document, model_type):
        if path == h.paths.inventory:
            writes.append(document.targets[0].result.status)
        return original_write(self, path, document, model_type)

    async def attempt(target, work_dir, datastore, _policy):
        assert target.result.status == "running"
        calls.append((target.id, work_dir, datastore))
        (work_dir / "same-session").write_text("temporary")
        return target.model_copy(
            update={
                "result": target.result.model_copy(
                    update={"status": "scanned" if len(calls) == 3 else "partial"}
                )
            }
        )

    monkeypatch.setattr(Workspace, "write", record)
    h.scanner.scan.side_effect = attempt
    assert asyncio.run(LocalRuntime(h.config).scan()) == 1
    assert len(calls) == 3 and len(set(calls)) == 1
    assert calls[0][2] == h.paths.datastore
    assert writes == ["running", "scanned"]
    assert not h.paths.scratch_parent.exists()


@pytest.mark.parametrize("failure", ["export", "conversion", "publication"])
def test_failed_publication_restarts_at_last_checkpoint(harness, monkeypatch, failure):
    h = harness
    old_report = h.paths.report.read_bytes()
    old_credentials = h.paths.credentials.read_bytes()
    sentinel = h.paths.boundary_dir / "evidence" / "historical" / "keep.env"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_bytes(b"historical evidence")
    with monkeypatch.context() as patch:
        if failure == "export":
            patch.setattr(
                h.scanner.export_report, "side_effect", RuntimeError("export failed")
            )
        elif failure == "conversion":
            patch.setattr(
                runtime,
                "deduplicate_report",
                AsyncMock(side_effect=RuntimeError("conversion failed")),
            )
        else:
            write = Workspace.write

            def fail(self, path, document, model_type):
                if path == h.paths.credentials:
                    raise OSError("publication failed")
                return write(self, path, document, model_type)

            patch.setattr(Workspace, "write", fail)
        with pytest.raises(ExceptionGroup):
            asyncio.run(LocalRuntime(h.config).scan())
    h.judge.judge.assert_not_awaited()
    assert h.paths.credentials.read_bytes() == old_credentials
    assert (h.paths.report.read_bytes() == old_report) == (failure == "export")
    assert sentinel.read_bytes() == b"historical evidence"
    assert all(reader.aclose.await_count == 1 for reader in h.readers)
    h.scanner.scan.reset_mock()
    assert asyncio.run(LocalRuntime(h.config).scan()) == 1
    h.scanner.scan.assert_not_awaited()  # Completed inventory survived the failure.
    saved = Workspace(h.config.workspace).read(h.paths.credentials, CredentialsDocument)
    assert saved is not None and saved.report_generated_at == "new"
    assert len(saved.credentials) == 1
    assert saved.credentials[h.credential.credential_id].judgment.verdict == "VALID"
    assert sentinel.read_bytes() == b"historical evidence"


@pytest.mark.parametrize("failure", ["judgment", "metadata", "extraction"])
def test_credential_checkpoint_failure_is_recoverable_without_losing_other_records(
    harness, monkeypatch, failure
):
    h = harness
    other = h.credential.model_copy(update={"credential_id": "zz-second"})
    initial = h.workspace.read(h.paths.credentials, CredentialsDocument)
    assert initial is not None
    initial.credentials[other.credential_id] = other
    h.workspace.write(h.paths.credentials, initial, CredentialsDocument)
    write = Workspace.write
    original = runtime.retain_first_evidence
    failed = False

    def failing_write(self, path, document, model_type):
        nonlocal failed
        if path == h.paths.credentials:
            candidate = document.credentials["zz-second"]
            if not failed and (
                (failure == "judgment" and candidate.judgment.verdict == "VALID")
                or (failure == "metadata" and candidate.extraction is not None)
            ):
                failed = True
                raise OSError("checkpoint failed")
        return write(self, path, document, model_type)

    async def failing_extraction(candidate, *args):
        if candidate.credential_id == "zz-second":
            raise OSError("extraction failed")
        return await original(candidate, *args)

    with monkeypatch.context() as patch:
        patch.setattr(Workspace, "write", failing_write)
        if failure == "extraction":
            patch.setattr(runtime, "retain_first_evidence", failing_extraction)
            assert asyncio.run(LocalRuntime(h.config).scan()) == 1
        else:
            with pytest.raises(ExceptionGroup):
                asyncio.run(LocalRuntime(h.config).scan())
    saved = Workspace(h.config.workspace).read(h.paths.credentials, CredentialsDocument)
    assert saved is not None
    first = saved.credentials[h.credential.credential_id]
    second = saved.credentials["zz-second"]
    assert first.judgment.verdict == "VALID"
    assert first.extraction is not None and first.extraction.status == "RETAINED"
    assert second.judgment.verdict == ("PENDING" if failure == "judgment" else "VALID")
    if failure == "extraction":
        assert second.extraction is not None and second.extraction.status == "ERROR"
    else:
        assert second.extraction is None
    if failure == "metadata":
        assert list((h.paths.boundary_dir / "evidence" / "zz-second").glob("*"))
    assert all(reader.aclose.await_count == 1 for reader in h.readers)
    h.judge.judge.reset_mock()
    if failure == "judgment":
        assert asyncio.run(LocalRuntime(h.config).judge()) == 1
    assert asyncio.run(LocalRuntime(h.config).extract()) == 1
    assert h.judge.judge.await_count == int(failure == "judgment")
    recovered = Workspace(h.config.workspace).read(
        h.paths.credentials, CredentialsDocument
    )
    assert recovered is not None
    assert recovered.credentials[h.credential.credential_id] == first
    assert all(
        c.extraction is not None and c.extraction.status == "RETAINED"
        for c in recovered.credentials.values()
    )


@pytest.mark.parametrize("phase", ["scan", "judge"])
def test_cancellation_closes_services_and_releases_operation_lock(harness, phase):
    h = harness

    async def scenario():
        entered, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def wait_forever(*_args):
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        if phase == "scan":
            h.scanner.scan.side_effect = wait_forever
        else:
            h.judge.judge.side_effect = wait_forever
        task = asyncio.create_task(LocalRuntime(h.config).scan())
        try:
            await entered.wait()
            with pytest.raises(WorkspaceBusyError):
                with Workspace(h.config.workspace).operation_lock():
                    raise AssertionError("operation lock released early")
            task.cancel()
            # Observe without a timeout that could issue a second cancellation.
            done, _ = await asyncio.wait({task}, timeout=0.5)
            assert task in done, "one cancellation must stop the async service"
            with pytest.raises(asyncio.CancelledError):
                await task
            assert cancelled.is_set()
            with Workspace(h.config.workspace).operation_lock():
                pass
            assert not h.paths.scratch_parent.exists()
            assert all(reader.aclose.await_count == 1 for reader in h.readers)
            assert all(backend.aclose.await_count == 1 for backend in h.backends)
            saved = Workspace(h.config.workspace).read(
                h.paths.inventory, ScanBoundaryInventory
            )
            assert saved is not None
            assert saved.targets[0].result.status == (
                "running" if phase == "scan" else "scanned"
            )
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


@pytest.mark.parametrize("owner", ["inventory", "scan", "judge", "extract"])
@pytest.mark.parametrize("contender", ["inventory", "scan", "judge", "extract"])
def test_top_level_operations_hold_the_same_lock_for_the_complete_operation(
    harness, monkeypatch, owner, contender
):
    h = harness

    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def wait_forever(*_args):
            entered.set()
            await release.wait()
            return 0

        local = LocalRuntime(h.config)
        if owner == "inventory":
            monkeypatch.setattr(runtime, "run_inventory", wait_forever)
        elif owner == "scan":
            h.scanner.scan.side_effect = wait_forever
        else:
            if owner == "extract":
                document = h.workspace.read(h.paths.credentials, CredentialsDocument)
                document.credentials[
                    h.credential.credential_id
                ].judgment = JudgmentResult(verdict="VALID")
                h.workspace.write(h.paths.credentials, document, CredentialsDocument)
                monkeypatch.setattr(runtime, "retain_first_evidence", wait_forever)
            else:
                h.judge.judge.side_effect = wait_forever
        task = asyncio.create_task(getattr(local, owner)())
        await entered.wait()
        try:
            with pytest.raises(WorkspaceBusyError):
                await getattr(LocalRuntime(h.config), contender)()
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        with Workspace(h.config.workspace).operation_lock():
            pass

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


def test_multiple_boundaries_scan_concurrently_but_judge_serially_after_publication(
    harness,
):
    h = harness
    h.config.scan_concurrency = 2
    for index in (2, 3):
        boundary = h.inventory.boundary.model_copy(update={"id": f"boundary-{index}"})
        scope = h.inventory.targets[0].scope.model_copy(
            update={"image": f"registry/image-{index}"}
        )
        target = h.inventory.targets[0].model_copy(
            update={
                "id": target_id_for(scope),
                "boundary": boundary,
                "scope": scope,
            }
        )
        inventory = h.inventory.model_copy(
            update={"boundary": boundary, "targets": (target,)}
        )
        candidate = h.credential.model_copy(
            update={
                "occurrences": (
                    h.credential.occurrences[0].model_copy(
                        update={"target_id": target.id}
                    ),
                )
            }
        )
        h.seed(inventory, candidate)

    async def scenario():
        active = set()
        started, maximum, judging, max_judging = [], 0, 0, 0
        overlap = asyncio.Event()
        original_scan = h.scanner.scan.side_effect

        async def scan(target, *args):
            nonlocal maximum
            assert target.id not in active and target.id not in started
            started.append(target.id)
            active.add(target.id)
            maximum = max(maximum, len(active))
            if len(active) == 2:
                overlap.set()
            await overlap.wait()
            await asyncio.sleep(0)
            result = await original_scan(target, *args)
            active.remove(target.id)
            return result

        async def judge(candidate, reader):
            nonlocal judging, max_judging
            judging += 1
            max_judging = max(max_judging, judging)
            paths = h.workspace.boundary(reader.boundary_id)
            saved = Workspace(h.config.workspace).read(
                paths.credentials, CredentialsDocument
            )
            report = Workspace(h.config.workspace).read(paths.report, TitusReport)
            assert saved is not None and report is not None
            assert saved.report_generated_at == report.generated_at == "new"
            assert candidate.credential_id in saved.credentials
            await asyncio.sleep(0)
            judging -= 1
            return JudgmentResult(verdict="VALID")

        h.scanner.scan.side_effect = scan
        h.judge.judge.side_effect = judge
        assert await LocalRuntime(h.config).scan() == 3
        assert len(started) == 3 and maximum == 2 and max_judging == 1
        h.policy.assert_called_once()
        assert all(reader.aclose.await_count == 1 for reader in h.readers)
        assert all(backend.aclose.await_count == 1 for backend in h.backends)
        assert not list(h.workspace.results_dir.glob("*/scratch"))

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


def test_later_scan_and_non_valid_judgment_preserve_indexed_evidence(harness):
    h = harness
    assert asyncio.run(LocalRuntime(h.config).scan()) == 1
    saved = Workspace(h.config.workspace).read(h.paths.credentials, CredentialsDocument)
    assert saved is not None
    old = saved.credentials[h.credential.credential_id]
    assert old.extraction is not None and old.extraction.output_path is not None
    path = h.paths.boundary_dir / old.extraction.output_path
    original_bytes = path.read_bytes()
    # The next report is empty. Append must preserve history without extraction.
    assert asyncio.run(LocalRuntime(h.config).scan()) == 1
    after_scan = Workspace(h.config.workspace).read(
        h.paths.credentials, CredentialsDocument
    )
    assert after_scan is not None
    assert after_scan.credentials[h.credential.credential_id] == old
    old.judgment = JudgmentResult(verdict="ERROR")
    h.workspace.write(h.paths.credentials, saved, CredentialsDocument)
    h.judge.judge.return_value = JudgmentResult(verdict="INVALID")
    assert asyncio.run(LocalRuntime(h.config).judge()) == 1
    latest = Workspace(h.config.workspace).read(
        h.paths.credentials, CredentialsDocument
    )
    assert latest is not None
    assert latest.credentials[h.credential.credential_id].extraction == old.extraction
    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize("failure_phase", ["scan", "judge"])
def test_worker_or_judger_failure_cancels_sibling_scan(harness, failure_phase):
    h = harness
    h.config.scan_concurrency = 2
    boundary = h.inventory.boundary.model_copy(update={"id": "other-boundary"})
    scope = h.inventory.targets[0].scope.model_copy(update={"image": "registry/other"})
    target = h.inventory.targets[0].model_copy(
        update={
            "id": target_id_for(scope),
            "scope": scope,
            "boundary": boundary,
        }
    )
    other = h.inventory.model_copy(update={"boundary": boundary, "targets": (target,)})
    candidate = h.credential.model_copy(
        update={
            "occurrences": (
                h.credential.occurrences[0].model_copy(update={"target_id": target.id}),
            )
        }
    )
    h.seed(other, candidate)

    async def scenario():
        sibling_entered = asyncio.Event()
        sibling_cancelled = asyncio.Event()
        original = h.scanner.scan.side_effect

        async def scan(target, *args):
            if target.boundary.id == "other-boundary":
                sibling_entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    sibling_cancelled.set()
            await sibling_entered.wait()
            if failure_phase == "scan":
                raise RuntimeError("worker failed")
            return await original(target, *args)

        h.scanner.scan.side_effect = scan
        if failure_phase == "judge":
            # A fatal judgment must propagate, unlike a per-credential ERROR result.
            h.judge.judge.side_effect = runtime.FatalJudgeError("judger failed")
        with pytest.raises(ExceptionGroup):
            await LocalRuntime(h.config).scan()
        assert sibling_cancelled.is_set()
        assert not list(h.workspace.results_dir.glob("*/scratch"))
        assert all(reader.aclose.await_count == 1 for reader in h.readers)
        assert all(backend.aclose.await_count == 1 for backend in h.backends)
        with Workspace(h.config.workspace).operation_lock():
            pass

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


@pytest.mark.parametrize(
    "initial_status,retryable,lifecycle,scope_lifecycle,attempts",
    [
        ("pending", False, "current", "active", 3),
        ("failed", True, "current", "active", 3),
        ("partial", True, "current", "active", 3),
        ("failed", False, "current", "active", 0),
        ("partial", False, "current", "active", 0),
        ("scanned", True, "current", "active", 0),
        ("pending", True, "superseded", "active", 0),
        ("pending", True, "current", "stale", 0),
    ],
)
def test_target_snapshot_processes_each_eligible_pin_once_per_run(
    harness, initial_status, retryable, lifecycle, scope_lifecycle, attempts
):
    h = harness
    original = h.inventory.targets[0].model_copy(deep=True)
    original.result.status = "scanned"
    other_scope = original.scope.model_copy(
        update={
            "image": "registry/eligibility-test",
            "lifecycle": scope_lifecycle,
        }
    )
    other = original.model_copy(
        update={
            "id": target_id_for(other_scope),
            "scope": other_scope,
            "lifecycle": lifecycle,
            "result": original.result.model_copy(
                update={
                    "status": initial_status,
                    "retryable": retryable,
                }
            ),
        }
    )
    h.workspace.write(
        h.paths.inventory,
        h.inventory.model_copy(
            update={
                "targets": (original, other),
            }
        ),
        ScanBoundaryInventory,
    )
    seen = []

    async def fail(target, work_dir, datastore, _policy):
        assert target.id == other.id and target.result.status == "running"
        seen.append((target.id, work_dir, datastore))
        return target.model_copy(
            update={
                "result": target.result.model_copy(
                    update={
                        "status": "partial",
                        "retryable": True,
                        "errors": ("transient",),
                    }
                )
            }
        )

    h.scanner.scan.side_effect = fail

    async def scenario():
        assert await LocalRuntime(h.config).scan() == 1
        assert len(seen) == attempts
        if attempts:
            assert len(set(seen)) == 1
        saved = Workspace(h.config.workspace).read(
            h.paths.inventory, ScanBoundaryInventory
        )
        assert saved is not None and saved.targets[0] == original
        assert saved.targets[1].result.status == (
            "partial" if attempts else initial_status
        )
        assert not h.paths.scratch_parent.exists()
        # A remaining retryable failure is retried on the NEXT run, not endlessly now.
        assert await LocalRuntime(h.config).scan() == 1
        assert len(seen) == attempts * 2

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


@pytest.mark.parametrize("failure", [False, True])
def test_scheduler_handoff_waits_for_publication_without_a_phase_flag(
    harness, monkeypatch, failure
):
    h = harness
    original = runtime.deduplicate_report

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()

        async def convert(*args):
            entered.set()
            await release.wait()
            if failure:
                raise RuntimeError("conversion failed before publication")
            return await original(*args)

        monkeypatch.setattr(runtime, "deduplicate_report", convert)
        operation = asyncio.create_task(LocalRuntime(h.config).scan())
        try:
            await entered.wait()
            report = h.workspace.read(h.paths.report, TitusReport)
            document = h.workspace.read(h.paths.credentials, CredentialsDocument)
            assert report is not None and report.generated_at == "new"
            assert document is not None and document.report_generated_at == "old"
            h.judge.judge.assert_not_awaited()
            release.set()
            if failure:
                with pytest.raises(ExceptionGroup):
                    await operation
                h.judge.judge.assert_not_awaited()
            else:
                assert await operation == 1
                h.judge.judge.assert_awaited_once()
                saved = h.workspace.read(h.paths.credentials, CredentialsDocument)
                assert saved is not None and saved.report_generated_at == "new"
        finally:
            release.set()
            await asyncio.gather(operation, return_exceptions=True)

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


def test_scan_with_no_boundaries_constructs_no_phase_services(harness, monkeypatch):
    h = harness
    inventory = h.inventory.model_copy(update={"lifecycle": "stale"})
    h.workspace.write(h.paths.inventory, inventory, ScanBoundaryInventory)
    scanner = Mock(side_effect=AssertionError("no scanner needed"))
    judge = Mock(side_effect=AssertionError("no judge needed"))
    backend = Mock(side_effect=AssertionError("no backend needed"))
    monkeypatch.setattr(runtime, "TitusCliScanner", scanner)
    monkeypatch.setattr(runtime, "DspyFindingJudge", judge)
    monkeypatch.setattr(runtime, "build_backend", backend)
    assert asyncio.run(LocalRuntime(h.config).scan()) == 0
    scanner.assert_not_called()
    judge.assert_not_called()
    backend.assert_not_called()


@pytest.mark.parametrize("change_pin", [False, True])
def test_snapshot_order_and_immutable_completion_are_preserved(harness, change_pin):
    h = harness
    extra_scope = h.inventory.targets[0].scope.model_copy(
        update={"image": "registry/second-source"}
    )
    extra = h.inventory.targets[0].model_copy(
        update={
            "scope": extra_scope,
            "id": target_id_for(extra_scope),
        }
    )
    inventory = h.inventory.model_copy(
        update={"targets": h.inventory.targets + (extra,)}
    )
    h.workspace.write(h.paths.inventory, inventory, ScanBoundaryInventory)
    old_report = h.paths.report.read_bytes()
    seen = []

    async def scan(target, *_args):
        seen.append(target.id)
        updates = {"result": target.result.model_copy(update={"status": "scanned"})}
        if change_pin:
            updates["scope"] = target.scope.model_copy(
                update={"digest": "sha256:wrong-pin"}
            )
        return target.model_copy(update=updates)

    h.scanner.scan.side_effect = scan
    if change_pin:
        with pytest.raises(ExceptionGroup):
            asyncio.run(LocalRuntime(h.config).scan())
        assert seen == [inventory.targets[0].id]
        assert h.paths.report.read_bytes() == old_report
        h.judge.judge.assert_not_awaited()
    else:
        assert asyncio.run(LocalRuntime(h.config).scan()) == 1
        assert seen == [target.id for target in inventory.targets]
    saved = h.workspace.read(h.paths.inventory, ScanBoundaryInventory)
    assert saved is not None
    assert [t.scope for t in saved.targets] == [t.scope for t in inventory.targets]
    assert [t.result.status for t in saved.targets] == (
        ["running", "pending"] if change_pin else ["scanned", "scanned"]
    )
