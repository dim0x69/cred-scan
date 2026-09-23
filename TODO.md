# TODO

The intended inventory workflow is documented in `AGENTS.md` and
[the visual guide](doc/end-to-end.html). The original implementation milestones
are recorded below; the review identifies remaining implementation gaps.

- [x] **Backend-scoped workspace layout.** Store each backend in
      `<workspace>/<backend>/` with `backend.json` and enrolled boundaries below
      `boundaries/`.
- [x] **Separate inventory lifecycle operations.** `inventory add` enrolls new
      boundaries; `inventory update` refreshes registered boundaries and handles
      confirmed absence without backend-wide discovery.
- [x] **Bounded enrollment.** `inventory add --new-count N` streams backend
      discovery and stops after N newly discovered boundaries.
- [x] **Backend selection.** Inventory can target one backend; source commands
      process persisted backends sequentially when no backend is selected.
- [x] **Workspace migration.** The existing workspace was migrated while
      preserving scan targets, reports, credentials, evidence, and Titus datastores.

## Deep bug and KISS review — 2026-09-23

Reviewed revision: `d6aa7ac` (`Split inventory enrollment and updates`). This is
a review backlog, not a record of implemented fixes or newly agreed design rules.
P1 means address first because credentials or persisted inventory are at risk;
P2 means a reproducible correctness or lifecycle gap; P3 means cleanup or a
documented implementation limitation. Source references below are relative to
`src/cred_scan/` and describe that revision.

### Bugs and invariant gaps

- [ ignore ] **P1 — Prevent bearer-token disclosure through pagination links.**
  `backend/adapters/artifactory/docker.py:477,502` follows arbitrary `Link`
  destinations through `_get`; `common.py:43` installs Authorization as a client
  default. A link to another HTTPS host starts a fresh authenticated request, so
  HTTPX's redirect credential stripping does not protect it. An HTTP link can
  also bypass the configured HTTPS requirement. A mock transport confirmed the
  synthetic bearer token reached an unrelated host. Restrict pagination URLs
  to the configured HTTPS origin, or explicitly implement unauthenticated
  cross-origin requests. Cover absolute links, relative links after redirects,
  and HTTPS-to-HTTP links. This exposes a gap in the intended Artifactory
  authorization boundary; existing redirect tests do not cover pagination.

- [x] **P1 — Do not treat a later catalog-page 404 as confirmed absence.**
      `ArtifactoryDockerBackend._paginated_names()` now preserves a first-page
      `ArtifactoryNotFoundError` for the existing confirmed-absence handling, but
      converts a continuation-page 404 to an `ArtifactoryError` with the original
      exception chained. `inventory()` therefore cannot mistake a failed page for
      absence; `Boundary` leaves `boundary.json` and `scantargets.json` unchanged.
      Adapter and `Workspace.update()` regressions cover the distinction and verify
      both existing documents remain byte-for-byte unchanged on continuation failure.

- [x] **P2 — Persist backend enrollment before successful boundaries can become
      undiscoverable.** `Workspace.add()` now ensures `backend.json` after complete
      discovery and before starting enrollment tasks whenever there are selected or
      already registered boundaries. Partial enrollment failure or cancellation can
      leave valid boundary documents, but the backend workspace remains enumerable.
      Regressions cover partial success followed by failure, cancellation during
      enrollment, discovery failure, empty discovery, and repair of an existing
      registered boundary without its backend marker. The fix does not require a
      multi-document transaction.

- [x] **P2 — Recheck new-only enrollment while holding the boundary lock.**
      `Workspace.add()` uses `Boundary.enroll_inventory()`, which rechecks for an
      existing record under both boundary locks and skips it before calling the
      backend. `Boundary.refresh_inventory()` remains the update path. The race
      regression verifies that an intervening absent registration stays absent,
      backend inventory is not called, and the raced boundary is not counted as a
      new enrollment.

- [x] **P2 — Coordinate inventory with source commands and skip absent boundaries.**
      `LocalRuntime._run_workspaces()` now takes a shared per-backend workspace gate
      for scan/judge/extract and an exclusive gate for inventory add/update, before
      boundary enumeration and through resource cleanup. Workspace enumeration uses
      registered paths; `Boundary.operation()` decides availability under its lock
      and treats absence as a normal skip before source services start. Titus inherits
      both lock descriptors. Regressions cover cross-process exclusion, shared source
      access, absent-boundary TaskGroup behavior, and lock descriptor inheritance.

- [ ] **P2 — Preserve significant whitespace in occurrence locators.**
      `backend/adapters/artifactory/docker.py:131,347` calls `.strip()` on the full
      locator. A layer containing both `app.env` and `app.env ` demonstrates the
      consequence: a locator for the second file returns the first file's bytes.
      This can feed the judge incorrect context and retain incorrect evidence.
      Preserve the exact locator and restrict Titus-compatible cleaning to archive
      matching; reject empty input without trimming valid filename characters.
      Add a regression using both filenames. This violates raw-locator preservation
      and exact source-read invariants.

- [ ] **P2 — Reject malformed manifests before replacing selected targets.**
      `backend/adapters/artifactory/docker.py:423-435` only validates that a manifest
      is an object; `:582-589` treats absent, empty, or wrongly typed `manifests` as
      an ordinary image manifest. Both `{}` and an OCI index with an empty descriptor
      list were accepted as scan scopes when supplied with a timestamp. Arbitrary
      response bytes can receive a computed digest and replace a previously usable
      target. Validate the supported manifest/index shapes, required descriptors,
      and selected child before returning inventory. Cover malformed roots and
      children and assert the previous inventory survives. This violates the rule
      that malformed discovery responses leave persisted selection unchanged.

- [ ] **P2 — Reject malformed Titus export entries instead of publishing a clean
      empty report.** `scan/titus.py:237-242` checks the outer array but silently
      filters non-object entries. A successful mocked export of `[42]` produced
      `findings=()` and `incomplete=False`; publication can then finish without
      exposing the discarded data. `scan/credentials.py:125` repeats the filter,
      while malformed Matches can also disappear without diagnostics. Validate the
      consumed export structure at one boundary and fail publication or explicitly
      record incompleteness. Cover mixed valid/invalid entries and malformed matches,
      retaining the pending-publication retry path on export failure.

- [ ] **P2 — Make Titus use the same once-per-run exclusion contents as
      deduplication.** `orch/global_config.py:25` freezes the loaded patterns, but
      `scan/titus.py:138` passes the original mutable file to every subprocess.
      After loading `old-pattern` and editing the file to `new-pattern`, the mock
      launch still referenced the changed file while `get_exclusions()` returned
      the old pattern. Later scans in one invocation can therefore use different
      exclusions from each other and from deduplication. Provide Titus a run-owned
      snapshot of the already-loaded path patterns and retain it through subprocess
      cleanup. This is an implementation gap in the confirmed once-per-run policy;
      saved credential history must remain untouched.

- [ ] **P3 — Remove or invalidate the stale boundary-object cache after add.**
      `orch/workspace.py:247-257,293-301` caches the pre-enrollment boundary tuple;
      newly constructed boundaries are not inserted and add never invalidates it.
      Reproduced: add returns one, `_registered_boundary_ids()` sees one, but
      `workspace.boundaries` remains empty. Reusing that Workspace for source work
      skips the new boundary. Separate CLI processes reduce the immediate impact,
      but the public aggregate is internally inconsistent. Prefer fresh lightweight
      enumeration, or maintain one explicit identity map with clear invalidation.

- [ ] **P3 — Reconcile the claimed paged discovery with the actual adapter.**
      `backend/adapters/artifactory/common.py:83-101` downloads and decodes the entire
      repository list; `docker.py:563-574` only then yields IDs.
      `orch/workspace.py:174-186` also accumulates selected IDs before enrollment.
      A first-yield check confirmed discovery fetches the whole `/api/repositories`
      response. `--new-count` bounds selected work, but cannot bound the initial
      repository download. The confirmed paged-stream discovery invariant and the
      guide's implementation claim are therefore not fully implemented. Check the
      source's supported discovery API before designing pagination; if that endpoint
      is inherently unpaged, explicitly resolve the limitation with the user rather
      than claiming that an async iterator makes it paged.

### KISS follow-ups

These are simplification proposals, not new invariants. Keep the boundary lock,
complete per-document checkpoints, cumulative Titus datastore, direct model
mutation, and separate command processes intact.

- [x] **Use one small atomic JSON writer.** `Boundary._write`
      (`orch/boundary.py:143`), `_write_backend_record` (`orch/workspace.py:135`), and
      `_WorkspaceStorage.write` (`tools/migrate_workspace_schema.py:71`) duplicate
      temporary-file creation, JSON serialization, fsync, rename, and cleanup with
      slightly different validation. Share the mechanical writer while leaving
      document ownership and checkpoints with Boundary; avoid a generic repository
      or transaction framework.

- [x] **Simplify inventory dispatch.** `InventoryRequest.backend` is unused,
      and `select_boundaries` dispatches back to add/update after those operations
      were already selected by the caller. Update only needs sorted registered IDs;
      add needs a new-ID iterator and a limit. Keep those two paths explicit and
      place enrollment's ownership check in Boundary. Remove the request wrapper if
      it has no remaining purpose.

- [x] **Remove unused duplicate helpers.** `Boundary.mark_absent`
      (`orch/boundary.py:314`) has no production or existing-test callers and
      duplicates refresh's record validation and absence persistence.
      `_WorkspaceStorage.read` and `_optional` in the migration tool, and
      `BackendName` in `orch/models.py`, also have no callers. Remove unused paths
      or give genuinely shared behavior one implementation. Keep the one-workspace
      migration as an offline tool; do not expand historical compatibility machinery.

- [x] **Validate backend settings once with a small typed model.**
      `AppConfig.backends` (`orch/models.py:91`) contains arbitrary dictionaries,
      requiring scattered `.get`, indexing, string coercion, duplicate-name checks,
      and late platform parsing in runtime code. Model the implemented Docker
      backend's required URL and platform fields at configuration load and report
      errors there. Avoid a dynamic plugin registry for the single implemented
      backend, and preserve standard configuration source precedence.

### Verification and limits

- Existing suite: **147 passed**, with 11 dependency deprecation warnings.
  The sandbox stalled on a minimal `asyncio.to_thread` check as well as the
  evidence test; the suite completed outside the sandbox in 5.65 seconds.
- `.venv/bin/ruff check .` and `.venv/bin/ty check src`: **passed**.
- Twelve temporary diagnostic cases exercised the reported bugs/gaps, including
  two malformed-manifest variants. They use synthetic credentials, mock HTTP
  responses, controlled operation ordering, and temporary workspaces. Their
  assertions document current faulty behavior; convert them to expected-behavior
  regressions when implementing fixes. The temporary harness is not committed.
- No live Artifactory or LLM calls or real Titus scans were made. The configured
  `./workspace` is
  absent in this checkout, so accumulated production data and the earlier
  migration's real outcome could not be audited. The checked migration milestone
  above is historical, not newly verified by this review.
- No application behavior, persisted format, or agreed invariant was changed.
  Implementation work should update the visual guide's affected implementation
  claims alongside fixes. The obsolete `current_plan.md` reference at the top
  of this file was replaced with the existing authoritative documentation.
