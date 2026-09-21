# TODO

Findings from the KISS, simplification, and bug review. Open-item approaches are
implementation proposals, not new project invariants. P1 items take priority
over P2 items and cleanup.

## Artifactory discovery and pagination

- [ignore] **P1 — Prevent token disclosure through pagination links.**
  `_paginated_names()` requests next-page URLs using the authenticated client,
  including URLs on another origin or using HTTP. A synthetic cross-origin link
  received the Bearer token. Resolve and validate next-page URLs before requesting
  them; rejecting cross-origin and non-HTTPS pagination is the proposed fix.
  Add regression coverage for both cases.
- [x] **P2 — Support relative pagination links and detect pagination loops.**
  Relative links currently fail because they are passed directly to a client
  without a base URL. Resolve them against the response URL and track visited
  URLs. Test relative catalog/tag links and repeated next-page URLs, preserving
  existing inventory when pagination fails.
- [x] **P1 — Fail discovery when missing timestamps prevent latest-version selection.**
  `_select_latest()` silently ignores tags without usable manifest timestamps.
  If all timestamps are missing, it returns no scan target and inventory refresh
  removes the previous selection; mixed timestamps can produce an incomplete
  selection. Raise a discovery error instead of silently excluding these tags.
  Test missing and malformed timestamps, including mixed candidates, and verify
  that the previous boundary record and scan targets remain unchanged.

Relevant source: [Docker adapter](src/cred_scan/backend/adapters/artifactory/docker.py).

## Source reads and evidence

- [x] **P2 — Normalize tar member path components.**
  Titus cleans reported paths with `path.Clean()`, while later archive lookup sees
  raw tar member names again. Use the same cleaning semantics for both sides,
  preserve raw locators, accept `..`, and reject only empty paths. Test locator
  parsing and actual archive lookup.

Relevant source: [Docker reader](src/cred_scan/backend/adapters/artifactory/docker.py).

## Judgment input and instructions

- [x] **P2 — Bound judge input and observations consistently.**
  Judge input now presents at most ten ordered locations and uses one compact
  serialization; the approximate JSON character context-window counter was
  removed. The registry contains only presented locations, while oversized
  inputs and source observations are left to the provider's actual context
  limit and DSPy's trajectory handling.
- [x] **P2 — Add the first-occurrence preference to the judge instructions.**
  The signature prefers the first location while allowing additional occurrence
  reads, and the behavior is covered by a test.
- [x] **Simplification — Avoid repeatedly serializing the growing judge input.**
  The final compact JSON is serialized once after selecting the ten locations.

Relevant source: [DSPy adapter](src/cred_scan/judge/dspy_adapter.py).

## Structure and shared logic

- [x] **Separate Docker schemas from runtime implementation.** Move
  `DockerImageScanScope` into the existing Artifactory models module so aggregate
  backend models do not import the large Docker adapter. Simplify the resulting
  deferred imports without changing persisted formats.
  Sources: [backend models](src/cred_scan/backend/models.py),
  [Artifactory models](src/cred_scan/backend/adapters/artifactory/models.py),
  [Docker adapter](src/cred_scan/backend/adapters/artifactory/docker.py).
- [x] **Define scan eligibility once.** Share the status/retry predicate used by
  `Boundary.needs_scan()` and `_scan()` target selection, retaining the separate
  publication-pending and missing-document checks.
  Source: [Boundary](src/cred_scan/orch/boundary.py).
- [ignore] **Share atomic document writing.** The duplicate writer is confined to
  the temporary migration script, so a shared abstraction is not justified.
  The original proposal was to replace duplicated serialization,
  temporary-file, replacement, and fsync logic in `Boundary._write()` and the
  migration helper with one small function. Preserve complete-document
  checkpoints, validation, atomic replacement, and durability behavior.
  Sources: [Boundary](src/cred_scan/orch/boundary.py),
  [migration tool](src/cred_scan/tools/migrate_workspace_schema.py).
- [x] **Simplify occurrence deduplication.** Replace repeated linear searches of
  growing occurrence lists with an insertion-ordered dictionary keyed by locator,
  preserving first-occurrence order.
  Source: [scan credential conversion](src/cred_scan/scan/credentials.py).
- [x] **Remove unused indirection and unreachable checks.** Remove the uncalled
  `run_inventory()` wrapper and the second, unreachable `backend_config is None`
  check in `Workspace._load_backend()`.
  Source: [Workspace](src/cred_scan/orch/workspace.py).
