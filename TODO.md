# TODO

The inventory workflow is implemented in `current_plan.md` and the runtime.

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
