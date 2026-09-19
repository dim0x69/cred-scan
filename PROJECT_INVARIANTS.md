# Project invariants

- A report boundary groups notifications; a scope identifies the logical source; a target carries its immutable pin.
- Inventory is authoritative, append-only, lifecycle-aware, and never deletes historical pins or occurrences.
- Each report boundary has one Titus datastore, and one worker owns one target and all its Titus invocations.
- Inventory, scan, judgment, and extraction operations are serialized by the single Workspace workflow.
- Scan publishes candidates only after the final boundary-wide Titus export; every occurrence references a nonempty pinned target ID.
- Only extracted files with nonexcluded findings are retained, with compact provenance and result metadata.
- Only VALID judgments trigger evidence extraction; retained evidence is never overwritten, and missing or corrupt evidence fails visibly.
- No whole-image, repository, archive, or general blob cache is allowed; a Boundary reader may reuse exact resolved locations and reads for its lifecycle.
- Runtime settings, workspace location, Titus, LLM, backend, and exclusion paths come from configuration; exclusions load once per run.
- Canonical schema versions, IDs, and field names are strict; legacy aliases, fallback IDs, and runtime migrations are forbidden.
- Backend discovery does not import scan, judgment, or orchestration; scan does not import judgment or orchestration; common remains feature-independent.
