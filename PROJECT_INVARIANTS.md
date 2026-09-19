# Project invariants

User-confirmed design rules. Implementation gaps are tracked in [TODO.md](TODO.md); these rules do not imply all behavior is implemented.

- A boundary is the unit of processing and persistence: it owns inventory, scanning, judgments, evidence, and their stored results. Reporting uses the same grouping. A scope identifies the logical source; a scan target identifies an immutable source version.
- Inventory keeps only the latest selected scan targets. Historical credentials and occurrences remain independent of inventory history. Failed or partial discovery preserves the previous inventory and records the error; replace inventory only after successful discovery.
- Each credential occurrence path identifies the exact immutable source version and file, allowing historical reads without historical inventory.
- Each boundary keeps one cumulative Titus datastore across scan runs, retaining past scan data as new scan targets are added. Inventory replacement does not reset it.
- Each boundary owns one scanner, one judge, and one extractor. Inventory, scan, judgment, and extraction are sequential within a boundary; different boundaries may run concurrently.
- Each boundary scans its scan targets sequentially, with at most one Titus invocation at a time. Titus's internal parallelism remains available; there is no application-level scanner pool within a boundary.
- Scan publishes candidates after scan attempts finish and the boundary-wide Titus export succeeds. Failed scan targets mark the report incomplete but do not block judgment and extraction of available findings. Every occurrence retains a self-contained source path.
- VALID and UNKNOWN judgments enable evidence extraction; retained evidence is never overwritten. On later runs, check only that its file exists and report missing files without automatic replacement; do not verify contents, size, or hash.
- Instruct the judge to prefer the first occurrence's file; it may read and cache additional occurrence files. Extraction retains only the first occurrence's file, reusing cached bytes when available.
- Retrieved-file caches are in-memory only, shared across scan, judgment, and extraction within one boundary workflow, and cleared when that workflow finishes. No cache persists across boundary workflows or runs; no whole-image, repository, archive, or general blob cache is allowed.
- Runtime settings, including workspace location, Titus, LLM, backend, and exclusion paths, come from config.yml. API keys and other secrets come from environment variables or .env. Exclusions load once per run.
- Changed exclusion patterns apply during subsequent scan processing; they do not retroactively filter or delete saved credentials, judgments, or evidence.
- This is a single-user project with one existing workspace. Every change to its persisted format includes migrating that workspace in the same task, preserving its accumulated results and evidence. Do not build compatibility machinery for a hypothetical installed user base.
- Keep module responsibilities clear and avoid circular dependencies; specific import directions are implementation choices.
