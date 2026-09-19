# Project instructions

## Core terms

- **Backend:** the source-system adapter responsible for discovery and source reads.
- **Boundary (`ScanBoundary`):** the unit of processing and persistence, such as an Artifactory repository. It owns inventory, scanning, judgments, evidence, and their stored results; reporting uses the same grouping.
- **Scope (`ScanScope`):** a logical source, such as a Docker image, Git repository, or package.
- **Scan target (`ScanTarget`):** an exact immutable version of a scope to scan within a boundary. Use “scan target”, not “pin”, as its name.
- **Inventory:** the boundary document listing its latest selected scan targets and scan results.
- **Credential:** a deduplicated detected credential with its judgment and extraction state.
- **Occurrence path (locator):** a backend path identifying the exact immutable source version and file where a credential occurred, independently of historical inventory.
- **Evidence:** a retained source file associated with a credential occurrence.

## Maintaining invariants

Read [PROJECT_INVARIANTS.md](PROJECT_INVARIANTS.md) before changing project behavior or design. Keep it concise and up to date with user-confirmed rules.

Confirm proposed additions or changes to invariants with the user before recording them as agreed rules. An explicit decision already given by the user is confirmation; do not ask again. Do not infer intended invariants solely from existing code or stale documentation.

After confirmation, update the affected invariants and [visual guide](doc/end-to-end.html) in the same task. Record agreed but unimplemented changes in [TODO.md](TODO.md), and distinguish intended behavior from current implementation. Keep behavioral rules in the invariants file rather than duplicating them here.
