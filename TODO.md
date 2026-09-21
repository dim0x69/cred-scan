4. **P2 — Make interrupted workspace migration retryable.** A failure after backup creation but before inventory replacement currently makes the next attempt fail at exclusive backup creation. Reuse an existing backup only after verifying it matches the original inventory; preserve conflicting backups and fail clearly. Test interruption between backup and replacement and successful retry without losing history or evidence.

6. **P2 — State the first-occurrence preference in the judge prompt.** Explicitly instruct the judge to prefer the first occurrence's file while allowing additional occurrence reads. Ordered locations alone do not implement the agreed instruction. Test the prompt contract.

7. **KISS — Simplify mutable service interfaces and work selection.** Make scanner.scan() and Boundary._scan_target() return None instead of returning the same target they mutate; update callers and tests. Consolidate duplicated judgment/extraction eligibility checks so each operation selects work in one place and returns its count. Preserve extraction's retained-file checks even when no new extraction is pending. Return only bytes from _find_file_in_archive(), removing the metadata dictionary discarded by its caller.

8. Implement titus_scan_arguments
