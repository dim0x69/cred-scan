1. add --extract with max size
2. add 512 KB scan limit (global)
3. Whenever the tasks below change persisted workspace formats, migrate the user's one existing workspace as part of that task. Preserve accumulated results and evidence; use a migration tailored to the actual workspace rather than a general compatibility framework.
5. Latest-only inventory is implemented in schema 9. Migrate the existing workspace with the inventory 8 -> 9 tool once its location is available; the configured ./workspace directory is absent in this checkout.
6. Allow evidence extraction for both VALID and UNKNOWN judgments. Update extraction eligibility, extraction processing, tests, and documentation; current code permits only VALID. Preserve the saved judgment if extraction fails.
7. Instruct the judge to prefer reading the first occurrence's file, while allowing additional occurrence reads. Extraction independently reads and retains only the first occurrence's file. Update judge instructions, tests, and documentation.
10. Align configuration sources with the agreed separation: runtime settings from config.yml; API keys and other secrets from environment variables or .env. Current settings sources accept YAML secrets and environment-provided nonsecret settings; restrict those sources and update configuration tests and documentation.
