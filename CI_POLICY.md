# CI and merge policy

The default branch requires a pull request, its configured GitHub Actions checks, an up-to-date branch, and resolved conversations. These protections apply to administrators. No independent approving review is required for this solo-maintainer repository. Force pushes and branch deletion are blocked.

The primary CI workflow pins third-party actions to immutable commit IDs. Version comments identify the reviewed release line; they do not make the pin update automatically. When updating an action, verify the commit against the official upstream repository, inspect release notes and permissions, update its commit/comment together, and require the complete CI result before merging. Toolchain version selection inside an action remains a separate policy.

Job names are part of the merge contract. If a required job is renamed or its trigger changes, update branch protection deliberately so it neither blocks all PRs nor silently drops a gate. Do not skip or weaken a required test to obtain a green result. Compilation and CI are not substitutes for platform/runtime acceptance described in the project documentation.
