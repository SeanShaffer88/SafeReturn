# File restore and rehearsal safety

Status: **Partially verified; pre-alpha.** These checks reduce specific risks;
they are not a security boundary against a process that can modify the target
while SafeReturn is working. Do not ship restore functionality as production
ready until the VM and sacrificial-disk gates in the architecture plan pass.

## What the engine checks

- Set IDs used to find or write manifests are restricted to the letters,
  digits, hyphens and underscores produced by the engine; reserved Windows
  device names are rejected. Reading a set also checks the format version,
  identity and recorded total size. A manifest whose internal ID differs from
  its filename is not used to rewrite another manifest.
- Before file restore, File Rehearsal or system-restore planning, **all** file
  paths are checked, even when a single file was selected. Paths must be
  slash-separated relative paths. Absolute paths, `.`/`..`, empty components,
  backslashes, colons (including Windows alternate streams), forbidden/control
  characters, trailing spaces or dots, and Windows device names are rejected.
  Exact duplicates, common case-insensitive collisions, and file-versus-parent
  conflicts are rejected too. Quick Check reports these as `unsafe_path`,
  `duplicate_path`, or `conflicting_path`; backup finalization refuses to
  publish a newly captured set with these problems. Some filenames valid on
  non-Windows filesystems are therefore not accepted as portable backups.
- The built-in directory-backed system-restore simulator also validates each
  partition-relative path from its plan before creating partition directories.
  A caller of the lower-level `restore_entries` API still supplies its own
  explicit destinations; that API does not enforce a common base folder.
- Planning and restore inspect existing destination components using
  `symlink_metadata`, and reject symbolic links, Windows reparse points and
  incompatible filesystem objects rather than intentionally following them.
  This applies to the selected destination's existing ancestors as well as
  the file itself, so a destination under a junction or symlink must be moved
  to a regular directory. These checks are point-in-time checks, **not**
  handle-relative or race-free containment.
- A file-restore plan retains each destination's SHA-256 or its absence, not
  just the displayed absent/identical/different category. Before the job
  starts, any content or presence change consumes the token and returns
  `restore.plan_stale` without restore writes. Each destination is checked
  again during the job and immediately before publication; a later change
  stops the job with `restore.target_changed`. Earlier files may already have
  been restored. The comparison does not establish file identity or detect
  changes that leave the same bytes.
- Files are rebuilt one decoded chunk at a time into random, exclusively
  created staging files. Size and SHA-256 are checked, the staging file is
  flushed and read back, and errors attempt to remove the temporary file. The
  engine does not reserve memory based on a manifest's claimed file size.
  A new destination is published using a hard link that fails if that name
  already exists; approved replacements use rename after the final check.
  Simulation artifacts and first-time Boot Rehearsal records also use unique,
  no-clobber staging. A simulation or new rehearsal refuses existing log,
  script or report names instead of silently replacing them: pick a fresh
  staging directory for another run. An explicit VM-outcome record update
  replaces the existing rehearsal record.

## Important limits and recovery

- **Concurrent changes remain a risk.** A symlink, junction, directory or
  existing file can be replaced between inspection and use. Approved
  overwrites use a rename that can replace a different file that appears
  after the last check. The checks do not pin directory handles or provide
  race-free containment. Use a private destination and stop other programs
  from modifying it; do not restore into an attacker-controlled tree.
- The case comparison is an approximation, not the Windows filesystem's
  complete case mapping, short-name (8.3) resolution, or every filesystem's
  aliasing/normalization rules. A successful check does not prove that all
  possible names are distinct. The filesystem and platform must be validated
  before relying on a restore.
- No-clobber publication requires hard-link support. Some filesystems,
  including FAT32, do not support it, so a restore or rehearsal there can
  fail rather than fall back to a clobbering write. Choose a suitable local
  filesystem and check permissions. The format of the underlying filesystem
  is not independently verified by these checks.
- Restores are **not transactions** across multiple files. An error can leave
  earlier files restored, new directories, and, if cleanup fails or the
  process stops, plaintext staging files. Review the destination and job
  report before retrying; preserve another backup of existing data. Flushing
  files does not establish directory-entry or power-loss durability.
- The manifest is plaintext and not authenticated. Path and consistency
  checks cannot establish that it is complete or that a coordinated change
  to a chunk list and file hash is genuine. Capture also normalizes backslashes
  and uses lossy conversion for non-Unicode names; on non-Windows sources it
  can record some original names differently. A passing Quick Check is not a
  guarantee that source names, the target, operating system, or boot
  environment can be restored successfully.
- The original unencrypted `plain::ChunkStore` is a prototype, not covered by
  these production-store safeguards. Custom system-restore executors must
  enforce their own destination safety. The built-in live disk executor is
  still a non-erasing skeleton; neither VM boot nor physical-disk recovery is
  established by directory-backed simulation.

Automated tests use synthetic files and cover traversal, Windows-style path
syntax, collisions, existing links, plan drift, partial jobs, staging-name
collisions, and simulation artifacts. Windows code is compiled in the
cross-target gate; only a Windows runtime test can exercise Windows reparse
point behavior. No stress test proves safety against concurrent attackers.
