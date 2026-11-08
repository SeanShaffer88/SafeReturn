# Backup completion and Quick Check

Status: **Partially verified; pre-alpha.** This describes the checks implemented
in the engine, not proof that a Windows PC can be restored or booted.

## Before a new set is published

1. The engine enumerates all selected roots and checks their names before
   copying any chunks. A non-Unicode logical root or descendant, a literal
   backslash in a selected Unix filename or descendant name, another
   non-portable recorded name, or a common file/directory case collision is
   refused as `backup.unsupported_path`. No new chunks or set manifest are
   written by that refusal; existing backup data and the source are not
   changed by it. The error identifies the logical path using escaped debug
   notation where needed. Rename or move the affected
   item, or choose a different source, then retry.
2. The engine inspects selected source roots and their checked ancestors for
   symbolic links and Windows reparse points. Detected links there refuse the
   backup as `backup.unsafe_source`. Child links, reparse points, and other
   non-regular entries are not intentionally followed; they are recorded as
   skipped. Files and directories are inspected again before use. These checks
   are **not race-free**; their scope and the trusted snapshot anchor are
   described below.
3. The capture reads the source files and stores content-addressed encrypted
   chunks. New chunk records are written to unique temporary files, flushed,
   and renamed. Existing chunks are reused, not silently replaced.
4. The engine reads back every chunk reference, including deduplicated ones,
   and checks each assembled file's recorded size and SHA-256. A missing or
   damaged chunk, inconsistent file, unsafe recorded path, duplicate path, or
   common case/file-directory path collision fails the backup before its
   manifest is published. The failure identifies an affected chunk and/or
   file. On these later failures, already copied chunks may remain as
   unreferenced pool data; existing set manifests are not intentionally changed.
5. The new manifest is written to a unique temporary file, flushed, and read
   back against the serialized data before it is renamed into the sets folder.
   If it cannot be written or verified, the job fails instead of reporting a
   completed backup.

The verification phase reports progress in **chunk references processed**, not
unique chunks: the same stored chunk may be read more than once when several
files use it, while a reference already known to be unreadable is skipped.
File contents are streamed one chunk at a time, in addition to manifest and
per-chunk bookkeeping; the check adds read I/O to every backup. No performance
estimate has been verified.

A corrupt chunk is **not automatically repaired**. Retrying the backup on the
same volume can reuse it and fail again. Use another healthy volume or recover
the affected data from a separate verified copy; do not delete old backups
unless you have another usable copy.

## Source names and coverage limits

- For a selected file, its actual filename is stored under a root label. For
  a selected directory, descendant component names are stored beneath that
  label. The label is intentionally an ASCII slug of the logical root's final
  component, not the original full source path or necessarily the original
  root directory name. Empty directories are not stored. A directory root's
  own name can therefore be slugged even when it would not be a portable
  recorded filename. Root-label collisions are refused.
- Native paths are parsed with the host's separators; mapped snapshot roots
  use Windows-style `\` or `/` separators on any host. The snapshot device
  prefix is opaque and is not recorded in the manifest. Logical roots must be
  Unicode, but a device prefix need not be. Custom `CaptureSource`
  implementations accepting non-native logical syntax must implement
  `logical_root_name` faithfully; custom sources are trusted to resolve the
  intended data.
- For live sources the selected root and its native ancestors are inspected
  using non-following metadata; a detected link, junction, or other Windows
  reparse point refuses the job as `backup.unsafe_source`. Windows
  drive-relative paths are refused. During traversal, detected child links,
  reparse points, and non-regular objects are recorded as skipped rather than
  intentionally followed. This includes mount points and cloud placeholders
  represented as reparse points: their contents are **not** captured through
  those entries. Walked child names are checked even for skipped entries.
- `MappedSource` treats its supplied snapshot device root as a **trusted,
  opaque anchor**. It inspects descendants but does not inspect the anchor or
  its ancestors when opening a descendant; when the anchor itself is selected,
  it is inspected. This permits the VSS device namespace without claiming its
  virtual ancestors are ordinary directories. The caller must establish the
  anchor is the intended source. Custom sources may supply such an anchor and
  carry the same responsibility; without one, all native ancestors are checked.
  Resolved paths outside the anchor or containing `..` beneath it are refused.
- These are path-based, point-in-time checks, **not a race-free sandbox**.
  Files or directories can change between inspection and open, while being
  read, or during enumeration; the engine does not pin handles to each checked
  ancestor. A check that detects a replaced file or ancestor stops the job
  without publishing a set, although chunks copied earlier may remain. Avoid
  untrusted or changing source trees and verify coverage separately. A live
  source is not made into a consistent snapshot by these checks. Rechecking
  ancestor metadata adds I/O per directory and file; its performance has not
  been measured.
- A saved backup with any recorded skips finishes with
  `JobOutcome::Succeeded` and summary ID `result.backup_succeeded_with_skips`;
  it is not a statement of complete coverage. The ordinary CLI warns and
  prints each skipped path and reason. Both ordinary and JSON CLI backups exit
  **3** when a set was saved with skips, rather than exit 0; automation must
  treat 3 as a saved but incomplete set, not as proof that no set exists. Other
  errors can also occur after a set was saved. To include needed data, copy it
  to a regular source outside the link/reparse point, retry, and compare the
  result with the intended sources. `--json` and job events signal the distinct
  result but do **not** provide skipped paths, counts, or the new set ID. Core callers
  can inspect `BackupOutcome.manifest.skipped`. For a CLI JSON-only run, use
  `list-sets` to identify the set and inspect the `skipped` field of its
  plaintext `sets/<set_id>.json` manifest; `list-sets` does not flag skips and
  cannot reliably associate a set with a particular concurrent job. Existing
  clients that ignore the new summary ID can incorrectly show generic success.
  Empty directories and files that were never observed are not listed as skips.
- This policy is not retroactive: older backups may have followed selected
  roots, ancestors, or Windows reparse points, and their manifests do not prove
  whether intended data was omitted. Compare them to the original sources and
  make a new backup when possible.
- The engine does not currently enforce separation between the source tree and
  the backup-volume destination. Use a separate destination outside the source
  tree; otherwise writes to the backup volume can also change that tree.
- Name checks approximate common Windows case behavior; they cannot detect all
  filesystem-specific case, Unicode-normalization or short-name aliases, or
  prove that every accepted path will work on a particular target. Older sets
  may already contain filenames changed by the former lossy/normalizing capture;
  Quick Check cannot recover or verify the original names. Compare with the
  original sources and make a new backup where possible.

## Quick Check

Quick Check is read-only. It rejects unsafe set IDs, unsupported manifest
versions, a set ID that does not match the manifest, and overflowing recorded
totals. It names missing, malformed, or corrupt chunks and files with
unavailable chunks, wrong assembled size/hash, unsafe paths, duplicate paths,
or common case/file-directory path collisions. The report counts distinct
chunks, while progress counts references processed. Empty files are checked too.
The core report and ordinary CLI output include individual failures; the
current `--json` event stream reports job status and progress but does not
include the detailed Quick Check report.

A passing check means the data currently referenced by this manifest can be
read and matches its recorded file sizes and hashes. It does **not** prove:

- That the plaintext manifest is authentic, complete, or unchanged. An entry
  removed from the manifest, or a coordinated change to its chunk list and
  file hash, may go undetected. File names, sizes, and times are visible on
  the backup volume.
- That a live capture was point-in-time consistent, or that all intended
  files were captured. See the source-name, skipped-entry and link limitations
  above. VSS mapping is implemented, but real snapshot behavior still needs
  Windows runtime validation.
- That EFI, BCD, or WinRE are present, that boot registration works, or that
  the PC can boot. Those are separate, still-unverified recovery checks.
- That the backup will remain readable later or survive a sudden power loss.
  File contents are flushed before rename, but directory-entry durability and
  device caches have not been validated across filesystems or hardware.

The catalog remains a rebuildable cache. Its refresh after a successful backup
is **best effort** and is not currently a flushed-and-re-read completion gate;
Quick Check does not independently validate catalog consistency. This is an
open gap relative to the architecture plan's stronger completion requirement.

## Tests and remaining validation

Automated tests cover unsupported and Unicode names, logical versus mapped
roots, file and directory case aliases, failed publication, damaged chunks,
empty and multi-chunk files, inconsistent file assembly, malformed IDs,
manifest errors, progress, and CLI output. Unix tests exercise selected,
ancestor, dangling, cyclic and replaced links; a Windows-gated test exercises
synthetic junctions and mapped roots when run on Windows. A Windows cross-target
check compiles those tests but does not run them. These tests use synthetic files
and do not replace real Windows, live VSS, WinPE, power-loss, device, concurrency,
or accessibility testing.
