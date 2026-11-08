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
2. The capture reads the source files and stores content-addressed encrypted
   chunks. New chunk records are written to unique temporary files, flushed,
   and renamed. Existing chunks are reused, not silently replaced.
3. The engine reads back every chunk reference, including deduplicated ones,
   and checks each assembled file's recorded size and SHA-256. A missing or
   damaged chunk, inconsistent file, unsafe recorded path, duplicate path, or
   common case/file-directory path collision fails the backup before its
   manifest is published. The failure identifies an affected chunk and/or
   file. On these later failures, already copied chunks may remain as
   unreferenced pool data; existing set manifests are not intentionally changed.
4. The new manifest is written to a unique temporary file, flushed, and read
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
- Walked child names are checked even for skipped entries. Child entries
  detected by `is_symlink` are recorded as skipped and not intentionally
  traversed; the ordinary CLI prints the skipped list. **This is not a complete
  link or reparse-point fence:** selected root links and ancestor links can be
  followed, and Windows junctions/other reparse points may be followed. Live
  source paths can also change between inspection and use. Avoid untrusted or
  changing source trees and inspect links/reparse points before backup. The
  current job-event/`--json` stream does not carry the skipped-entry list.
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
manifest errors, progress, and CLI output. Platform-gated tests cover raw Unix
names and Windows unpaired-surrogate roots when run on those platforms. They
use synthetic files and do not replace real Windows, VSS, WinPE, power-loss,
device, or accessibility testing.
