# Backup completion and Quick Check

Status: **Partially verified; pre-alpha.** This describes the checks implemented
in the engine, not proof that a Windows PC can be restored or booted.

## Before a new set is published

1. The capture reads the source files and stores content-addressed encrypted
   chunks. New chunk records are written to unique temporary files, flushed,
   and renamed. Existing chunks are reused, not silently replaced.
2. The engine reads back every chunk reference, including deduplicated ones,
   and checks each assembled file's recorded size and SHA-256. A missing or
   damaged chunk, inconsistent file, unsafe recorded path, duplicate path, or
   common case/file-directory path collision fails the backup before its
   manifest is published. The failure identifies an affected chunk and/or
   file. Chunks already copied may remain as unreferenced pool data; the
   source files and previous set manifests are not changed.
3. The new manifest is written to a unique temporary file, flushed, and read
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
- That a live capture was point-in-time consistent; use a VSS snapshot where
  available. Skipped entries are recorded separately in the manifest and
  reported by the backup command. Capture currently normalizes backslashes
  and uses lossy conversion for non-Unicode names; on non-Windows sources,
  some original filenames can therefore be recorded under a different name.
  Do not rely on such names until capture preserves or explicitly rejects them.
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

Automated tests cover damaged reused and newly written chunks, failed manifest
publication, empty and multi-chunk files, reordered/removed chunk references,
size and hash mismatches, duplicate paths, malformed IDs, oversized chunk
headers, manifest version/identity/overflow errors, progress, and CLI output.
They use synthetic files and do not replace real Windows, VSS, WinPE,
power-loss, device, or accessibility testing.
