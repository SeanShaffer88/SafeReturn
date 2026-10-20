# S3 Notes — capture layer: snapshot sources, VSS session, system facts

**Date:** 2026-10-20 · **Slices:** 1 `c127e206` (capture sources), 2 `baf0ed5a` (VSS session + engine glue), 3 `4fbada2a` (system facts), 4 `030b6ac1` (CLI), 5 = this doc.
**Status of the whole repo:** pre-alpha. Everything below is implemented and tested on synthetic data and temp trees. **No snapshot has ever been taken by this code** — VSS runtime behavior remains UNVERIFIED (see the list at the end); that is precisely what the S0.5 on-machine session must now prove, and S3 was designed so that session is a small gate, not a rewrite.

---

## What was built

### Capture sources (`safereturn-core/src/capture.rs`)

The set walk no longer reads the filesystem directly. It consumes a `CaptureSource`: given a *logical* root the caller asked for (`C:\Users\Sam`), it resolves the path the walk should actually open, and it states the capture mode the manifest must record.

- **`LiveSource`** — the pre-S3 behavior, identity resolution. It is the default everywhere (`backup_tree` and `Engine::start_backup` delegate through it), and the existing test suite passes untouched.
- **`MappedSource`** — prefix mapping for snapshot capture: logical roots on one volume are opened under a different root (on Windows, the snapshot device object). The mapping reuses the S0 spike's proven rule (`snapshot_path()`): strip the volume prefix, join the remainder. Roots outside the volume — and roots that would escape it via `..` — are refused with a named error (`CaptureRootOutsideVolume`) during enumeration, i.e. before any set exists.
- **The invariant:** manifests record *logical* paths only. A snapshot device path (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`) is an artifact of one capture session; if it ever appeared in a manifest, restores would depend on a device object that no longer exists. A test serializes a snapshot-captured manifest and asserts the device root string appears nowhere in it.

Manifest change: every set now records **`capture_mode`** — `live` or `vss_snapshot`. The field has a serde default of `live`, so pre-S3 manifests parse truthfully (they were all live captures). Display names for roots are now derived from the logical root string (splitting on both separators), so a Windows-style logical root names its files identically on any host OS.

Tests (6, `tests/capture.rs`): mapped vs live backup of the same content produces identical file facts (paths/sizes/hashes/chunk lists) with only the capture mode differing; file-root mapping matches too; foreign/escaping/drive-relative roots are refused and save nothing; pre-S3 manifests read back as `live`; the engine's `start_backup_with_source` emits the standard job events and stores `vss_snapshot`.

### VSS session (`safereturn-vss/src/session.rs`)

`SnapshotSession` is the engine-facing handle for one snapshot of one volume:

- `begin(volume)` drives the existing Rust state machine alongside the C++ helper (`win::snapshot_volume`, dynamically loaded — still no link dependency). The helper performs the pre-snapshot sequence as one call; the machine is then driven through the same steps so its enforced order and call log describe the session. Divergence between the two is reported as an internal `Sequence` error, after tearing the helper session down as an abort.
- `device_root()` exposes the snapshot device object for `MappedSource`.
- `finish()` = BackupComplete → DeleteSnapshots → Release; `abort()` = AbortBackup → DeleteSnapshots → Release. The helper handle is consumed exactly once (tracked by an explicit flag — double-destroy would be a double free in C++).
- **Drop without finish/abort aborts** (best-effort). A leftover snapshot pins copy-on-write disk space indefinitely, and "completing" an abandoned session would tell writers a backup succeeded that nobody captured. Abort is the only honest default; callers should still finish/abort explicitly because Drop cannot report errors.
- **Off Windows**, `begin` returns the typed `SnapshotError::UnsupportedPlatform` ("snapshots require Windows… Nothing was captured."), tested on Linux. The type exists on every platform so the CLI and engine compile everywhere with one code path.

The engine glue is one method: `Engine::start_backup_with_source(label, roots, &dyn CaptureSource, sink)` — same job events as a live backup. The snapshot's life cycle belongs to the caller (the engine only reads while the session is alive); core does not depend on the VSS crate.

The one runtime exercise is a test that cannot run by accident: `tests/live_snapshot.rs` is `#[ignore]`d **and** requires `SR_VSS_LIVE=1`. CI never runs it. It encodes the S0.5 assertions (device root is a GLOBALROOT device object; finish completes) so the on-machine check cannot drift from the code.

### System facts (`safereturn-core/src/system.rs`, manifest `system` section)

A system set's manifest can now carry a `system` section (`SystemFacts`): boot mode (UEFI/BIOS), Secure Boot state, BitLocker state per volume, the EFI System Partition's file list (paths + sizes + SHA-256), WinRE presence/location, and whether the BCD store was captured into the set (and where — or why not).

The schema enforces the honesty rules structurally:

- Every fact is a `Fact<T>`: a value, a **source**, and — iff the value could not be determined — an **unknown_reason**. `SystemFacts::validate()` rejects a sourceless fact, an unknown without a reason, a value that also carries a reason, an ambiguous BCD capture, and an unknown format version. Facts are attached with `attach_system_facts`, which validates first and **refuses to replace** facts a set already carries.
- Facts that cannot be determined are recorded as unknown *with the reason* — never guessed, never silently omitted.
- `list_esp_files` is real, platform-independent work: walk a mounted ESP root, hash every regular file. `esp_fact` wraps it so an unlistable root becomes an explicit unknown instead of aborting a backup.
- Gatherers implement `SystemFactsGatherer`. `StaticFactsGatherer` returns facts produced elsewhere (validated). `UnavailableGatherer` produces the all-unknown record with one stated reason — what a platform without a gatherer attaches, so "we could not gather here" is itself recorded.
- The **Windows gatherer is a skeleton** (`#[cfg(windows)]`): it determines only what is determinable by construction from the code — firmware type via the documented `GetFirmwareType` API (Kernel32/winbase.h), and WinRE presence *at its default location* (absence there is reported unknown, not "absent", because WinRE can live on a recovery partition). Secure Boot, BitLocker, BCD export, and ESP-root discovery are returned as unknowns whose reasons name the exact runtime check that remains (`reagentc /info`, `manage-bde -status`, registry mirror, `bcdedit /export`). Parsing any of those is runtime work and is marked UNVERIFIED rather than faked. A cfg(windows) test pins the one invariant available pre-runtime: whatever the skeleton produces must satisfy the validation schema.

The section is omitted entirely (`skip_serializing_if`) on plain file sets and pre-S3 manifests, so nothing about existing sets changed shape.

### CLI (`backup --snapshot`, `--system-facts`)

- `backup --snapshot C:\` (Windows, elevated): begins a `SnapshotSession`, captures the listed roots (which must be on that volume) through a `MappedSource` over the device root, and finishes the session on success / aborts it on backup failure. If the backup succeeded but snapshot cleanup failed, the CLI says the set **was** saved, warns that a shadow copy may remain, and exits non-zero — the failure is never hidden inside a success message.
- **No silent fallback, ever:** if the snapshot cannot be taken, the backup stops, *nothing is written*, and the error explains the three ways forward. Only an explicit `--allow-live` substitutes a live capture — with repeated WARNING lines, and the set recorded (truthfully) as `live`. The backup summary now always prints the capture mode, so the distinction is visible in every run and in `--json` flows via the manifest.
- `backup --system-facts <FILE>` attaches a gatherer's facts JSON to the new set (validated; a damaged file is a named error and attaches nothing). `--esp-root <DIR>` replaces the facts' ESP entry with a fresh listing of that root, announced on stderr.

Tests (CLI smoke, +2): facts attach end-to-end incl. the `--esp-root` override and damaged-file refusal; off-Windows, `--snapshot` fails with nothing written (`list-sets` proves no set appeared), and `--allow-live` produces a warned, live-labelled set. The off-Windows snapshot test is `cfg(not(windows))` by construction — CI on Windows never attempts a real snapshot.

### Contract / format changes (complete list)

- **Wire contract (`safereturn-contract`): unchanged.** No new message shapes; capture options are engine/CLI-level in S3. Shell exposure of snapshot backup belongs in the backup-plan flow and lands with the desktop shell slice under the same golden-fixture rules (noted in SHELL_CONTRACT.md §5, S3 update).
- **Set manifest (core-internal format):** added `capture_mode` (defaulted — old manifests parse) and optional `system` (omitted when absent — old manifests and plain file sets are byte-shaped as before).
- **No new dependencies.** Cargo.lock changed only for the CLI → safereturn-vss path dependency.

## UNVERIFIED — what the S0.5 on-machine session must still prove

Everything in this section is stated plainly because none of it has been observed working:

1. **The probe**: run the `safereturn-vss` binary elevated on a real Windows machine/VM — create + initialize + gather writer metadata with no snapshot (S0_FINDINGS §1 item 2). The helper compiled in CI (S0.5 addendum) but has never executed.
2. **A real snapshot round-trip**: `SR_VSS_LIVE=1 cargo test -p safereturn-vss --test live_snapshot -- --ignored`, elevated: `begin("C:\\")` creates a snapshot whose device root is a GLOBALROOT device object, and `finish()` deletes it. Afterwards `vssadmin list shadows` must show **no leftover shadow** (drop/abort paths included — kill a capture mid-run and check again).
3. **A locked-file read through the mapping**: open a file that is locked on the live volume (e.g. a database in use) via the snapshot device path — the S0 promise the whole mapping exists for (S0_FINDINGS §1 item 3).
4. **An end-to-end snapshot backup**: `safereturn backup <volume> <label> C:\... --snapshot C:\` on a real machine; confirm the set verifies (L1) and restores, and that the manifest says `vss_snapshot` and contains no device path.
5. **Per-writer status** (helper TODO from S0): writer failures during GatherWriterMetadata/PrepareForBackup are not yet surfaced per writer; the product's pre-flight writer check depends on it. Still S0.5 work — deliberately not touched here.
6. **Windows gatherer runtime facts**: `GetFirmwareType` result on real firmware, WinRE default-location check accuracy, and the four reasoned unknowns (Secure Boot, BitLocker, BCD export, ESP root discovery) each need their runtime implementation + verification before any of them may be reported as known.
7. **Failure behavior on a real volume**: snapshot of a nearly-full or BitLocker-protected volume, VSS service stopped, non-elevated run — each must produce the named error and write nothing. Only the non-Windows branch of this matrix is tested today.

Also not done (by design, later slices): full system-volume capture orchestration (ESP/Recovery partitions as captured objects — S3 provides their facts + the source plumbing; partition capture/restore is S4/S5), bare-metal restore (S5), WinPE media (S4), per-writer status in the UI.
