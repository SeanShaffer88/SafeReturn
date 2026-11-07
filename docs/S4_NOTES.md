# S4 notes — WinPE recovery-media builder (2026-10-20)

S4 adds the recovery-media builder to `safereturn-core` plus CLI
commands. It follows the plan doc §4.4: WinPE from the Windows ADK
(`copype` → DISM servicing → `MakeWinPEMedia /UFD /bootex`), a
two-partition USB (FAT32 boot + NTFS data), host drivers injected,
and the boot-test marker that turns "we built it" into "it booted,
on this date" — or honestly says NOT TESTED YET.

**Status: planning, contract, verify, and marker code is tested with
synthetic data. Actual media creation is disabled.** The Windows
executor refuses before any command or write, even with
`SR_MEDIA_LIVE=1`. Its drive selector is not bound to the planned
physical target or protected-disk checks; an opt-in flag or a matching
plan token is not a safety proof. No media has been built by this code.
CI must never build media. See the prerequisites and UNVERIFIED list
below.

## What was built

| Piece | Where |
|---|---|
| Pure media plan (facts → layout, steps, warnings, typed refusals) | `core/src/media.rs`, tests `media_plan.rs` (10) |
| Contract: `PlanMedia` / `CreateMedia` / `MediaPlanned` + 3 goldens | `contract`, `docs/SHELL_CONTRACT.md` §5 S4 note |
| Engine create flow: random single-use token, drift re-check, executor trait | `core/src/engine.rs`, `core/src/media_exec.rs`, tests `media_engine.rs` (8) |
| Media manifest `safereturn-media.json` (write/read) | `core/src/media.rs` |
| Verify + boot-test marker protocol (host read + PE-side writer) | `core/src/media_verify.rs`, tests `media_verify.rs` (10) |
| CLI `media plan/create/verify` | `safereturn-cli`, smoke tests (3) |
| Non-destructive Windows executor refusal test | `core/tests/media_live.rs`; cross-platform fence test in `media_exec.rs` |

## The plan (slice 1)

`compute_media_plan(facts, options)` is pure: the shell supplies
**facts** (target size/removable/serial suffix — last 4 characters
only, the full serial is never collected; WinPE source present +
`winpe.wim` size + ADK version as supplied; driver `.inf` list;
payload entries with size + SHA-256), and the plan computes
everything else. Refusals are typed errors with fix paths:
`media.target_too_small` (< 8 GiB), `media.payload_too_large`
(doesn't fit the FAT32 ceiling or leaves no room for data),
`media.target_not_removable`, `media.winpe_source_missing`,
`media.invalid_facts`. A non-removable target is refused unless the
caller sets an explicit override — and then the plan carries a
permanent warning (`media.target_not_removable_override`) that is
recorded in the media manifest.

### Layout math

```text
content          = winpe.wim bytes + payload bytes
margin           = ceil(content / 4)        (25%, see below)
boot partition   = align_up(max(content + margin, 512 MiB), 1 MiB), capped at 32 GiB
data partition   = target − 1 MiB (initial offset) − boot partition, min 512 MiB
```

Sources for the constants: 8 GiB minimum and the 32 GiB FAT32
partition ceiling are the MakeWinPEMedia two-partition practice in
Microsoft Learn's "WinPE: Create USB bootable drive" (the doc also
warns drives larger than 32 GB waste the remainder — our NTFS
partition is sized to use it as backup-data space instead, which is
the plan §4.4 design, recorded as ours); 512 MiB floors and the
1 MiB alignment are standard partition practice. The 25% margin is
**a stated planning allowance, not a measurement**: serviced WinPE
images grow (optional components, drivers, payload staged in the
image), and the plan would rather refuse early than fail at
MakeWinPEMedia. It is one named constant; the on-machine session
should replace it with a measured value.

## Build steps and optional components

Plan step order: `copype amd64` → DISM mount → one AddPackage per
optional component **in dependency order** → AddDriver per host
driver → payload copies → DISM unmount `/Commit` → `MakeWinPEMedia
/UFD` with `/bootex` (UEFI CA 2023-signed boot files; requires ADK
≥ 10.1.26100.2454 per the plan doc's Learn citations).

Components, each justified by what the PE shell/engine needs (the
same text lives in `media.rs`):

- **WinPE-WMI** — disk/volume facts and storage queries in PE.
- **WinPE-NetFX** — no SafeReturn code is .NET; it is a documented
  prerequisite of WinPE-PowerShell.
- **WinPE-Scripting** — WSH; likewise a PowerShell prerequisite.
- **WinPE-PowerShell** — the operator/diagnostic shell and the
  sequencing of documented Windows tools (`bcdboot`, `reagentc`,
  diskpart scripts) during bare-metal restore (S5).
- **WinPE-StorageWMI** — storage-management WMI providers the
  restore-target picker and SafeTarget checks use.
- **WinPE-SecureStartup** — BitLocker/TPM support in WinPE, so a
  protected volume stays inspectable/unlockable with the user's
  recovery key instead of being an opaque wall.

Payload is staged **both** into the mounted image (so the recovery
shell runs from the WinPE RAM disk even if the stick is pulled
mid-restore) and at the media root under `safereturn/` (so the
manifest can list it and the host-side verify can check it).

## Execution model (slice 2)

The engine issues a random plan token; `create_media` consumes it on
any attempt and compares **caller-supplied** disk ID, model, size,
removable flag, and serial suffix with the planned facts. Drift is
refused as `media.plan_stale` before the executor is called. Matching
facts do not prove physical identity or detect all device swaps.

Execution goes through `MediaExecutor`:

- `UnsupportedExecutor` (non-Windows) returns `core.unsupported_platform`.
- `WindowsAdkExecutor` always returns `media.executor_not_ready` before
  preparing files or running any command. The retained ADK/DISM steps
  are not executed; `SR_MEDIA_LIVE=1` cannot override the fence.
- Caller-supplied test executors are a seam for simulation; the built-in
  fence does not make arbitrary custom executors safe.

The CLI's deterministic plan id binds the stated plan facts, **not**
`--target-spec` to a physical device. `media plan` and its JSON event
warn that built-in creation is unavailable; `media create` cannot erase
a device through the built-in executor. Planning and `media verify`
remain available and do not establish bootability.

## Manifest, verify, and the boot-test marker (slice 3)

Finished media carries `safereturn-media.json` (format v1): plan id,
creation time, core version, the warnings shown at create time (so a
non-removable override can never be hidden after the fact), the
layout, and every payload entry with its SHA-256.

`verify_media` reports facts, no score:

- every payload entry re-hashed and size-checked — a bad file is
  **named**, with what is wrong (missing / size differs / content
  differs);
- boot files present (`EFI/Boot/bootx64.efi`, `sources/boot.wim`,
  checked case-insensitively — FAT32 semantics);
- the boot-test state, below. `passed()` means payload + boot files
  only — deliberately: intact media is not thereby boot-tested.

**Marker protocol.** Fresh media has no marker and reports
`NotTested` — shown by every surface as NOT TESTED YET. On first
boot, the PE side calls `record_boot_test` (in core — one
implementation for both sides) to write `safereturn-boottest.json`
to the NTFS partition root: format version, the media's plan id,
boot timestamp, firmware type if WinPE could determine it (else
`null` — unknown recorded as unknown), and whether the recovery
shell was reached. The host counts media as boot-tested **only**
when a marker parses, matches the schema, names *this* media's plan
id, and says the shell was reached. A marker that fails any check
is `Invalid` with the reason; a boot that stopped before the shell
is its own state (`BootStartedShellNotReached`), not a pass and not
a silent nothing.

## Named open items (not guessed)

- **Target identity and protected disks:** independently resolve the
  Windows erase target to the physical disk, bind it to the confirmed
  preview, and refuse source, backup, system, recovery-media, missing,
  ambiguous, and changed identities as appropriate. Account for removal,
  remapping, and replacement throughout the potentially long ADK build,
  especially immediately before an erase. Full serials or other stable
  identifiers may be needed internally; a four-character suffix alone
  is not unique. The current CLI supplies facts and `--target-spec`
  independently and cannot provide this guarantee.
- **Independent safety validation:** review the Windows implementation
  and race handling, test with synthetic identities and failure injection,
  then validate only in a disposable VM/device session with explicit
  approval. Do not restore a live test merely by setting an environment
  variable.
- **OC cab file names / localized cab layout** in the installed ADK
  (`WinPE_OCs\<Name>.cab`, `WinPE_OCs\en-us\<Name>_en-us.cab`) are
  the documented layout as recorded in the plan doc's research; the
  executor applies the language cab only when it exists. Verify
  against the real ADK in the on-machine session.
- **MakeWinPEMedia /UFD invocation details** — the `/bootex` switch
  and the two-partition result are per Microsoft Learn as cited in
  the plan doc; whether the executor's `cmd /C` invocation matches
  the ADK's expectation (the tools are normally run from the
  *Deployment and Imaging Tools Environment*) is unverified — the
  executor invokes the tools by full path under the ADK root for
  exactly this reason, but the environment question stays open.
- Whether `MakeWinPEMedia /UFD`'s own partitioning matches our
  computed layout byte-for-byte, or the build must pre-partition.
  The plan computes the layout for the *preview* and the manifest;
  if the tool's layout differs, the manifest records the plan's
  numbers and verify would need the actuals — resolve on-machine.
- ADK version detection: the plan records the version **as
  supplied**; nothing reads the installed ADK's version yet.

## UNVERIFIED — the on-machine media session must check

Everything about real execution. Nothing below has run:

1. ADK presence/version on the target machine (≥ 10.1.26100.2454
   for `/bootex`); `copype` output layout matches the executor's
   assumed `media\sources\boot.wim` + `mount` paths.
2. DISM mount, OC `/Add-Package` (cab names, en-US layout, package
   order), `/Add-Driver`, unmount/commit against the real image.
3. `MakeWinPEMedia /UFD /bootex` against a real USB device:
   resulting partition layout (FAT32 boot + NTFS remainder?) and
   sizes vs the plan's computed layout.
4. The media **boots** on a representative PC — Secure Boot on,
   UEFI CA 2023 path — and the injected host storage/network
   drivers work in WinPE.
5. The PE shell (when it exists, S6) writes the boot-test marker;
   host `media verify` then reports the boot-test date. Also the
   marker write on FAT32/exFAT-mounted data partitions.
6. Failure behavior: nearly-full target, non-admin run, ADK
   partially installed, USB removed mid-build.
7. Only after the safety prerequisites above are implemented and
   reviewed, design and explicitly approve a disposable-device live
   test. `media_live.rs` is currently a non-destructive refusal test;
   setting `SR_MEDIA_LIVE=1` cannot enable a media build.

The S0.5 VSS list in `docs/S3_NOTES.md` is unchanged and still open.
