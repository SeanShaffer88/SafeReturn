# S5 notes — bare-metal (whole-PC) restore (2026-10-20)

S5 builds everything about a whole-PC restore that can be built and
verified *without* a machine: given a system backup set (S3 format,
with a system-facts section) and the facts of a blank or replaceable
target disk, produce the complete restore as inspectable data —
GPT layout, per-partition file application, and the post-apply boot
steps — refuse what cannot boot, disclose what is missing, execute
the whole flow against a directory-backed fake disk on any OS, and
verify an applied tree without ever claiming more than file
inspection proves. Execution against a real disk stays gated
exactly like S4's media execution, and the Windows executor is a
skeleton that renders its artifacts and refuses to run them.

Nothing in S5 has touched a real disk. The UNVERIFIED list at the
end is the agenda for the on-machine restore session.

## What was built

- **Slice 1 — the planner** (`core/src/system_restore.rs`): pure,
  cross-platform. Inputs: a set manifest, target-disk facts (size,
  model, serial suffix — last 4 only, removable), the target
  machine's firmware mode as a sourced `Fact<BootMode>`, and an
  explicit root mapping (which recorded set root is the OS volume,
  which is the ESP capture — the planner never guesses). Output: a
  `SystemRestorePlan` with a deterministic plan id (same scheme as
  S4's MediaPlan), the partition layout, every file application,
  the post-apply steps as data, and the plan's warnings.
- **Slice 2 — contract + engine + executors**: `PlanSystemRestore`
  / `StartSystemRestore` / `SystemRestorePlanned` in
  `safereturn-contract` (16 golden fixtures; SHELL_CONTRACT §5 S5
  note; `erase_warning_id` = `system_restore.will_erase_target`,
  always present), the engine's third plan-token namespace (same
  discipline as restore/media: single-use, consumed on any attempt,
  target drift — size, removable, serial suffix, firmware mode —
  refuses with `system_restore.plan_stale` before the executor is
  ever called), a **simulation executor**, a **Windows executor
  skeleton**, and the pure generators for the diskpart script and
  the boot command lines.
- **Slice 3 — verification** (`core/src/system_restore_verify.rs`):
  `verify_system_restore(plan, applied_root)` — see "Verification
  semantics" below.
- **Slice 4 — CLI**: `restore-system plan|execute|verify`,
  stateless like the media group (the deterministic plan id is the
  token; execute recomputes and matches before doing anything).
  `--simulate <DIR>` is the documented test path; `verify` works
  from a plan file saved by `plan --plan-out`.
- **Slice 5 — these notes** + README status.

No new dependencies.

## Layout: every size computed, every default sourced

GPT, UEFI only, partitions in on-disk order:

| # | Partition | Size | Source of the size |
|---|---|---|---|
| 1 | ESP (FAT32, label "System", letter S) | 300 MiB default; grows to recorded ESP contents + 32 MiB headroom when those exceed it | Default: Microsoft Learn, *UEFI/GPT-based hard drive partitions* — the ESP minimum is 200 MB on 512-byte-sector drives and 300 MB on 4K-native drives; the default covers both. The 32 MiB growth headroom is a stated planning allowance (room for the BCD store bcdboot writes), not a measurement. |
| 2 | MSR (unformatted, no letter) | 16 MiB | Same Learn document: "The size of the MSR is 16 MB." (An older Learn revision said 128 MB; the current Windows 11 document says 16 MB, and Windows 10/11 installs use 16 MB — the current document wins.) |
| 3 | Windows (NTFS, label "Windows", letter W) | The remainder of the disk | Holds the set's OS data plus free-space headroom of max(10% of that data, 512 MiB) — a stated planning allowance for the page file and first updates, not a measurement. |
| 4 | Windows RE tools (NTFS, label "Windows RE tools", letter R) — only when WinRE is placed | max(300 MiB, Winre.wim + 200 MiB) | Microsoft Learn / KB 3135522: the partition "must be at least 300 megabytes" and, for Windows 10 version 2004 and later, "must have at least 200 MB of free space". Type id `de94bba4-06d1-4d40-a16a-bfd50179d6ac` and GPT attributes `0x8000000000000001` are the documented values (same sources + the Learn DiskPart sample). |

Plus a 1 MiB front reserve (GPT structures, 1 MiB-aligned layout)
and a 1 MiB end reserve (backup GPT). **Required minimum target** =
front + ESP + MSR + WinRE + OS data + headroom + end; a smaller
target refuses with `system_restore.target_too_small` carrying both
numbers. A target *larger* than the source is the normal case: the
Windows partition absorbs the difference.

Each partition's `size_source` travels inside the plan itself, so a
user (or a test, or the S6 shell) can interrogate any number.

## File application

Set files are classified by their recorded root: ESP-root files →
the ESP at their in-ESP paths; OS-root files → the Windows
partition at their in-volume paths. WinRE placement: the set's
`Winre.wim` (found at the staged location
`Windows\System32\Recovery\Winre.wim`, or any
`Recovery\WindowsRE\Winre.wim` under the OS root) is *also* applied
to the recovery partition at `Recovery\WindowsRE\Winre.wim`.
Files under any *other* recorded root refuse the plan
(`system_restore.invalid_facts`) — a bare-metal restore never
silently drops backed-up content; the error tells the user to
restore that root separately.

## Post-apply steps as data

1. `bcdboot W:\Windows /s S: /f UEFI` — Microsoft Learn, *BCDBoot
   Command-Line Options*: `/f` requires `/s`; with `/s`, bcdboot
   does **not** create a firmware NVRAM entry and relies on the
   firmware's default path (`\EFI\Boot\bootx64.efi`, which the ESP
   application places) — the plan requires that fallback file in
   the set for exactly this reason.
2. `reagentc /setreimage /path R:\Recovery\WindowsRE /target W:\Windows`
   then `reagentc /enable` — Microsoft Learn, *REAgentC
   command-line options*: `/setreimage` sets the WinRE image
   location; `/target` is the documented offline form used from
   WinPE. (Only when WinRE is placed.)
3. Notices (not commands): the BitLocker notice and the Secure
   Boot note below.

The generators (`diskpart_script`, `post_step_commands`) are pure
functions, unit-tested byte-for-byte / argv-for-argv against the
documented forms — a wrong script is the scariest failure mode in
this feature, so it is treated as code. The diskpart script
follows the Learn sample structure (`select disk`, `clean`,
`convert gpt`, `create partition efi/msr/primary` with explicit
MiB sizes, formats, letters S/W/R, `set id` + `gpt attributes` on
the recovery partition, `list volume`, `exit`). Plan sizes are
1 MiB-aligned except the Windows partition on a target whose size
is not a whole MiB; there the script floors to whole MiB and the
sub-MiB remainder stays unallocated (the end reserve already
accounts for the backup GPT).

## Refusals (named, at plan time — before anything is erased)

- `system_restore.not_a_system_set` — the set has no system-facts
  section. A file backup restores files; it cannot rebuild a PC.
- `system_restore.firmware_unsupported` — the source PC booted
  BIOS. S5 builds UEFI/GPT only; BIOS/MBR restore is a later
  phase, not a silent conversion.
- `system_restore.firmware_unknown` — source *or* target firmware
  mode is an unknown fact. A boot plan is never built on a guess.
- `system_restore.firmware_mismatch` — source UEFI vs target BIOS
  (or the reverse, should a future build plan BIOS). Never crossed
  silently.
- `system_restore.boot_files_missing` — the set's ESP content is
  empty, or lacks `EFI/Microsoft/Boot/bootmgfw.efi` or
  `EFI/Boot/bootx64.efi`. (bcdboot regenerates boot-environment
  files from the Windows partition, but a capture with neither
  boot manager is not a usable system backup; the plan refuses
  rather than hoping.)
- `system_restore.target_too_small` — computed above.
- `system_restore.invalid_facts` — malformed serial suffix, empty
  disk id, named roots absent from the set or identical, a set
  file under no recorded root, or the unmapped-extra-root case.

Disclosed gaps that do **not** block (they ride in the plan, the
contract summary, the CLI output, and the restore log):

- **WinRE missing** (`system_restore.winre_missing`): source had
  WinRE but the set carries no image; source had none; or its
  presence was never recorded. No recovery partition, no reagentc
  steps. A restore that silently loses WinRE is a failed restore —
  so the gap is named everywhere the plan is shown. (An image
  found in the set *is* placed even when the facts disagreed; the
  warning then discloses the disagreement.)
- **BitLocker** (below). **Secure Boot state unknown**. **ESP
  listing drift** between the set's ESP files and the recorded
  `esp_files` fact (the set's files are what get applied; the
  drift is disclosed).

## The BitLocker rule

VSS reads an *unlocked* volume, so a BitLocker-protected PC backs
up fine — and the restored volume is **not** encrypted. Nothing in
the restore can change that (the source's protectors and keys do
not transfer). So when the source facts record BitLocker `on` or
`suspended` for any volume, the plan *must* carry the
`system_restore.bitlocker_not_restored` warning **and** a
`system_restore.bitlocker_notice` post-step, in plain words: this
restored disk is NOT encrypted; turn BitLocker on again after the
PC first starts. With BitLocker recorded `off` for every volume,
neither appears (tested: present iff protected). Unknown state is
its own warning — never folded into the protected claim.

## The Secure Boot rule

When the source facts record Secure Boot **on**, the plan carries
a `system_restore.secure_boot_note` post-step: the restored boot
files are the source PC's own signed Windows boot files; if the
target firmware's Secure Boot database rejects them at first
start, check the firmware setup — and do not leave Secure Boot
off. Recorded off → no note. Unknown → the
`system_restore.secure_boot_state_unknown` warning. SafeReturn
never asks for Secure Boot to be disabled as part of a restore.

## Simulation vs real, and verification semantics

The **simulation executor** applies a plan to a directory-backed
fake disk (`esp/`, `msr/`, `windows/`, `winre/` under one root)
using the same chunk-rebuilding, hash-verifying restore path file
restores use — the full flow (token → drift check → application
from a real encrypted set → recorded post steps) runs in tests on
any OS. It also writes:

- `safereturn-restore-log.json` — the plan id, target facts,
  warnings, and every post step with status
  **`recorded_simulated`**. In a simulation the boot commands are
  recorded, never run, and the log says so. Only the on-machine
  flow may record a step as executed.
- `safereturn-diskpart.txt` — the exact script this plan would run
  on disk 0, for inspection.

The engine finishes a simulated job under summary id
`result.system_restore_simulated`, a real one under
`result.system_restore_completed` — the two never share a summary.

`verify_system_restore(plan, applied_root)` re-reads the tree:
every planned file present with matching SHA-256 (missing and
mismatched are named per partition), the required ESP boot files
present, and the WinRE image present iff the plan placed one
(`winre_image_present: Option<bool>` — `None` when the plan placed
none, which is not a failure). And the report's
`boot_files_registered` is a sourced `Fact<bool>` that verification
**always** returns unknown-with-a-reason: BCD registration is
created by bcdboot on the machine and cannot be concluded from
files being present. "Files in place" (`files_in_place()`) and
"boot registered" are separate facts, and only the first is ever
claimed here.

## The Windows executor skeleton

`WindowsDiskExecutor` (cfg(windows), compile-verified) is gated by
`SR_RESTORE_LIVE=1` (`system_restore.live_not_enabled` before the
gate). With the gate satisfied it renders the plan's diskpart
script (with the real disk index) and boot command lines into a
caller-chosen work dir, then refuses with
`system_restore.executor_not_ready`. It cannot erase anything.
Off Windows, `platform_system_restore_executor` returns the
unsupported executor (`core.unsupported_platform`). The
`#[ignore]`d live test (`tests/system_restore_live.rs`,
SR_RESTORE_* env vars) exercises exactly this skeleton path on a
real machine.

## CI note

The first final-head CI run (92479e1d) failed the Windows job's
test step: one new test asserted the *non-Windows* platform
executor's error (`unsupported_platform`) unconditionally, but on
Windows the platform executor is the gated skeleton, which refuses
with `system_restore.live_not_enabled` because SR_RESTORE_LIVE is
not set in the test environment. Every local gate was green — the
local windows-target gate *compiles* test targets but cannot run
them, the same gap S3 hit in compile form. Fixed in 3ce89b55 by
making the assertion platform-shaped (each platform asserts its
own executor's refusal); CI is green on both jobs at that head.
Lesson recorded: any test that touches a `platform_*` factory is
platform-shaped by definition and must be written that way.

## Named open items (not guessed)

- Whether `reagentc /enable`, run in WinPE after a `/target`'d
  `/setreimage`, needs its own `/target` on the Windows builds we
  support — the Learn examples run plain `/enable` after the
  offline `/setreimage`; flagged for the on-machine session.
- Whether bcdboot's missing NVRAM entry (the `/s` behavior above)
  boots cleanly on the firmware of the test machine, or whether
  the flow should add a documented step to create the entry
  (e.g. a second bcdboot run without `/s` once the disk is the
  boot disk). The fallback path file is in place either way.
- DiskPart `size=` units are MB; the script emits whole MiB
  (identical for the aligned sizes here). The on-machine session
  confirms DiskPart accepts the generated script verbatim.
- WinRE partition *position*: the plan puts it last (after
  Windows), matching Microsoft's layout guidance and leaving the
  Windows partition able to grow into the disk — the push-button
  recovery implications of a custom layout (ARCH plan §6) are
  S6+ work.
- The ESP application and bcdboot both write boot files (the set's
  captured ESP contents land first; bcdboot then builds the BCD
  and refreshes the boot environment from the restored Windows).
  Whether bcdboot should run *before* file application on a real
  disk (so a bcdboot failure leaves the captured BCD untouched) is
  an ordering question for the on-machine session; the plan's step
  order is application → bcdboot, recorded as data either way.
- Targets that are also the backup source or hold the only backup
  copy: the plan-token + facts model carries the data a shell
  needs to refuse them, but the SafeTarget check itself lands
  with the shell flows (S6), as SHELL_CONTRACT already notes for
  restore plans generally.

## UNVERIFIED — the on-machine restore session must check

No real bare-metal restore has ever been run. In order:

1. **The diskpart script, verbatim**, against a sacrificial disk:
   partition sizes/types/letters land as planned; the recovery
   partition gets the documented type id + attributes; DiskPart
   exits clean.
2. **File application to real volumes** (the executor's missing
   middle): partition the disk, assign letters, apply the plan's
   files from the volume, respecting the letters the diskpart
   script assigned.
3. **bcdboot**: exit status, the BCD it creates, the NVRAM-entry
   question above, and a first boot of the restored disk to the
   Windows logon screen.
4. **reagentc**: `/setreimage` with `/target` from WinPE, then
   `/enable`; `reagentc /info` shows the restored WinRE enabled at
   the recovery partition; boot into WinRE once and confirm it
   starts.
5. **The BitLocker notice flow end-to-end**: restore a set from a
   BitLocker-on source; confirm the restored volume is unencrypted
   (as warned), then re-enable BitLocker after first boot.
6. **Secure Boot**: first boot with Secure Boot ON using the
   restored (source-signed) boot files; behavior with the UEFI CA
   2023 transition on the test machine's firmware.
7. **Different-size targets**: restore a 512 GB source onto a
   256 GB target (fits by the computed minimum) and onto one below
   the minimum (refused); confirm Windows is healthy on the
   smaller disk.
8. **The skeleton's gate + artifacts** via the ignored live test
   (SR_RESTORE_* env): plan from real facts on the machine,
   artifacts rendered, refusal as designed.
9. **Failure matrix**: wrong disk index stated in the facts
   (drift/identity checks), a set whose ESP capture is incomplete
   (refused by name), WinRE image missing (warning shown before
   erase, restore proceeds), power loss mid-apply (partial disk is
   visibly partial — re-run from the top; there is no resume).
10. **Where `boot_files_registered` gets set**: the on-machine
    flow records it from bcdboot's/reagentc's own results — until
    that flow exists, no surface may show registration as proven.
