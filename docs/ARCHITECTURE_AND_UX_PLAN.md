# SafeReturn — Architecture & UX Plan
*Working title. Rename is cheap until first release; the concept is the product.*

**One-line promise:** A full-disk backup for ordinary Windows users that *proves* it can bring your PC back — before you ever need it to.

**Date:** 2026-10-20 · **Status:** Pre-implementation plan, for SEAN's approval of scope + UI-stack spike
**Applies:** Windows 10 22H2 / Windows 11, x64, UEFI/GPT first (BIOS/MBR = best-effort later). Single-PC home users, not enterprise fleet management.

---

## 1. The problem, in the user's words

> "My PC won't start. I have a backup… I think. I don't know where it is, whether it worked, how to start from it, or what it will erase."

Every part of a normal backup product fails this person at a different moment:

1. **Setup** assumes they know what a volume, image, or incremental is.
2. **"Backup completed"** says nothing about whether a restore would succeed.
3. **Recovery media** is an afterthought — created (if ever) in a separate tool, never boot-tested.
4. **Restore** is a technician's console shown to someone already having their worst computer day.

SafeReturn is designed backwards from that bad day.

## 2. Standout feature: Recovery Rehearsal

Not "verification" buried in a log. A named, guided, repeatable rehearsal with a plain-language result the user keeps.

### The four rehearsal levels

| Level | Name in UI | What actually happens | Time | Touches your real disk? |
|---|---|---|---|---|
| 1 | **Quick Check** | Every chunk's SHA-256 re-hashed against the catalog; catalog consistency; EFI/BCD/WinRE boot components confirmed present in the backup | Minutes, background | No — read-only on backup |
| 2 | **File Rehearsal** | Backup is mounted read-only; a mix of user-picked "files I can't lose" + a random sample is restored to a sandbox folder, hashes compared, and file types opened/parsed where a safe viewer exists | Minutes | No — writes only to sandbox |
| 3 | **Boot Rehearsal** | Backup is restored to a virtual disk and booted in an isolated VM (Hyper-V where available); boot success, logon-screen reachability, and elapsed time are recorded. Fallback where Hyper-V is unavailable (most Home PCs): restore-to-VHD + BCD validation + a guided boot test of the recovery USB itself | 15–45 min | No — VM/VHD only |
| 4 | **Full Dress Rehearsal** | Whole-PC restore to a spare disk, guided end-to-end, using the exact WinPE flow a real disaster would use | 30–90 min | Only the spare disk the user explicitly picks |

### The Recovery Card

After any successful rehearsal, the app produces a one-page **Recovery Card** (PDF + printable, also saved onto the recovery USB):

- Which drive to plug in, and which USB to boot from — with the PC's own boot-menu key shown if known
- Steps 1-2-3 in large type, written for a stressed non-technical reader (or a family member helping them)
- Date of last good backup, date and level of last successful rehearsal
- Where the encryption password / recovery key is kept (a *location hint the user writes*, never the password itself)
- A support summary: backup ID, app version, rehearsal log reference

### Honesty rules (non-negotiable, carried over from InstallScope)

- No invented "health score" number. The UI shows **facts**: "Last backup: Tue 9:41 pm · Quick Check passed Wed · Boot Rehearsal passed Sep 12 · Recovery USB boot-tested: Yes."
- A rehearsal that was never run says **"Not tested yet"** — in amber, not hidden.
- A failed check names the failing component and the fix ("3 files could not be read from the backup drive — re-run backup; if it repeats, the drive may be failing"), never just "verification failed."
- "Backup completed" is never shown until catalog + hashes for that job are written and re-read.

## 3. Core jobs

1. **First Backup (guided, ~4 screens)**
   Detect internal disks and candidate destinations → recommend an external drive (warn plainly if destination is the same physical disk, a small USB stick, or nearly full) → choose what "everything" means with a visual disk map → set a backup password with strength + recovery-key export → run, with honest progress (files/size remaining, not a fake %).

2. **Automatic protection**
   Scheduled (Task Scheduler), catch-up on missed runs, "back up when I plug in the backup drive" trigger, pause on battery / metered network. Retention in plain language ("Keep daily copies for a week, weekly for a month, monthly for a year") mapped to a GFS policy underneath.

3. **Browse & restore individual files**
   Timeline first ("when do you want to go back to?"), then a familiar file explorer mounted read-only from the backup. Restore to original place (with overwrite preview: newer/older/size) or to a folder. Deleted-file recovery is the same flow — no separate "undelete" mode.

4. **Whole-PC restore**
   Two entry points, same flow: from inside Windows (to a different disk / after disk replacement wizard) and from the **bootable recovery USB** (WinPE, large-type guided UI, mouse + keyboard + touch). See safeguards in §6.

5. **Recovery media builder**
   Offered at the end of the first backup — not buried in settings. Builds a WinPE USB containing the recovery app, storage/network drivers captured from *this* PC, and a pointer to the backup catalog. Ends with an optional **boot test**: restart instructions + a marker file the app checks on next launch to confirm "yes, this PC booted from this USB on [date]."

## 4. Checked technology options

Researched 2026-10-20 against Microsoft Learn (primary). Citations at §10.

### Imaging / capture

| Option | How it works | Strengths | Why not sole engine |
|---|---|---|---|
| **A. Own engine on VSS (recommended)** | App acts as a VSS *requester* via `IVssBackupComponents`; VSS writers quiesce apps, provider gives a consistent point-in-time snapshot while the PC keeps running [Learn: VSS] | Live, application-consistent backup; we control chunking, dedup, encryption, catalog | Most engineering — mitigated by phased scope (§7) |
| B. DISM **FFU** | Sector-based full-disk capture/apply; Xpress-Huffman compression; built-in catalog + hash table validated before apply [Learn: FFU] | Fastest factory-style imaging; free; proven apply path from WinPE | Target must be ≥ source size; poor incremental story; clumsy single-file restore; cleans entire target drive. Useful as a *reference* and possible export format, not the product engine |
| C. DISM **WIM** | File-based image of a partition; mountable/modifiable; deploys to different-sized disks [Learn: WIM vs FFU] | File-based restore model is exactly what consumers need; mount = file browsing | No dedup/incremental/encryption product story on its own; still needs our catalog, scheduler, UX |
| D. File-level only (restic-style) | Copy files with dedup, no volume/boot handling | Great file restore, simplest v1 | Not a whole-PC product — no bootable bare-metal restore, which is the brief |

**Decision: Option A, phased file-first.**
- **Phase 1 engine:** From the VSS snapshot, capture the system volume *file-by-file* into our own content-addressed chunk store, plus capture EFI + Recovery partitions and boot configuration as first-class objects. Restore re-creates partitions, lays files down, and rebuilds boot with `bcdboot` + `reagentc /setreimage` (the same sequence Microsoft's own WIM deployment scripts use). Advantage: restores to a *smaller-or-different* disk (WIM's documented advantage over FFU) and file restore falls out for free.
- **Phase 2 engine:** Block-level incremental capture from the VSS snapshot for speed on large, mostly-static volumes, writing into the *same* chunk store/catalog. File restore then goes through a volume mounter. No format break.

### Chunk store (our format, deliberately boring)

- Content-addressed chunks (target 1–4 MiB, content-defined chunking in Phase 2; fixed-size acceptable in Phase 1 prototype), SHA-256 per chunk, zstd compression, per-chunk authenticated encryption (XChaCha20-Poly1305 or AES-256-GCM — pick one in the crypto spike; no home-rolled primitives).
- Key derivation: Argon2id from the user's backup password; a separate **recovery key file** (exported at setup) can unlock without the password.
- Catalog: append-only manifest per backup (JSON/CBOR + SQLite index that can be *rebuilt from manifests*). If the app and its database die with the PC, the recovery USB rebuilds everything it needs from the backup drive alone. This is a rehearsal-tested property, not a hope.
- Every backup job ends: flush → re-read manifest → hash-verify newly written chunks → only then mark job good.

### Bootable recovery environment

- **WinPE** built with the Windows ADK: `copype` creates the working files, `MakeWinPEMedia /UFD` or `/ISO` creates media [Learn: WinPE]. Two-partition USB layout (FAT32 boot + NTFS data) to get past FAT32's 4 GB file / 32 GB partition limits on UEFI systems [Learn: single-USB WinPE].
- Use **`/bootex`** (ADK ≥ 10.1.26100.2454, Dec 2024) so boot files are signed with the Windows UEFI CA 2023 certificate — matters as the 2011 CA expires out of Secure Boot trust [Learn: MakeWinPEMedia].
- Inject this PC's storage/network drivers at media-build time; list exactly which drivers were added on the confirmation screen.
- The recovery app in WinPE is the *same core library* with a reduced, large-type shell — one restore code path, tested in both places. Never a second, divergent restore implementation.

### Platform traps designed for, not discovered later

- **BitLocker:** On a running system, VSS reads the *unlocked* volume, so backups succeed transparently — and the *restored* volume is not automatically BitLocker-protected. The restore flow must say this in plain words, offer guided re-enable after first boot, and the First Backup flow must prompt the user to confirm they can find their BitLocker recovery key (48-digit; Microsoft-account escrow pointed to, never collected by us) before they rely on any of this.
- **Secure Boot / boot order:** The boot test (§3.5) exists precisely because "the USB is bootable" ≠ "this PC will boot it." Record the outcome per-PC.
- **Different-size target disk:** Allowed down to *used-space + headroom*, checked before anything is erased; the check shows both disks by model, serial suffix, size, and current contents summary.
- **WinRE:** Restore re-registers WinRE (`reagentc`) and the rehearsal's Quick Check verifies WinRE is present in the restored layout — a "successful" restore that silently loses the recovery partition is a failed restore.

## 5. Architecture

```
safereturn-core   (Rust library — no UI, no Windows-only code where avoidable)
  catalog/        manifests, indexes, retention policy
  chunkstore/     chunking, hash, compression, encryption, verify
  engine/         backup / restore / mount / rehearsal orchestration
  model/          Disk, Volume, Backup, RehearsalResult — plain data, serde

safereturn-win    (Rust, Windows platform layer)
  vss/            IVssBackupComponents requester (COM), snapshot lifecycle
  disk/           partition layout (GPT), volume enumeration, safe-target checks
  winpe/          ADK media builder, driver capture/injection, boot-test marker
  scheduler/      Task Scheduler integration

safereturn-engine (Rust — core + win + VSS helper, elevated; owns ALL logic)
safereturn-app    (desktop shell — DECIDED 2026-10-20: WinUI 3 / C#, Win App SDK;
                   not elevated; talks to engine over named pipe, see SHELL_CONTRACT.md)
safereturn-pe     (WinPE shell — DECIDED: native Win32 / Rust, same contract messages
                   in-process, reduced large-type UI)
safereturn-cli    (support/advanced CLI: verify, list, mount, restore — scriptable)
```

Rules: long work off the UI thread with cancellation; every destructive operation goes through one `SafeTarget` check type; the core must be testable on synthetic disk images without a real PC at risk; structured logs a support human can read, with a one-click "copy diagnostics" that redacts paths/usernames by default.

## 6. Safety & UX standards

Per SEAN's production-polish standard and quality manifesto (recorded 2026-10-20, applies to all projects):

- Safe defaults for beginners, advanced controls grouped and explained for pros.
- Every consequential screen states: what will happen, what will be **erased**, what the recovery path is, and how long it typically takes — before the button.
- Whole-PC restore safeguards: target disk ≠ backup source disk, ≠ disk holding the only backup copy; size check; contents preview; destructive confirm starts focused on **Cancel**, requires picking the target twice (list + summary), and offers "make a backup of the current disk first" when space allows.
- Tooltips on every interactive control; full keyboard path; screen-reader names; high-contrast + text-scaling respected; no essential information carried by hover or color alone.
- Errors are specific with a fix path and a "what was *not* changed" line. Nothing fails silently; a missed scheduled backup surfaces within a day, not at disaster time.
- Offline-first, no telemetry by default, no account, no networking except optional user-configured NAS destination. Backups are encrypted by default; the password is never stored in plaintext and never leaves the PC.

## 7. Build order (small, CI-gated slices — SEAN's established process)

| Slice | Deliverable | Proves |
|---|---|---|
| **S0 Spike (1 wk)** | VSS snapshot of C: from a Rust requester; read one locked file from the snapshot; UI-stack spike (see §8) | The riskiest API works in our hands |
| S1 | Chunk store + manifest + `verify` (Level-1 rehearsal logic) with tests on synthetic data | Format + honesty core |
| S2 | File/folder backup → restore to folder, end-to-end, scheduled | A useful product even before bare-metal |
| S3 | Full system-volume backup (VSS, incl. EFI/Recovery capture) + timeline file explorer | Whole-PC data is actually captured |
| S4 | WinPE media builder + driver injection + boot-test marker | Bootable media, tested on the target PC |
| S5 | Bare-metal restore in WinPE → spare disk & VM; `bcdboot`/`reagentc` rebuild | The disaster flow works |
| S6 | Rehearsals L1+L2 in UI + Recovery Card (PDF/print/USB) | **The standout feature, v1** |
| S7 | Boot Rehearsal L3 (Hyper-V path + Home-edition fallback) | Standout feature, complete |
| S8 | Onboarding polish, accessibility pass, docs, first public release | Shippable to ordinary users |

Explicitly **out of v1:** cloud storage destinations, Mac/Linux, enterprise central management, continuous (CDP) backup, restoring to dissimilar hardware as a headline feature (best-effort only, said so in UI).

## 8. Open decisions for SEAN

1. **Desktop shell: DECIDED by SEAN 2026-10-20 — WinUI 3 (C#) desktop + native Win32 (Rust) recovery shell.** The S0 spike (files/S0_FINDINGS.md) established that neither WinUI 3 nor WPF can run in WinPE, so two shells were unavoidable once desktop polish was prioritized; Muse's recommendation (Win32 everywhere) was the runner-up and was not chosen. The two-codebase risk is managed by the Shell Contract (files/SHELL_CONTRACT.md): engine owns all logic and wording, shells only render, message types live in the `safereturn-contract` Rust crate with golden JSON fixtures the C# tests consume. Desktop pins Windows App SDK stable (2.5.1 at decision time; recheck at scaffold).
2. **Name:** SafeReturn is a working title. Alternatives noted: *Second Chance PC*, *HomeVault Backup*. Decide before S4 (name is burned into recovery media).
3. **License / distribution:** Open-source like InstallScope/DriverGuard? That decision affects the crypto/format docs (publishing the format spec is good for trust either way).

## 9. Risks, honestly

- **VSS is fiddly.** Writer failures, snapshot space, and antivirus interference are the #1 support burden of every Windows backup tool. Mitigation: pre-flight writer check in First Backup, specific error surfacing, S0 spike first.
- **Hyper-V is absent/disabled on many Home PCs.** Boot Rehearsal L3 must degrade gracefully (VHD + USB boot test) and never claim a boot test that didn't happen.
- **WinPE driver gaps** can make a recovery USB blind to an NVMe disk. Mitigation: capture drivers from the host at build time + rehearsal L4 exercises the real path.
- **A backup tool can destroy data.** Restore code ships only after S5 passes against VM + sacrificial-disk test rigs, with the `SafeTarget` checks fuzzed/unit-tested. No exceptions for schedule pressure.

## 10. Sources (Microsoft Learn unless noted)

- Volume Shadow Copy Service — service/requester/writer/provider model; backup apps as requesters: https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service and https://learn.microsoft.com/en-us/windows/win32/vss/requestors
- Capture and apply FFU images (DISM `/capture-ffu`, `/apply-ffu`, hash-table validation): https://learn.microsoft.com/hu-hu/windows-hardware/manufacture/desktop/deploy-windows-using-full-flash-update--ffu?view=windows-11
- WIM vs VHD vs FFU comparison (file- vs sector-based, deploy to different sizes): https://learn.microsoft.com/hu-hu/windows-hardware/manufacture/desktop/wim-vs-ffu-image-file-formats?view=windows-11
- WinPE: create bootable media (Copype / MakeWinPEMedia): https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-create-usb-bootable-drive?view=windows-11
- MakeWinPEMedia options, incl. `/bootex` Windows UEFI CA 2023 (ADK 10.1.26100.2454): https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/makewinpemedia-command-line-options?view=windows-11
- WinPE on a single USB (FAT32 limits, two-partition layout): https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe--use-a-single-usb-key-for-winpe-and-a-wim-file---wim?view=windows-11
- WIM deployment script pattern (`bcdboot`, copying WinRE, `Reagentc /Setreimage`): https://learn.microsoft.com/windows-hardware/manufacture/desktop/capture-and-apply-windows-using-a-single-wim

*Documented facts above are Microsoft's; product design, phasing, and recommendations are ours and are labeled as such in the text.*
