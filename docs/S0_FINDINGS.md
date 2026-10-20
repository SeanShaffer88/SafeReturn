# SafeReturn — S0 Spike Findings
**Date:** 2026-10-20 · **Scope:** (1) VSS requester spike, (2) UI-stack comparison
**Code:** `src-s0-vss/` (state machine + tests + C++ helper + Rust FFI driver)
**Honesty note:** everything below separates *verified here* (this Linux VM: compiles, unit tests) from *documented* (Microsoft Learn) from *unverified* (needs a real Windows machine / WinPE boot).

---

## Part 1 — VSS spike

### Verified here
- The documented requester sequence (Learn: *Requesters*, *Overview of Processing a Backup Under VSS*, *Overview of Pre-Backup Tasks*) is encoded as a Rust state machine (`src-s0-vss/src/lib.rs`). Out-of-order calls return a `VSS_E_BAD_STATE` analogue; a session is single-use after release, matching Learn's rule that an `IVssBackupComponents` object must never be reused.
- `cargo test` (Linux): **4/4 pass** — full sequence, bad-state rejection, single-use enforcement, and snapshot-device path mapping (the function that turns `C:\Users\…\open.db` into `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Users\…\open.db`, i.e. how locked files are read from the snapshot).
- `cargo check --target x86_64-pc-windows-msvc`: **passes** for the Rust FFI driver (`src/win.rs`).

### The headline finding: the Rust `windows` crate cannot reach the VSS requester
- `windows` 0.61.3, module `Win32::Storage::Vss` (inspected in the local crate source): ships writer, provider, and snapshot-management interfaces (`IVssAsync`, `IVssComponent`, `IVssSnapshotMgmt`, …) but **`IVssBackupComponents` and `CreateVssBackupComponents` are absent**. The first compile attempt failed on exactly those two imports, and a full-text search of the crate confirms they exist nowhere in it.
- Consequence: a pure-Rust requester would require hand-defining a ~50-method COM vtable. Its method *order* cannot be verified from anything available in this environment, and a wrong order fails silently at runtime — in backup software, that class of bug is disqualifying.

### Resolution adopted (in the spike, ready to reuse)
- **Narrow C++ helper** (`src-s0-vss/cpp/vss_helper.cpp`, ~150 lines) compiled against the real SDK `vsbackup.h` + `VssApi.lib`, exporting 5 C functions (create / initialize / gather-metadata / snapshot-volume / destroy) that the Rust state machine drives. The header guarantees the vtable; Rust keeps sequencing, policy, and all product logic.
- Documented sequence implemented in the helper: `CreateVssBackupComponents → InitializeForBackup → SetBackupState(TRUE, TRUE, VSS_BT_FULL, FALSE) → GatherWriterMetadata+Wait → StartSnapshotSet → AddToSnapshotSet(volume, GUID_NULL) → PrepareForBackup+Wait → DoSnapshotSet+Wait → GetSnapshotProperties → BackupComplete+Wait → DeleteSnapshots → Release`. Privilege requirement (elevated, backup privilege; `E_ACCESSDENIED` otherwise) is documented at both layers.

### Unverified / next (S0.5, first tasks on a Windows machine or windows-latest CI)
1. Compile `vss_helper.cpp` (needs Windows SDK — first CI job when the repo exists).
2. Run the probe elevated on a test VM: create + initialize + gather metadata (creates no snapshot).
3. Run `snapshot_volume("C:\\")`, read a *locked* file via `snapshot_path()`, complete + delete; confirm with `vssadmin list shadows` that nothing leaks.
4. Add per-writer status enumeration (`GatherWriterStatus`/`GetWriterStatus`) — the helper has a marked TODO; the product's pre-flight writer check depends on it.

---

## Part 2 — UI-stack comparison

### The gate that decides most of it: WinPE
The recovery shell must run in WinPE. Documented facts (Learn, *WinPE Optional Components* / *WinPE: Mount and Customize*):

| Stack | In WinPE? | Evidence |
|---|---|---|
| **WinUI 3** | **No** | WinPE's .NET OC lists "Windows Runtime" among features with no/reduced functionality in PE; WinPE "only supports legacy apps" |
| **WPF** | **No** | Same OC reference, verbatim: "Windows Presentation Foundation (WPF) (not supported)" in WinPE |
| **egui / eframe** | **Unverified** | It's a Win32 window + GPU rendering (glow/wgpu). WinPE's graphics/driver set is minimal; no source found either way. Only a real WinPE boot test settles it |
| **Native Win32** | **Yes** | Win32 is WinPE's native app model — Microsoft's own PE tooling is Win32 |

So *any* choice other than Win32-everywhere means **two UI codebases** (desktop + PE). That cost is certain; it must be bought with something worth more.

### Desktop scoring (1–5, higher better; evidence-based)

| Criterion | WinUI 3 (C#) | WPF (C#) | egui (Rust) | Native Win32 (Rust) |
|---|---|---|---|---|
| Accessibility out of the box (UIA/Narrator/keyboard/focus) | 5 — UIA built into controls; Learn a11y checklist is written for it | 4 — mature UIA, older patterns | 2 — AccessKit exists and is on by default in eframe, **but** tooltips are hover-only and custom widgets are the app's own problem: our InstallScope audit measured ≈33% tooltip coverage and mouse-only custom tiles *in our own egui app* | 4 — standard controls inherit UIA/keyboard/focus from the OS; drops to 2 if we custom-draw, so: standard controls only, by rule |
| Text scaling & high contrast | 5 — all WinUI text controls scale without customization (Learn) | 4 | 3 — manual discipline | 4 — standard controls + per-monitor DPI, layout code is ours |
| Native Windows feel for ordinary users | 5 | 3 | 2 | 4 |
| Touch | 5 | 3 | 2 | 3 |
| One language with the Rust core | 1 — C# shell + interop/process boundary | 1 | 5 | 5 |
| Same toolkit in WinPE shell | 1 (gate: no) | 1 (gate: no) | 3 (unverified) | 5 |
| Speed to build guided flows | 4 | 4 | 5 | 2 |
| **Weighted total*** | 3.1 | 2.7 | 2.8 | **3.9** |

\* Weights reflect this product: WinPE gate & a11y ×3, single-language & native feel ×2, speed ×1. Scores are our assessment; the *evidence column facts* above are the documented part.

### Recommendation
**Native Win32 with standard controls (Rust, `windows` crate) for both shells** — one toolkit, one language, the only stack that passes the WinPE gate, OS-inherited accessibility, and it compounds with InstallScope's native-Win32 migration work instead of competing with it. SafeReturn's flows are wizard-shaped (progress, lists, trees, confirm dialogs) — exactly what standard controls do best, and a familiar Windows look is a *feature* for a stressed non-technical user.

Runner-up: WinUI 3 desktop + Win32 PE shell, if you judge modern desktop polish worth a permanent second UI codebase and a C# shell. egui is **rejected for this product** (fastest to build, wrong risk profile: our own audit evidence + unverified PE rendering). WPF is dominated by WinUI 3 on desktop and fails the same gate.

This is a recommendation, not a fait accompli — the call is yours (§8.1 of the Plan). The core, VSS helper, and chunk store are stack-agnostic either way; S1 work is unblocked regardless.

> **DECISION (SEAN, 2026-10-20): WinUI 3 desktop + Win32 recovery shell** — the runner-up above, chosen for desktop polish/accessibility for ordinary users, accepting the two-shell cost. The mitigation designed for exactly that cost is the Shell Contract (`files/SHELL_CONTRACT.md`) + `safereturn-contract` crate. The Win32-everywhere recommendation is preserved here as the record of the alternative, not the plan.

### The comparison test artifact: First Backup screen spec (any shell must satisfy)
- **Controls in tab order:** destination list (ListView, each row: drive icon, name, size, free space, "same disk as Windows" warning icon *with visible text*) → password field + visible strength caption → "Show password" checkbox → recovery-key save button → Back / Continue buttons.
- **Rule demonstrated:** every tooltip text also exists as visible caption or accessible description. No hover-only information, anywhere, per the production-polish standard.
- **Accessible names:** e.g. Continue = "Continue: back up this PC to Seagate Backup Plus, 1.8 terabytes free"; destructive/erasing actions are never the initially focused control.
- **States specified per control:** empty (no destination plugged in → illustration + "Plug in an external drive" + Refresh), loading (drive scan spinner, controls disabled but Cancel live), error (drive too small → exact numbers + what to do), success.
- **Keyboard:** full flow completable by keyboard; Esc = Back/Cancel with confirm if a backup is running; F1 = context help (as in InstallScope).

---

## Sources
- VSS requester life cycle & API: https://learn.microsoft.com/en-us/windows/win32/vss/requestors · https://learn.microsoft.com/en-us/windows/win32/vss/overview-of-processing-a-backup-under-vss · https://learn.microsoft.com/en-us/windows/win32/vss/overview-of-pre-backup-tasks
- IVssBackupComponents (single-use rule, CreateVssBackupComponents): https://learn.microsoft.com/en-us/windows/win32/api/vsbackup/nl-vsbackup-ivssbackupcomponents
- InitializeForBackup (E_ACCESSDENIED / privileges): https://learn.microsoft.com/en-us/windows/desktop/api/VsBackup/nf-vsbackup-ivssbackupcomponents-initializeforbackup
- WinPE optional components (WPF not supported; Windows Runtime reduced): https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-add-packages--optional-components-reference?view=windows-11
- Accessibility checklist (text scaling, tools, CI checks): https://learn.microsoft.com/en-us/windows/apps/design/accessibility/accessibility-checklist
- egui accessibility (AccessKit, default in eframe): https://docs.rs/egui (feature flags) and lib.rs/crates/egui FAQ
- Local evidence: InstallScope quality audit, `~/workspace/installscope-quality/quality-audit.md` (2026-10-20)

---

## Addendum 2026-10-20 — S0.5 compile verification via CI (repo: SeanShaffer88/SafeReturn)

The repo + windows-latest CI SEAN chose as the next step closed the
compile-verification gap in four runs:

1. Run #1 FAILED at `cargo test` on Windows: LNK2019, 5 unresolved
   `sr_vss_*` symbols — the Rust test binary linked before the helper
   existed. FIX: win.rs now loads vss_helper.dll at RUNTIME
   (LoadLibraryW/GetProcAddress, OnceLock-cached); nothing links the
   helper, and a missing DLL is a clean runtime error.
2. Run #2 FAILED one test: golden fixture compare — the file on disk
   had CRLF (Windows checkout conversion), generated JSON has LF;
   content otherwise identical. FIX: `.gitattributes` pins
   `* text=auto eol=lf`; the golden test also normalizes CRLF on read.
3. Run #3: tests green on Windows; failed compiling the helper itself —
   ~30 errors inside vsbackup.h (VSS_COMPONENT_TYPE, IVssWMFiledesc,
   VSS_USAGE_TYPE… all undefined). Root cause: those types live in
   <vswriter.h>; Microsoft Learn's vsbackup.h requirements state
   "include VsBackup.h, Vss.h, VsWriter.h". FIX: added the include.
4. Run #4 GREEN (both jobs): fmt clean, all workspace tests pass
   natively on windows-latest, and vss_helper.cpp compiles clean
   against Windows SDK 10.0.26100 with VssApi.lib.

STILL UNVERIFIED (unchanged): runtime behavior — the probe has not
run elevated on a real Windows machine; no snapshot has been taken.
That remains the S0.5 on-machine checklist in §1 above.
