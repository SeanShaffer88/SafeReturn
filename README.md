# SafeReturn

Full-disk backup and recovery for ordinary Windows users — bootable system
backups, verification, and restore of individual files or the whole PC through
a guided interface.

Most backup tools will tell you a backup "completed." Almost none will prove
it can bring your PC back. SafeReturn is built around that proof.

## The standout: Recovery Rehearsal

Recovery you can understand and **test before a crisis**, in four levels:

1. **Quick Check** — every chunk of the backup is re-hashed; boot components
   (EFI / BCD / WinRE) are confirmed present.
2. **File Rehearsal** — files you choose (plus a random sample) are restored
   to a sandbox folder and verified byte-for-byte.
3. **Boot Rehearsal** — the backup is restored to a virtual disk and actually
   booted, without touching your real disk.
4. **Full Dress Rehearsal** — a guided whole-PC restore to a spare disk using
   the exact recovery flow a real disaster would use.

After a successful rehearsal, SafeReturn produces a printable **Recovery
Card**: which drive to plug in, which USB to boot from, and steps 1-2-3 in
large type, written for a stressed non-technical reader.

Honesty is a design rule here: no invented "health score." The app shows
facts — last backup time, which rehearsals passed and when — and says
"Not tested yet" when a rehearsal has never run.

## Status

**Pre-alpha.** Architecture, the riskiest technical spike (S0), the
S1/S2 engine, the S3 capture layer, and the S4 recovery-media
builder are done; there is no installable product yet. What exists
today:

- A production encrypted chunk store (`safereturn-core`): content-addressed
  chunks (SHA-256 of the plaintext, dedupe), compressed and encrypted
  per-chunk (XChaCha20-Poly1305), volumes unlocked by an Argon2id
  passphrase or a recovery-key file, multi-folder backup sets with
  manifests stored on the volume, Level-1 verify that names damaged
  chunks, and a catalog that rebuilds from the manifests alone. See
  `docs/S1_S2_NOTES.md`.
- The S3 capture layer: backups read through a **capture source** — the
  live filesystem by default, or a VSS snapshot via a prefix-mapped
  source — and every set manifest records which (`capture_mode`), plus
  an optional system-facts section (boot mode, Secure Boot, BitLocker,
  ESP contents, WinRE, BCD status — each fact sourced, each unknown
  explicit and reasoned). See `docs/S3_NOTES.md`. Honest limit: this
  code has never taken a real snapshot — VSS runtime verification is
  the pending S0.5 on-machine session, listed precisely in those notes.
- The S4 recovery-media builder: a pure, fully tested **media plan**
  (two-partition FAT32+NTFS layout computed from stated facts, typed
  refusals, a non-removable override that is recorded forever),
  contract messages + an engine create flow with the same plan-token
  discipline as restore, a Windows ADK executor (`copype`/DISM/
  `MakeWinPEMedia /bootex`) that refuses to run unless explicitly
  enabled, a media manifest, cross-platform `verify_media`, and the
  **boot-test marker**: media reports NOT TESTED YET until a real
  boot records itself on the stick. See `docs/S4_NOTES.md`. Honest
  limit: no media has ever been built by this code — execution is
  compile-verified only, with the on-machine checklist in those
  notes.
- An engine API over the shell contract with restore **plan tokens**:
  a restore executes only the exact preview that was confirmed, refuses
  stale plans, and writes nothing on refusal. Plus Level-2 File
  Rehearsal (sandbox restore + byte-compare).
- A headless CLI (`safereturn-cli`): `init-volume`, `backup` (with
  `--snapshot <VOL>` and `--system-facts <file>`), `list-sets`,
  `verify`, `restore-set`, `restore-file`, `rehearse-file`, and
  `media plan` / `media create` / `media verify`.
- A VSS requester spike: the documented Windows Volume Shadow Copy sequence
  as a tested state machine, plus a narrow C++ helper that talks to the real
  VSS API (`safereturn-vss`). Compiling that helper on Windows is verified by
  CI — see the note under *Building*.
- The shell ↔ engine message contract shared by the future WinUI 3 desktop
  app, the Win32 recovery shell for WinPE, and the CLI
  (`safereturn-contract`, with golden JSON fixtures).

License: MIT (see `LICENSE`).

## Layout

```text
crates/
  safereturn-contract/   Message types between shells and engine (+ golden fixtures)
  safereturn-core/       Encrypted chunk store, sets, verify, engine API, rehearsals
  safereturn-cli/        Headless CLI (init-volume, backup, verify, restore, rehearse)
  safereturn-vss/        VSS requester state machine + C++ helper (cpp/)
docs/
  ARCHITECTURE_AND_UX_PLAN.md
  S0_FINDINGS.md
  S1_S2_NOTES.md
  S3_NOTES.md
  S4_NOTES.md
  SHELL_CONTRACT.md
```

## Building

Requires a stable Rust toolchain. On any OS:

```sh
cargo fmt --all
cargo test --workspace
```

Windows-target compile check (works from Linux/macOS with the target
installed via `rustup target add x86_64-pc-windows-msvc`):

```sh
cargo check --workspace --target x86_64-pc-windows-msvc
```

The C++ VSS helper (`crates/safereturn-vss/cpp/vss_helper.cpp`) builds only on
Windows against the Windows SDK (`VssApi.lib`). The Windows CI job compiles it
on every push — that compile is the verification the S0 spike was designed to
produce.
