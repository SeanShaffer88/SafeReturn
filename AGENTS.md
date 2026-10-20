# AGENTS.md — SafeReturn conventions

## What this is
Full-disk backup/recovery for ordinary Windows users. The standout feature is
Recovery Rehearsal (testable, understandable recovery). Design source of truth
lives in `docs/` — read `ARCHITECTURE_AND_UX_PLAN.md` before changing behavior,
`S0_FINDINGS.md` before touching VSS or UI-stack assumptions, and
`SHELL_CONTRACT.md` before changing anything a shell and the engine exchange.

## Architecture rules
- The Rust engine owns **all** logic, flow order, defaults, and user-visible
  wording. Shells (WinUI 3 desktop, Win32 WinPE, CLI) only render.
- Shell ↔ engine message types live in `crates/safereturn-contract` and are
  pinned by golden JSON fixtures. Any change to a message shape or a default
  must update the fixtures in the same commit (the C# shell's tests consume
  them; drift must fail a test, not reach a user).
- **VSS:** never hand-define or hand-edit COM interface definitions. The VSS
  requester lives in `crates/safereturn-vss/cpp/vss_helper.cpp`, compiled
  against the real Windows SDK `vsbackup.h`, behind a narrow C ABI that the
  Rust state machine drives. (Reason: the Rust `windows` crate does not expose
  `IVssBackupComponents` — see `docs/S0_FINDINGS.md`.)
- The engine re-validates every destructive request itself; a UI confirmation
  is never the only safety check.

## Product standards
- Honesty: no invented scores or progress claims. Show facts; say "Not tested
  yet" when something has not been tested. Errors state what happened, the
  fix path, and what was *not* changed.
- Accessibility is a requirement, not a phase: full keyboard path, screen-
  reader names, tooltips on every interactive control, and no essential
  information carried only by hover or color.
- Safe defaults for beginners; advanced controls grouped and explained.
  Destructive actions: preview, explicit confirmation focused on Cancel, and
  a recovery path wherever one exists.
- Offline-first, no telemetry by default, no account required. Backup data is
  encrypted by default; secrets are never logged.

## Gates (all must pass before push)
```sh
cargo fmt --all
cargo test --workspace                                   # full suite, never a filtered subset
cargo check --workspace --all-targets --target x86_64-pc-windows-msvc
# --all-targets is load-bearing: test files are targets too, and
# cfg(windows) test code compiles nowhere else. S3's first CI runs
# failed on exactly that — a borrow error in a Windows-only test that
# every other gate had passed. (Plain `cargo check --target` does not
# compile test targets.)
```
CI additionally compiles the C++ VSS helper on `windows-latest`.
Report exactly what ran and what was not verified (e.g. Windows runtime,
WinPE boot, screen-reader behavior) — never claim more than the evidence shows.
