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

---

## Development standard

This project follows SEAN's **Universal Windows Desktop Master Prompt** — the standing development standard for all of SEAN's Windows desktop projects, current and future. The full text is maintained by SEAN (ask him for the current version); this section is the in-repo summary, and the project's own instructions add project-specific requirements on top of it.

Core standards:

- Production quality only: no rough demos or placeholder features presented as finished; safe defaults for beginners, explained advanced controls for professionals.
- Accessibility is a requirement: keyboard navigation, accessible names, visible focus, sufficient contrast, no meaning by color alone, specific error messages with a fix path.
- Every consequential action explains its risks, limitations, and recovery options; destructive or irreversible actions are confirmed, previewed where feasible, and backed up or undoable where feasible.
- Data safety: local-first storage, offline-capable core features, versioned data formats, atomic writes, tested migrations, and no silent data loss.
- Verification honesty: compatibility and readiness claims are labeled Verified, Partially verified, or Unverified; never claim a check that did not run.

Standing defaults (a project brief may override a specific default):

- Product-family look: the black/red aesthetic matching InstallScope is preferred, not mandatory.
- Rust is the default for new projects and for new components where it fits; existing stacks are preserved — this is not a rewrite mandate.
- Support as many Windows versions as makes sense for the project; consider Windows 10 support when feasible without materially extending development time. Never claim support that has not been verified.
- Status and task reports include a Progress % and an ETA whenever they can be estimated responsibly.
- Public documentation avoids competitor comparisons by default (internal research may name competitors; license attributions for bundled components are kept).
- License: MIT for SEAN-owned projects; forks retain their upstream license.
