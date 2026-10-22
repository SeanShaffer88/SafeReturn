# Safe Windows validation — October 21, 2026

Status: **Partially verified; pre-alpha.** This is evidence from a real standard-user Windows session, not a recovery certification.

Environment: Windows 11 Home, build 26300, x64; Rust MSVC toolchain. Source: `4854e57fff94730d1985b08a0108dd118872e3ca`. No elevation, physical-disk writes, recovery-media creation, or boot tests were performed.

## Completed

- `cargo fmt --all --check`: passed.
- `cargo test --workspace`: 138 passed, zero failed, three intentionally ignored live tests.
- `cargo check --workspace --all-targets --target x86_64-pc-windows-msvc`: passed, including Windows-only test compilation.
- `cargo build -p safereturn-cli`: passed.
- The five Windows CLI integration tests executed real child processes against synthetic temporary trees: encrypted volume initialization; backup/list/verify; file and set restore; restore confirmation refusal; file rehearsal; folder-backed whole-system restore simulation; system-fact/snapshot flag handling; media plan-token discipline; and media-tree tamper reporting.
- Engine tests exercised corrupted chunks, stale/mismatched plan tokens, overwrite refusal, interrupted/error paths and recovery-card facts. Their simulation/fake-executor results do not establish live recovery behavior.

The test files are `crates/safereturn-cli/tests/cli_smoke.rs` and the integration suites under `safereturn-core`, `safereturn-vss`, `safereturn-shell` and `safereturn-pe-shell`.

## Unverified gates

| Gate | Why still open | Required next evidence |
| --- | --- | --- |
| Real VSS begin/capture/release | Live test intentionally ignored; no elevated session | Approved elevated Windows session, SDK helper, real locked-file snapshot and cleanup verification; follow S3 notes |
| Recovery USB creation and boot | No disposable target selected | Explicitly identified disposable device, media verification and actual WinPE boot |
| Whole-disk restore | No disposable disk/VM selected; current real executor also refuses execution | Implement/review the executor, then test only against an explicitly selected disposable target |
| VM boot rehearsal | No Hyper-V test VM available in this Home session | Isolated compatible VM and observed boot; retain source of the observation |
| Pro, Windows 10, ARM64, accessibility | Not exercised here | Separate edition/device and assistive-technology matrix |

User-approved scope for this session was safe tests on the existing PC and explicit documentation of hardware-only gaps. No live flags (`SR_VSS_LIVE`, `SR_MEDIA_LIVE`, `SR_RESTORE_LIVE`) were enabled. Do not label these results a successful whole-PC recovery.
