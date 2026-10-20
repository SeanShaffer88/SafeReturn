# S1 + S2 Notes — production chunk store and engine API

**Date:** 2026-10-20 · **Slices:** S1 (commit `5cb2c54e`), S2 (commit `6f80fa27`) on top of the S0 skeleton.
**Status of the whole repo:** pre-alpha. Everything below is implemented and tested on synthetic data; nothing has touched a real Windows system volume yet (see "Not done / not verified").

---

## What was built

### S1 — production chunk store (`safereturn-core`)

- **Volume** (`src/volume.rs`): a self-describing backup directory — `volume.json` header, `chunks/` content-addressed records, `sets/` manifests, `catalog.json` index. New volumes refuse to overwrite an existing one.
- **Per-chunk pipeline**: plaintext chunk (fixed 1 MiB) → compress → XChaCha20-Poly1305 encrypt with a fresh random 192-bit nonce → store under `chunks/<2 hex>/<chunk id>`. The chunk id is the SHA-256 of the *plaintext*, so dedupe works before encryption and identical content is stored exactly once per volume (a chunk is written only if absent, which is also why a nonce can never be reused for the same data).
- **Chunk records carry algorithm ids** (record version, compression alg, encryption alg, nonce, plaintext length) so the format can evolve per-chunk without a volume migration. Reading a chunk re-hashes the decrypted plaintext and refuses anything that does not hash to its id — AEAD alone would not catch two valid records being swapped; the AAD (= chunk id) plus the hash check together do.
- **Backup sets** (`src/sets.rs`): `backup_tree` walks one or more roots (files or folders, recursive), records per-file path/size/mtime/whole-file SHA-256/chunk list in a per-set manifest stored on the volume. Symlinks are skipped *and recorded in the manifest* — never silently. An unreadable source file aborts the backup with a named error and **no set manifest is written**, so a partial backup never appears as a set (already-stored chunks stay as reusable dedupe content).
- **Level-1 verify over a whole set**: fetch + decrypt + decompress + re-hash every distinct chunk; the report gives files / chunks checked / plaintext bytes / every failure named by chunk id with a reason code (`missing`, `decrypt_failed`, `hash_mismatch`, `decompress_failed`, `bad_record`).
- **Catalog rebuild**: `rebuild_catalog` regenerates `catalog.json` by scanning set manifests only. `list_sets` also reads manifests directly — manifests are the source of truth, the catalog is a cache.
- The S1 prototype (`src/plain.rs`, unencrypted) is untouched; its tests still pin its behavior as the reference implementation.

### S2 — engine API + CLI

- **Engine** (`src/engine.rs`) wraps an unlocked volume and speaks the shell contract: jobs emit `JobStarted → JobProgress → JobFinished`; `list_backups` emits `BackupList` with facts from the manifests.
- **Restore plan tokens** (the contract's safety core): `plan_restore` computes exact destinations and per-file target states (absent / identical / differs), discloses overwrite count, and returns a single-use random token. `start_restore` requires that exact token, consumes it, **re-checks every target state before writing**, and refuses with `PlanStale` — writing nothing — if reality drifted from the preview. Unknown/reused/empty tokens are `InvalidPlanToken`. There is no other restore path in the engine API.
- **Level-2 File Rehearsal**: chosen files plus a deterministic pseudo-random sample (xorshift64* seeded by FNV-1a of the set id — same set and counts ⇒ same sample everywhere, so results are reproducible) are restored into a temp sandbox and hash-compared per file; the report names each file pass/fail with a reason. Sandbox is removed unless the caller keeps it.
- **Contract additions** (same slice, per repo rules): `ListBackups`, `PlanRestore { backup_id, target_dir, path }`, `StartRestore { plan_token }`, `StartFileRehearsal { backup_id, paths }`, events `BackupList`, `RestorePlanned(RestorePlan)` — with four new golden fixtures (`plan_restore`, `start_restore`, `backup_list`, `restore_planned`) and a §5 note in SHELL_CONTRACT.md.
- **CLI** (new crate `safereturn-cli`, binary `safereturn`): `init-volume`, `backup`, `list-sets`, `verify`, `restore-set`, `restore-file`, `rehearse-file`. Plain-language output; every error prints what happened, the fix path (from the core error), and a "What was not changed:" line. `--json` renders the contract events as JSON Lines; `--yes` is the CLI's way of confirming the exact restore plan it just printed (without it, a plan that would replace files stops and writes nothing). A separate crate so the core library stays free of argv/stdio/exit-code concerns.

## Format and crypto decisions (and why)

- **XChaCha20-Poly1305 over AES-256-GCM**: 192-bit random nonces make per-chunk random nonce generation safe without a counter discipline; no AES-NI assumption; one AEAD for chunk bodies and key wraps. The plan left this choice to the crypto work; it is now made and recorded in chunk records (encryption alg 1).
- **DEFLATE (flate2/miniz_oxide) instead of zstd — a deliberate, documented deviation.** The zstd crate compiles its C library via cc-rs, which fails this repo's mandated gate `cargo check --workspace --target x86_64-pc-windows-msvc` from a non-Windows host (`lib.exe` not found — reproduced locally before the decision). Compression alg id **1 is reserved for zstd**, deflate is 2, none is 0; records are self-describing, so adopting zstd later (when the check story changes) reads old chunks forever and needs no migration. Each chunk also falls back to *stored uncompressed* when deflate would expand it.
- **Argon2id** for the passphrase KDF (32 MiB, 3 iterations, 1 lane by default), with salt and parameters stored in the volume header so they can be raised for new volumes without breaking old ones.
- **Key management**: one random 256-bit volume key encrypts everything. It is stored in `volume.json` wrapped twice — once under an Argon2id-derived key (passphrase), once under the recovery key directly (the recovery key is already 256-bit random, so no KDF). The recovery-key file is plain text (`SAFERETURN RECOVERY KEY` header, grouped hex, volume id, and a 4-byte SHA-256 check code): a mistyped or damaged file is rejected as `BadRecoveryKey` ("the file is damaged"), while a well-formed key for a *different* volume fails as `UnlockFailed`. Authentication failures are deliberately indistinguishable beyond that — no oracle for guessing.
- **Hex, not base64**, in JSON metadata and the key file: no extra dependency, one canonical form, human-comparable.
- **Writes are temp-file + rename** for chunks, manifests, and restored files: a crash never leaves a torn file under a valid name.

## Tests (all in the workspace suite)

- Prototype: round-trip + corruption detection (unchanged, still passing).
- S1 (`tests/volume_sets.rs`, 6): multi-root tree round-trip byte-identical; dedupe (same content → one chunk; re-backup writes zero new chunks); corrupted chunk detected by verify *and* refused by restore, named by id; wrong passphrase rejected; recovery key opens a passphrase-created volume (and wrong-key vs garbage-file errors are distinct); catalog rebuild from manifests only, on a copied volume with the catalog deleted.
- Crypto/hex unit tests (4): wrap/unwrap, KDF determinism/sensitivity, key-file round-trip + typo detection, hex codec.
- S2 (`tests/engine.rs`, 5): token discipline (no token / wrong token / reused token all refused with *nothing written*; exact token executes the previewed overwrite); stale plan refused with nothing written; low-level restore still refuses unapproved overwrites; File Rehearsal passes, detects a damaged chunk and names it, sampling is deterministic; BackupList reports manifest facts.
- CLI (`tests/cli_smoke.rs`, 1 end-to-end + 1 unit): real binary — init → backup → list → verify → restore-file → restore-set refused without `--yes` and allowed with → rehearse → recovery-key-only open; wrong passphrase fails loudly with a "what was not changed" line.

Gate run before every push: `cargo fmt --all` (check clean), full `cargo test --workspace` (24 tests passing at S2), `cargo check --workspace --target x86_64-pc-windows-msvc` clean.

## Dependencies added (kept small, all reputable)

`flate2` (miniz_oxide backend only), `chacha20poly1305`, `argon2`, `getrandom`, `zeroize` — plus `safereturn-contract` as a path dependency of core and CLI, and `serde_json` in the CLI for `--json`. All pinned in the committed `Cargo.lock`.

## Not done / not verified (honest list)

- **No VSS wiring**: backups read the live filesystem, not a snapshot. S0.5 (probe runs elevated on a real Windows machine) is still open, and S3 (system-volume capture incl. EFI/Recovery) builds on it.
- **Not run on Windows hardware**: the workspace test suite is exercised by CI on `windows-latest`; the CLI has not been run interactively on a real Windows PC, and nothing here has touched a real system volume, BitLocker volume, or WinPE.
- Argon2id defaults were chosen from OWASP/RFC guidance, not benchmarked on target hardware.
- The CLI passphrase prompt does not disable terminal echo (documented in its usage); shells' protected-memory handling is contract-level, not implemented here.
- `catalog.json` is refreshed after each engine backup and rebuildable on demand; no flow *requires* it yet.
- Chunk size is fixed 1 MiB (content-defined chunking is Phase 2 per the plan); no incremental/differential sets, no retention/GFS, no scheduling — those are later slices.
- Set manifests and volume header are plaintext JSON on the volume: file *contents* are encrypted; file names, sizes, and times are visible to anyone holding the drive. That is the current design (it keeps manifests human-inspectable for recovery), stated here so it is a decision, not a surprise.
