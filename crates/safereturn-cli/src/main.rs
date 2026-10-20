//! SafeReturn headless CLI — the support/advanced shell. It renders the
//! engine's contract events as plain text (or, with `--json`, as the
//! exact contract JSON Lines the other shells consume). All decisions —
//! what a backup contains, whether a restore may proceed — are the
//! engine's; this file only parses arguments, prints, and sets exit
//! codes.
//!
//! Exit codes: 0 = done (and, for verify/rehearse, passed),
//! 1 = the operation failed or a check did not pass,
//! 2 = usage error or a confirmation that was not given.
//!
//! Passphrase sources, in order: `--passphrase <p>` (visible in shell
//! history — fine for scripts/tests, not recommended interactively),
//! the SAFERETURN_PASSPHRASE environment variable, or an interactive
//! prompt. Known limitation of this support CLI: the prompt does not
//! disable terminal echo.

use safereturn_contract::{Event, JobOutcome, WireMessage};
use safereturn_core::crypto::{format_recovery_key, parse_recovery_key};
use safereturn_core::*;
use safereturn_vss::SnapshotSession;
use std::io::Write;
use std::path::{Path, PathBuf};

const EXIT_OK: i32 = 0;
const EXIT_FAIL: i32 = 1;
const EXIT_USAGE: i32 = 2;

#[derive(Default)]
struct Options {
    passphrase: Option<String>,
    recovery_key_file: Option<PathBuf>,
    recovery_key_out: Option<PathBuf>,
    json: bool,
    yes: bool,
    keep_sandbox: bool,
    sample: usize,
    files: Vec<String>,
    /// `backup --snapshot <VOL>`: capture from a VSS snapshot of VOL.
    snapshot: Option<String>,
    /// `backup --allow-live`: explicitly permit falling back to a live
    /// capture when the snapshot cannot be taken (loudly warned, and
    /// the set is recorded as a live capture).
    allow_live: bool,
    /// `backup --system-facts <file>`: attach a gatherer's facts JSON.
    system_facts: Option<PathBuf>,
    /// `backup --esp-root <dir>`: fresh ESP listing for the facts.
    esp_root: Option<PathBuf>,
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(|s| s.as_str()) else {
        print_usage();
        return EXIT_USAGE;
    };
    if cmd == "--help" || cmd == "-h" || cmd == "help" {
        print_usage();
        return EXIT_OK;
    }
    // `media` is a subcommand group with its own flags (S4); it is
    // dispatched before the shared option parser.
    if cmd == "media" {
        return run_media(&args[1..]);
    }
    // `restore-system` is a subcommand group with its own flags
    // (S5); same treatment.
    if cmd == "restore-system" {
        return run_restore_system(&args[1..]);
    }
    // `rehearse-boot` (L3 Boot Rehearsal, S6) likewise.
    if cmd == "rehearse-boot" {
        return run_rehearse_boot(&args[1..]);
    }
    // `recovery-card` (S6) is a standalone generator with its own
    // fact flags; it needs no volume unless --volume is given.
    if cmd == "recovery-card" {
        return run_recovery_card(&args[1..]);
    }
    let (pos, opts) = match parse_options(&args[1..]) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("Error: {msg}");
            print_usage();
            return EXIT_USAGE;
        }
    };
    let result = match cmd {
        "init-volume" => cmd_init_volume(&pos, &opts),
        "backup" => cmd_backup(&pos, &opts),
        "list-sets" => cmd_list_sets(&pos, &opts),
        "verify" => cmd_verify(&pos, &opts),
        "restore-set" => cmd_restore(&pos, &opts, None),
        "restore-file" => cmd_restore_file(&pos, &opts),
        "rehearse-file" => cmd_rehearse(&pos, &opts),
        other => {
            eprintln!("Error: unknown command '{other}'.");
            print_usage();
            EXIT_USAGE
        }
    };
    result
}

fn print_usage() {
    eprintln!(
        "SafeReturn — backup that proves it can bring your files back.

Usage:
  safereturn init-volume <folder> [--recovery-key-out <file>]
  safereturn backup <volume> <label> <folder-or-file>... [--snapshot <VOL>] [--allow-live] [--system-facts <file>] [--esp-root <dir>]
  safereturn list-sets <volume>
  safereturn verify <volume> <set-id>
  safereturn restore-set <volume> <set-id> <target-folder> [--yes]
  safereturn restore-file <volume> <set-id> <path-in-set> <target-folder> [--yes]
  safereturn rehearse-file <volume> <set-id> [--file <path-in-set>]... [--sample <n>]
  safereturn media plan --target-size <bytes> --serial-suffix <last4> --winpe-wim <file> [--removable] [--override-non-removable] [--payload <file>=<media/path>]... [--driver <inf>]...
  safereturn media create --plan-token <id from media plan> <same target/winpe flags as the plan> [--target-spec <F:>]
  safereturn media verify <media-root> [--data-root <ntfs-partition-root>]
  safereturn restore-system plan <volume> <set-id> --target-size <bytes> --serial-suffix <last4> --os-root <set root> --esp-root <set root> --firmware <uefi|bios> [--target-model <model>] [--removable] [--plan-out <file>]
  safereturn restore-system execute <volume> <set-id> --plan-token <id from restore-system plan> <same target flags as the plan> (--simulate <folder> | [--disk-index <n>] [--work-dir <folder>])
  safereturn restore-system verify <applied-root> --plan <plan file from restore-system plan --plan-out>
  safereturn rehearse-boot plan <volume> <set-id> --staging <folder> <same target flags as restore-system plan> [--hyperv] [--edition <label>]
  safereturn rehearse-boot run <volume> <set-id> --staging <folder> <same target flags as restore-system plan> [--hyperv] [--edition <label>]
  safereturn rehearse-boot report <staging-folder> [--record-vm-boot <what happened> --source <who/what observed it>]
  safereturn recovery-card --out <file> [--format <html|text>] --pc <description> --backup-model <model> --backup-serial <last4> [--backup-label <label>] [--media-model <model> --media-serial <last4> [--media-label <label>]] [--boot-key <key>] [--password-hint-location <text>] [--volume <folder> [--passphrase <pw> | --recovery-key <file>] [--set <set-id>]] [--rehearsal-staging <folder>]

Credentials (every command except init-volume):
  --passphrase <p>        passphrase (or set SAFERETURN_PASSPHRASE, or be prompted)
  --recovery-key <file>   open the volume with a saved recovery key file instead

Snapshot backups (Windows, elevated): --snapshot C:\\ captures from a
VSS snapshot of that volume, so every folder you list must be on it. If
the snapshot cannot be taken, the backup STOPS and nothing is written —
a live capture is substituted only when --allow-live is passed, with a
loud warning, and the set is then recorded as a live capture.

System facts: --system-facts <file> attaches a gatherer's facts JSON to
the new set's manifest. With --esp-root <dir>, the facts' ESP listing
is replaced by a fresh listing of <dir>.

Recovery media (S4): `media plan` computes the layout for a target from
the facts you pass (device size, serial suffix, WinPE .wim) and prints
the plan plus its plan id — planning writes nothing. `media create`
recomputes the plan from the same flags and only proceeds when
--plan-token matches that plan id exactly; it prints the plan and the
erase warning first. Creating media ERASES the target device. Real
creation is Windows-only and additionally requires SR_MEDIA_LIVE=1.
`media verify` checks built media anywhere: payload hashes, boot
files, and the boot-test marker (fresh media honestly reports
NOT TESTED YET).

Whole-PC restore (S5): `restore-system plan` computes the GPT layout
for restoring a system set onto a target disk from the facts you pass
(disk size, serial suffix, firmware mode, and which of the set's
recorded roots is the OS volume and which is the ESP capture) and
prints the full plan — layout with the source of every size, file
counts, warnings, and the exact boot commands it would run — plus its
plan id. Planning touches nothing. `restore-system execute`
recomputes the plan from the same flags and only proceeds when
--plan-token matches that plan id exactly; it prints the plan and the
erase warning first. Executing ERASES the target disk. With
--simulate <folder> it applies the plan to a folder-backed fake disk
instead — the documented test path, works on any OS — and verifies
the result. Real execution is Windows-only and gated
(SR_RESTORE_LIVE=1); this build's Windows executor renders the
diskpart script and command lines for inspection and refuses to run
them (see docs/S5_NOTES.md). `restore-system verify` re-checks an
applied tree (e.g. a simulation folder) against a saved plan file:
files in place, boot files present, WinRE present — and boot
registration reported NOT VERIFIED, because file inspection cannot
prove it.

Boot Rehearsal (L3, S6): `rehearse-boot plan` computes the same plan
a whole-PC restore would use, but for a staging folder, and prints
the guided checklist for the machine-only VM steps (Hyper-V
PowerShell commands as data when --hyperv is stated; the
validation-only path otherwise). `rehearse-boot run` applies the
plan into the staging folder through the same restore path a real
restore uses, verifies every file partition by partition, and
writes safereturn-rehearsal.json there. A rehearsal NEVER claims a
boot: its report says \"not boot-tested\" until the on-machine step
records the VM boot outcome with `rehearse-boot report <folder>
--record-vm-boot \"<what happened>\" --source \"<who/what saw it>\"`.
`rehearse-boot report` prints the stored record. Nothing in a
rehearsal touches a real disk.

Recovery Card (S6): `recovery-card` generates the printable card
(HTML by default when --out ends in .html, else plain text; force
with --format). The facts are inputs, stated by you: which PC, the
backup drive (model + last 4 of its serial + its label), the
recovery USB if one exists, and the PC's boot-menu key if you know
it (unknown prints a generic vendor key table, marked as guidance).
--password-hint-location takes the LOCATION where your password is
kept (\"in the fire safe\") — the card has no way to hold a password
and every card prints \"This card never contains your password.\"
With --volume (and its unlock flags) the newest backup (or --set)
fills the last-backup line; --rehearsal-staging fills the last
rehearsal line from a Boot Rehearsal record.

Other flags: --json (contract JSON events), --yes (confirm a restore plan
that replaces files), --keep-sandbox (rehearse-file: keep the sandbox)."
    );
}

fn parse_options(args: &[String]) -> std::result::Result<(Vec<String>, Options), String> {
    let mut pos = Vec::new();
    let mut opts = Options {
        sample: 8,
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let take_value = |i: &mut usize| -> std::result::Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag {arg} needs a value"))
        };
        match arg.as_str() {
            "--passphrase" => opts.passphrase = Some(take_value(&mut i)?),
            "--recovery-key" => opts.recovery_key_file = Some(PathBuf::from(take_value(&mut i)?)),
            "--recovery-key-out" => {
                opts.recovery_key_out = Some(PathBuf::from(take_value(&mut i)?))
            }
            "--file" => opts.files.push(take_value(&mut i)?),
            "--sample" => {
                let v = take_value(&mut i)?;
                opts.sample = v
                    .parse()
                    .map_err(|_| format!("--sample needs a number, got '{v}'"))?;
            }
            "--snapshot" => opts.snapshot = Some(take_value(&mut i)?),
            "--system-facts" => opts.system_facts = Some(PathBuf::from(take_value(&mut i)?)),
            "--esp-root" => opts.esp_root = Some(PathBuf::from(take_value(&mut i)?)),
            "--allow-live" => opts.allow_live = true,
            "--json" => opts.json = true,
            "--yes" => opts.yes = true,
            "--keep-sandbox" => opts.keep_sandbox = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag '{flag}'")),
            _ => pos.push(arg.clone()),
        }
        i += 1;
    }
    Ok((pos, opts))
}

// ---------------------------------------------------------------------------
// Credentials + engine setup

fn resolve_passphrase(opts: &Options, confirm: bool) -> std::result::Result<String, String> {
    if let Some(p) = &opts.passphrase {
        return Ok(p.clone());
    }
    if let Ok(p) = std::env::var("SAFERETURN_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    let p = prompt_line("Backup passphrase: ")
        .ok_or_else(|| "could not read a passphrase".to_string())?;
    if confirm {
        let again = prompt_line("Repeat passphrase: ")
            .ok_or_else(|| "could not read a passphrase".to_string())?;
        if p != again {
            return Err("the two passphrases did not match — nothing was created".to_string());
        }
    }
    Ok(p)
}

fn prompt_line(prompt: &str) -> Option<String> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok()?;
    Some(line.trim_end_matches(['\n', '\r']).to_string())
}

fn unlock(volume_dir: &str, opts: &Options) -> std::result::Result<UnlockedVolume, CoreError> {
    let locked = Volume::open(volume_dir)?;
    if let Some(key_file) = &opts.recovery_key_file {
        let text = std::fs::read_to_string(key_file).map_err(|e| CoreError::Io {
            path: Some(key_file.clone()),
            source: e,
        })?;
        let key = parse_recovery_key(&text)?;
        locked.unlock_with_recovery_key(&key)
    } else {
        let passphrase = resolve_passphrase(opts, false).map_err(|msg| CoreError::Io {
            path: None,
            source: std::io::Error::other(msg),
        })?;
        locked.unlock_with_passphrase(&passphrase)
    }
}

fn report_error(err: &CoreError) -> i32 {
    eprintln!("Error: {err}");
    eprintln!("What was not changed: {}", what_was_not_changed(err));
    EXIT_FAIL
}

fn what_was_not_changed(err: &CoreError) -> &'static str {
    match err {
        CoreError::UnlockFailed
        | CoreError::BadRecoveryKey { .. }
        | CoreError::NotAVolume { .. } => {
            "Nothing — the volume was not opened and nothing was written."
        }
        CoreError::VolumeAlreadyExists { .. } => "Nothing — the existing volume is untouched.",
        CoreError::InvalidPlanToken | CoreError::PlanStale { .. } | CoreError::RestoreConflict { .. } => {
            "Nothing was restored or overwritten."
        }
        CoreError::SourceUnreadable { .. } => {
            "No backup set was saved. (Chunks already copied stay on the volume as reusable content; no partial set exists.)"
        }
        CoreError::CaptureRootOutsideVolume { .. } => {
            "No backup set was saved. (Chunks already copied stay on the volume as reusable content; no partial set exists.)"
        }
        CoreError::InvalidSystemFacts { .. } | CoreError::SystemFactsAlreadyPresent { .. } => {
            "The backup set itself is untouched — no facts were attached or changed."
        }
        CoreError::MediaTargetTooSmall { .. }
        | CoreError::MediaPayloadTooLarge { .. }
        | CoreError::MediaTargetNotRemovable
        | CoreError::MediaSourceMissing { .. }
        | CoreError::MediaInvalidFacts { .. }
        | CoreError::MediaInvalidPlanToken
        | CoreError::MediaPlanStale { .. }
        | CoreError::UnsupportedPlatform { .. }
        | CoreError::LiveNotEnabled { .. } => {
            "Nothing was written to any device — no media was created or erased."
        }
        CoreError::SystemRestoreNotASystemSet { .. }
        | CoreError::SystemRestoreFirmwareUnsupported { .. }
        | CoreError::SystemRestoreFirmwareUnknown { .. }
        | CoreError::SystemRestoreFirmwareMismatch { .. }
        | CoreError::SystemRestoreTargetTooSmall { .. }
        | CoreError::SystemRestoreInvalidFacts { .. }
        | CoreError::SystemRestoreBootFilesMissing { .. }
        | CoreError::SystemRestoreInvalidPlanToken
        | CoreError::SystemRestorePlanStale { .. }
        | CoreError::SystemRestoreLiveNotEnabled { .. } => {
            "Nothing was touched — no disk was erased, partitioned, or written."
        }
        CoreError::SystemRestoreExecutorNotReady { .. } => {
            "Nothing was erased. (The executor wrote only its inspection files — the diskpart script and the boot command list.)"
        }
        _ => "Nothing was changed by this operation.",
    }
}

// ---------------------------------------------------------------------------
// Event rendering (this is the CLI's shell job: presentation only)

fn phase_label(id: &str) -> &str {
    match id {
        "phase.copying_files" => "Copying files",
        "phase.checking_backup" => "Checking backup chunks",
        "phase.restoring_files" => "Restoring files",
        "phase.file_rehearsal" => "Restoring sample files to a sandbox",
        "phase.building_media" => "Building recovery media",
        "phase.restoring_system" => "Restoring system files",
        "phase.boot_rehearsal" => "Boot Rehearsal: applying the restore to a staging folder",
        other => other,
    }
}

fn make_sink(json: bool) -> impl FnMut(Event) {
    move |ev: Event| {
        if json {
            let msg = WireMessage::Event(ev);
            println!(
                "{}",
                serde_json::to_string(&msg).unwrap_or_else(|_| "{}".to_string())
            );
            return;
        }
        match ev {
            Event::JobProgress {
                phase_id,
                done,
                total,
                unit,
                ..
            } => {
                eprintln!("  {}: {done}/{total} {unit}", phase_label(&phase_id));
            }
            Event::JobFinished {
                outcome,
                summary_id,
                ..
            } => {
                let mark = match outcome {
                    JobOutcome::Succeeded => "done",
                    JobOutcome::Failed => "FAILED",
                    JobOutcome::Cancelled => "cancelled",
                };
                eprintln!("  [{mark}] {summary_id}");
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Commands

fn cmd_init_volume(pos: &[String], opts: &Options) -> i32 {
    let Some(dir) = pos.first() else {
        eprintln!("Error: init-volume needs a folder path.");
        return EXIT_USAGE;
    };
    let key_out = opts
        .recovery_key_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("safereturn-recovery-key.txt"));
    if key_out.exists() {
        eprintln!(
            "Error: {} already exists — refusing to overwrite a recovery key file. Pick another --recovery-key-out path.",
            key_out.display()
        );
        eprintln!("What was not changed: Nothing — no volume was created.");
        return EXIT_FAIL;
    }
    let passphrase = match resolve_passphrase(
        opts,
        opts.passphrase.is_none() && std::env::var_os("SAFERETURN_PASSPHRASE").is_none(),
    ) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_FAIL;
        }
    };
    match Volume::create(dir, &passphrase, now_unix()) {
        Ok((locked, recovery_key)) => {
            let text = format_recovery_key(&locked.header().volume_id, &recovery_key);
            if let Err(e) = write_key_file(&key_out, &text) {
                eprintln!("Error: volume created at {dir}, but the recovery key could not be written: {e}");
                eprintln!("What was not changed: the volume exists, but without a recovery key file the passphrase is the ONLY way in. Re-run init-volume for a fresh volume in another folder once you can write the key file.");
                return EXIT_FAIL;
            }
            println!("Backup volume created at {dir}");
            println!("Volume ID: {}", locked.header().volume_id);
            println!("Recovery key written to {}", key_out.display());
            println!(
                "Move that recovery key file somewhere safe (a USB stick or printed copy, ideally not only on this PC). \
                 It opens this volume if you ever forget the passphrase — and anyone who finds it can open the volume too."
            );
            EXIT_OK
        }
        Err(e) => report_error(&e),
    }
}

fn write_key_file(path: &PathBuf, text: &str) -> std::io::Result<()> {
    std::fs::write(path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn cmd_backup(pos: &[String], opts: &Options) -> i32 {
    if pos.len() < 3 {
        eprintln!(
            "Error: backup needs <volume> <label> and at least one folder or file to back up."
        );
        return EXIT_USAGE;
    }
    let unlocked = match unlock(&pos[0], opts) {
        Ok(u) => u,
        Err(e) => return report_error(&e),
    };
    let roots: Vec<PathBuf> = pos[2..].iter().map(PathBuf::from).collect();

    // Snapshot session (S3): taken before the engine runs and held for
    // exactly the backup's duration. The honesty rule: if the snapshot
    // cannot be taken, the backup stops and nothing is written — a
    // live capture is substituted ONLY under an explicit --allow-live,
    // with warnings, and the set is then recorded as a live capture.
    let mut snapshot_session: Option<SnapshotSession> = None;
    let mut mapped: Option<MappedSource> = None;
    if let Some(volume) = &opts.snapshot {
        match SnapshotSession::begin(volume) {
            Ok(session) => {
                let device = session.device_root().unwrap_or("(unknown device)");
                eprintln!("Snapshot: capturing from a VSS snapshot of {volume} at {device}.");
                eprintln!(
                    "If reading the snapshot fails, the backup stops — a live capture is never substituted silently."
                );
                mapped = Some(MappedSource::new(
                    volume.clone(),
                    PathBuf::from(device.to_string()),
                ));
                snapshot_session = Some(session);
            }
            Err(e) => {
                if opts.allow_live {
                    eprintln!("WARNING: the snapshot could not be taken: {e}");
                    eprintln!(
                        "WARNING: --allow-live was given, so this backup reads the LIVE disk instead. \
                         Files that change or are locked during the backup may be captured inconsistently. \
                         The set will be recorded as a live capture — it is NOT a snapshot backup."
                    );
                } else {
                    eprintln!("Error: {e}");
                    eprintln!(
                        "What was not changed: Nothing — no backup set was saved, and no live capture was substituted. \
                         Run without --snapshot for a live backup, pass --allow-live to permit one here, \
                         or fix the snapshot problem (snapshots need Windows, an elevated prompt, and the VSS service running)."
                    );
                    return EXIT_FAIL;
                }
            }
        }
    }

    let mut engine = Engine::new(unlocked);
    let mut sink = make_sink(opts.json);
    let backup_result = match &mapped {
        Some(m) => engine.start_backup_with_source(&pos[1], &roots, m, &mut sink),
        None => engine.start_backup(&pos[1], &roots, &mut sink),
    };
    let outcome = match backup_result {
        Ok(o) => {
            // Finish (BackupComplete + delete snapshot) only a backup
            // that succeeded; a failed backup aborts its snapshot.
            if let Some(session) = snapshot_session {
                if let Err(e) = session.finish() {
                    eprintln!(
                        "Warning: backup set {} WAS saved, but the snapshot could not be cleaned up: {e}",
                        o.manifest.set_id
                    );
                    eprintln!(
                        "A leftover shadow copy may remain on the PC — check `vssadmin list shadows` and delete it there if it is listed."
                    );
                    print_backup_summary(&o, opts);
                    return EXIT_FAIL;
                }
            }
            o
        }
        Err(e) => {
            if let Some(session) = snapshot_session {
                let _ = session.abort();
            }
            return report_error(&e);
        }
    };

    print_backup_summary(&outcome, opts);

    // System facts (S3): attach the gatherer's facts to the new set.
    if let Some(facts_path) = &opts.system_facts {
        match attach_facts(&engine, &outcome.manifest.set_id, facts_path, opts) {
            Ok(()) => {
                if !opts.json {
                    println!(
                        "System facts attached to set {} (recorded in the set manifest).",
                        outcome.manifest.set_id
                    );
                }
            }
            Err(e) => return report_error(&e),
        }
    }
    EXIT_OK
}

fn print_backup_summary(outcome: &BackupOutcome, opts: &Options) {
    if opts.json {
        return;
    }
    let m = &outcome.manifest;
    println!("Backup finished.");
    println!("set_id: {}", m.set_id);
    println!(
        "Capture: {}",
        match m.capture_mode {
            CaptureMode::VssSnapshot => "VSS snapshot (one point in time)",
            CaptureMode::Live => "live filesystem (files read as they were found)",
        }
    );
    println!(
        "Files backed up: {} ({} bytes)",
        m.files.len(),
        m.total_bytes()
    );
    println!(
        "New chunks written: {}; already on the volume: {}",
        outcome.chunks_written, outcome.chunks_reused
    );
    if m.skipped.is_empty() {
        println!("Skipped: nothing");
    } else {
        println!("Skipped:");
        for s in &m.skipped {
            println!("  {} — {}", s.path, s.reason);
        }
    }
}

/// Load a system-facts JSON file and attach it to a set (S3). With
/// `--esp-root`, the facts' ESP listing is first replaced by a fresh
/// listing of that root (stated on stderr, never silently).
fn attach_facts(
    engine: &Engine,
    set_id: &str,
    facts_path: &Path,
    opts: &Options,
) -> std::result::Result<(), CoreError> {
    let text = std::fs::read_to_string(facts_path).map_err(|e| CoreError::Io {
        path: Some(facts_path.to_path_buf()),
        source: e,
    })?;
    let mut facts = parse_system_facts(&text)?;
    if let Some(esp_root) = &opts.esp_root {
        eprintln!(
            "ESP listing: taken fresh from {} (replaces the facts file's ESP entry).",
            esp_root.display()
        );
        facts.esp_files = esp_fact(
            esp_root,
            format!("ESP root supplied with --esp-root: {}", esp_root.display()),
        );
        facts.validate()?;
    }
    attach_system_facts(engine.volume(), set_id, facts)?;
    Ok(())
}

fn cmd_list_sets(pos: &[String], opts: &Options) -> i32 {
    let Some(dir) = pos.first() else {
        eprintln!("Error: list-sets needs a volume folder.");
        return EXIT_USAGE;
    };
    let unlocked = match unlock(dir, opts) {
        Ok(u) => u,
        Err(e) => return report_error(&e),
    };
    let engine = Engine::new(unlocked);
    let mut sink = make_sink(opts.json);
    match engine.list_backups(&mut sink) {
        Ok(backups) => {
            if !opts.json {
                if backups.is_empty() {
                    println!("No backup sets on this volume yet.");
                }
                for b in &backups {
                    println!(
                        "{}  {}  {}  {} files, {}",
                        b.backup_id,
                        b.label,
                        fmt_datetime(b.created_unix),
                        b.file_count,
                        format_bytes(b.total_bytes)
                    );
                }
            }
            EXIT_OK
        }
        Err(e) => report_error(&e),
    }
}

fn cmd_verify(pos: &[String], opts: &Options) -> i32 {
    if pos.len() < 2 {
        eprintln!("Error: verify needs <volume> and <set-id>.");
        return EXIT_USAGE;
    }
    let unlocked = match unlock(&pos[0], opts) {
        Ok(u) => u,
        Err(e) => return report_error(&e),
    };
    let mut engine = Engine::new(unlocked);
    let mut sink = make_sink(opts.json);
    match engine.start_verify(&pos[1], &mut sink) {
        Ok(report) => {
            if !opts.json {
                println!(
                    "Quick Check of set {}: {} files, {} chunks, {} of backup data",
                    report.set_id,
                    report.files,
                    report.chunks_checked,
                    format_bytes(report.plaintext_bytes)
                );
                if report.passed() {
                    println!(
                        "Result: every chunk is intact — the backup matches what was written."
                    );
                } else {
                    println!(
                        "Result: {} of {} chunks are damaged or missing:",
                        report.failures.len(),
                        report.chunks_checked
                    );
                    for f in &report.failures {
                        println!("  DAMAGED chunk {} ({})", f.chunk_id, f.reason);
                    }
                    println!("Re-run the backup from the original files; if this repeats, the backup drive may be failing.");
                }
            }
            if report.passed() {
                EXIT_OK
            } else {
                EXIT_FAIL
            }
        }
        Err(e) => report_error(&e),
    }
}

fn cmd_restore(pos: &[String], opts: &Options, only_path: Option<&str>) -> i32 {
    // pos: volume, set-id, [path-in-set for restore-file], target-dir
    let (volume_dir, set_id, target_dir) = match (pos.len(), only_path) {
        (3, None) => (&pos[0], &pos[1], &pos[2]),
        (4, Some(_)) => (&pos[0], &pos[1], &pos[3]),
        _ => {
            eprintln!("Error: restore needs <volume> <set-id> [<path-in-set>] <target-folder>.");
            return EXIT_USAGE;
        }
    };
    let unlocked = match unlock(volume_dir, opts) {
        Ok(u) => u,
        Err(e) => return report_error(&e),
    };
    let mut engine = Engine::new(unlocked);
    let mut sink = make_sink(opts.json);
    let plan = match engine.plan_restore(set_id, &PathBuf::from(target_dir), only_path, &mut sink) {
        Ok(p) => p,
        Err(e) => return report_error(&e),
    };
    if !opts.json {
        println!("Restore plan: {}", plan.target_summary);
    }
    if plan.overwrite_count > 0 && !opts.yes {
        eprintln!(
            "This plan replaces {} existing file(s). Nothing was written. If that is exactly what you confirmed, re-run with --yes.",
            plan.overwrite_count
        );
        return EXIT_USAGE;
    }
    match engine.start_restore(&plan.plan_token, &mut sink) {
        Ok(outcome) => {
            if !opts.json {
                println!(
                    "Restored {} file(s) ({}). {} file(s) were already identical and left as they were.",
                    outcome.files_written,
                    format_bytes(outcome.bytes_written),
                    outcome.files_already_identical
                );
            }
            EXIT_OK
        }
        Err(e) => report_error(&e),
    }
}

fn cmd_restore_file(pos: &[String], opts: &Options) -> i32 {
    if pos.len() != 4 {
        eprintln!("Error: restore-file needs <volume> <set-id> <path-in-set> <target-folder>.");
        return EXIT_USAGE;
    }
    let path = pos[2].clone();
    cmd_restore(pos, opts, Some(&path))
}

fn cmd_rehearse(pos: &[String], opts: &Options) -> i32 {
    if pos.len() < 2 {
        eprintln!("Error: rehearse-file needs <volume> and <set-id>.");
        return EXIT_USAGE;
    }
    let unlocked = match unlock(&pos[0], opts) {
        Ok(u) => u,
        Err(e) => return report_error(&e),
    };
    let mut engine = Engine::new(unlocked);
    let mut sink = make_sink(opts.json);
    match engine.start_file_rehearsal(
        &pos[1],
        &opts.files,
        opts.sample,
        opts.keep_sandbox,
        &mut sink,
    ) {
        Ok(report) => {
            if !opts.json {
                for entry in &report.entries {
                    if entry.passed {
                        println!("PASS {} — {}", entry.path, entry.detail);
                    } else {
                        println!("FAIL {} — {}", entry.path, entry.detail);
                    }
                }
                println!(
                    "File Rehearsal: {} of {} files restored into a sandbox and matched the backup record.",
                    report.passed_count(),
                    report.entries.len()
                );
                if report.kept_sandbox {
                    println!("Sandbox kept at {}", report.sandbox.display());
                }
                if !report.passed() {
                    println!("A failed rehearsal means a real restore of those files would fail too — re-run the backup from the original files.");
                }
            }
            if report.passed() {
                EXIT_OK
            } else {
                EXIT_FAIL
            }
        }
        Err(e) => report_error(&e),
    }
}

// ---------------------------------------------------------------------------
// Recovery media (S4): plan / create / verify.
//
// The CLI is stateless between runs, so its confirmation token is the
// plan's deterministic id: `media plan` prints it, `media create`
// recomputes the plan from the same flags and refuses unless the
// supplied --plan-token equals that id. The guarantee the user cares
// about is identical to the engine's token flow: what gets created is
// exactly the plan that was printed — different facts, no create.
// (In-process shells use the engine's random single-use tokens.)
//
// The payload defaults to this CLI's own executable staged as
// safereturn/safereturn.exe when no --payload is given: the media
// needs *a* recovery program on it, and in this support CLI the
// honest stand-in is the tool itself. Real shells pass the Win32 PE
// shell + engine payload explicitly.

#[derive(Default)]
struct MediaOptions {
    target_size: Option<u64>,
    removable: bool,
    override_non_removable: bool,
    serial_suffix: Option<String>,
    target_model: Option<String>,
    winpe_wim: Option<PathBuf>,
    adk_version: Option<String>,
    drivers: Vec<String>,
    /// (source file, media-relative destination) pairs.
    payload: Vec<(PathBuf, String)>,
    plan_token: Option<String>,
    target_spec: Option<String>,
    data_root: Option<PathBuf>,
    json: bool,
}

fn run_media(args: &[String]) -> i32 {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        eprintln!("Error: media needs a subcommand: plan, create, or verify.");
        print_usage();
        return EXIT_USAGE;
    };
    let (pos, mopts) = match parse_media_options(&args[1..]) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_USAGE;
        }
    };
    match sub {
        "plan" => cmd_media_plan(&mopts),
        "create" => cmd_media_create(&mopts),
        "verify" => cmd_media_verify(&pos, &mopts),
        other => {
            eprintln!("Error: unknown media subcommand '{other}' — use plan, create, or verify.");
            EXIT_USAGE
        }
    }
}

fn parse_media_options(
    args: &[String],
) -> std::result::Result<(Vec<String>, MediaOptions), String> {
    let mut pos = Vec::new();
    let mut o = MediaOptions::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let take_value = |i: &mut usize| -> std::result::Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag {arg} needs a value"))
        };
        match arg.as_str() {
            "--target-size" => {
                let v = take_value(&mut i)?;
                o.target_size = Some(
                    v.parse()
                        .map_err(|_| format!("--target-size needs a byte count, got '{v}'"))?,
                );
            }
            "--removable" => o.removable = true,
            "--override-non-removable" => o.override_non_removable = true,
            "--serial-suffix" => o.serial_suffix = Some(take_value(&mut i)?),
            "--target-model" => o.target_model = Some(take_value(&mut i)?),
            "--winpe-wim" => o.winpe_wim = Some(PathBuf::from(take_value(&mut i)?)),
            "--adk-version" => o.adk_version = Some(take_value(&mut i)?),
            "--driver" => o.drivers.push(take_value(&mut i)?),
            "--payload" => {
                let v = take_value(&mut i)?;
                let (src, rel) = v
                    .split_once('=')
                    .ok_or_else(|| format!("--payload needs <file>=<media/path>, got '{v}'"))?;
                o.payload.push((PathBuf::from(src), rel.to_string()));
            }
            "--plan-token" => o.plan_token = Some(take_value(&mut i)?),
            "--target-spec" => o.target_spec = Some(take_value(&mut i)?),
            "--data-root" => o.data_root = Some(PathBuf::from(take_value(&mut i)?)),
            "--json" => o.json = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag '{flag}'")),
            _ => pos.push(arg.clone()),
        }
        i += 1;
    }
    Ok((pos, o))
}

/// Build the media facts from the flags — the facts are what the
/// operator states and what this machine can measure (the .wim and
/// payload files are read and hashed here, in the shell, because the
/// engine plans from facts, not from paths it should not trust).
fn build_media_facts(mopts: &MediaOptions) -> std::result::Result<MediaFacts, String> {
    let size = mopts
        .target_size
        .ok_or("--target-size <bytes> is required (the target device's size)")?;
    let serial = mopts
        .serial_suffix
        .clone()
        .ok_or("--serial-suffix <last 4 of the device serial> is required")?;
    let wim = mopts.winpe_wim.clone().ok_or(
        "--winpe-wim <file> is required (the winpe.wim from your ADK WinPE working files)",
    )?;
    let (wim_present, wim_size) = match std::fs::metadata(&wim) {
        Ok(m) if m.is_file() => (true, m.len()),
        _ => (false, 0),
    };
    let mut payload = Vec::new();
    if mopts.payload.is_empty() {
        // Default payload: this executable, staged under safereturn/.
        let exe = std::env::current_exe().map_err(|e| {
            format!("could not locate this executable for the default payload: {e}")
        })?;
        let data = std::fs::read(&exe)
            .map_err(|e| format!("could not read {} for the payload: {e}", exe.display()))?;
        payload.push(PayloadFact {
            source_path: exe.to_string_lossy().into_owned(),
            dest_rel: "safereturn/safereturn.exe".into(),
            size_bytes: data.len() as u64,
            sha256: sha256_hex(&data),
        });
    } else {
        for (src, rel) in &mopts.payload {
            let data = std::fs::read(src)
                .map_err(|e| format!("could not read payload file {}: {e}", src.display()))?;
            payload.push(PayloadFact {
                source_path: src.to_string_lossy().into_owned(),
                dest_rel: rel.clone(),
                size_bytes: data.len() as u64,
                sha256: sha256_hex(&data),
            });
        }
    }
    Ok(MediaFacts {
        target: MediaTargetFacts {
            disk_id: String::new(),
            model: mopts
                .target_model
                .clone()
                .unwrap_or_else(|| "USB device".into()),
            serial_suffix: serial,
            size_bytes: size,
            removable: mopts.removable,
        },
        winpe: WinPeSourceFacts {
            wim_path: wim.to_string_lossy().into_owned(),
            wim_size_bytes: wim_size,
            present: wim_present,
            adk_version: mopts.adk_version.clone(),
        },
        drivers: mopts.drivers.clone(),
        payload,
    })
}

fn media_plan_options(mopts: &MediaOptions) -> MediaPlanOptions {
    MediaPlanOptions {
        allow_non_removable: mopts.override_non_removable,
    }
}

fn print_media_plan(plan: &MediaPlan, token: &str, json: bool) {
    if json {
        let summary = safereturn_contract::MediaPlan {
            plan_token: token.to_string(),
            target_disk_id: plan.facts.target.disk_id.clone(),
            target_summary: format!(
                "{} (…{}): {} device — {} boot (FAT32), {} data (NTFS)",
                plan.facts.target.model,
                plan.facts.target.serial_suffix,
                format_bytes(plan.facts.target.size_bytes),
                format_bytes(plan.layout.boot_partition_bytes),
                format_bytes(plan.layout.data_partition_bytes),
            ),
            erase_warning_id: Some("media.will_erase_target".to_string()),
            boot_partition_bytes: plan.layout.boot_partition_bytes,
            data_partition_bytes: plan.layout.data_partition_bytes,
            payload_bytes: plan.payload_total_bytes,
            warnings: plan.warnings.iter().map(|w| w.id().to_string()).collect(),
        };
        let msg = WireMessage::Event(Event::MediaPlanned(summary));
        println!(
            "{}",
            serde_json::to_string(&msg).unwrap_or_else(|_| "{}".to_string())
        );
        return;
    }
    println!(
        "Target: {} (…{}) — {}",
        plan.facts.target.model,
        plan.facts.target.serial_suffix,
        format_bytes(plan.facts.target.size_bytes)
    );
    println!(
        "Layout: {} FAT32 boot partition + {} NTFS data partition",
        format_bytes(plan.layout.boot_partition_bytes),
        format_bytes(plan.layout.data_partition_bytes)
    );
    println!(
        "Payload: {} in {} file(s); WinPE image: {}",
        format_bytes(plan.payload_total_bytes),
        plan.facts.payload.len(),
        format_bytes(plan.facts.winpe.wim_size_bytes)
    );
    if !plan.facts.drivers.is_empty() {
        println!("Drivers from this PC: {}", plan.facts.drivers.len());
    }
    for w in &plan.warnings {
        match w {
            MediaWarning::NonRemovableOverride => println!(
                "WARNING: this device is NOT removable media, and the override was given. \
                 Creating media ERASES it completely. This warning is recorded on the media."
            ),
        }
    }
    println!("Steps:");
    for (i, step) in plan.steps.iter().enumerate() {
        println!("  {}. {}", i + 1, step.describe());
    }
    println!("Plan id: {token}");
}

fn cmd_media_plan(mopts: &MediaOptions) -> i32 {
    let facts = match build_media_facts(mopts) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_USAGE;
        }
    };
    match plan_media(&facts, &media_plan_options(mopts)) {
        Ok(plan) => {
            let token = plan.plan_id.clone();
            print_media_plan(&plan, &token, mopts.json);
            if !mopts.json {
                println!(
                    "Planning changed nothing. To create this media, run media create with the same flags and --plan-token {token}."
                );
            }
            EXIT_OK
        }
        Err(e) => report_error(&e),
    }
}

fn cmd_media_create(mopts: &MediaOptions) -> i32 {
    let Some(token) = &mopts.plan_token else {
        eprintln!("Error: media create needs --plan-token <id> from `media plan` — creating media erases the target, so it only ever runs a plan you have seen.");
        eprintln!("What was not changed: Nothing was written to any device.");
        return EXIT_USAGE;
    };
    let facts = match build_media_facts(mopts) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_USAGE;
        }
    };
    let plan = match plan_media(&facts, &media_plan_options(mopts)) {
        Ok(p) => p,
        Err(e) => return report_error(&e),
    };
    if plan.plan_id != *token {
        eprintln!(
            "Error: --plan-token does not match the plan these flags produce (that plan's id is {}). The facts changed since the plan you confirmed, or the token is wrong.",
            plan.plan_id
        );
        eprintln!("What was not changed: Nothing was written to any device. Run `media plan` again, check the plan, and create with its id.");
        return EXIT_FAIL;
    }
    print_media_plan(&plan, &plan.plan_id, mopts.json);
    if !mopts.json {
        println!(
            "WARNING: creating this media ERASES the target device ({}, …{}) completely — every file on it will be gone.",
            plan.facts.target.model, plan.facts.target.serial_suffix
        );
    }
    let executor = platform_executor(mopts.target_spec.clone().unwrap_or_default());
    match executor.execute(&plan, &mut |done, total| {
        if !mopts.json {
            eprintln!("  Building media: step {done}/{total}");
        }
    }) {
        Ok(()) => {
            println!(
                "Media created from plan {}. It is NOT boot-tested yet — boot the PC from it once and let the recovery shell start; that test is recorded on the media. Until then, do not count on it.",
                plan.plan_id
            );
            EXIT_OK
        }
        Err(e) => report_error(&e),
    }
}

fn cmd_media_verify(pos: &[String], mopts: &MediaOptions) -> i32 {
    let Some(root) = pos.first() else {
        eprintln!("Error: media verify needs the media root folder (the boot/FAT32 partition, mounted or copied).");
        return EXIT_USAGE;
    };
    let report = match verify_media_roots(Path::new(root), mopts.data_root.as_deref()) {
        Ok(r) => r,
        Err(e) => return report_error(&e),
    };
    let m = &report.manifest;
    println!(
        "Media manifest: plan {}, created {} by SafeReturn core {}",
        m.plan_id,
        fmt_datetime(m.created_unix),
        m.created_by_version
    );
    if m.warnings_shown.is_empty() {
        println!("Warnings shown at creation: none");
    } else {
        println!(
            "Warnings shown at creation: {}",
            m.warnings_shown.join(", ")
        );
    }
    for check in &report.payload {
        if check.ok {
            println!("  OK   {} — {}", check.dest_rel, check.detail);
        } else {
            println!("  FAIL {} — {}", check.dest_rel, check.detail);
        }
    }
    for bf in &report.boot_files {
        println!("  {} {}", if bf.present { "OK  " } else { "MISS" }, bf.path);
    }
    println!(
        "Integrity: {}",
        if report.passed() {
            "PASS — payload and boot files match the manifest"
        } else {
            "FAIL — see the lines above; rebuild this media before trusting it"
        }
    );
    match &report.boot_test {
        BootTestStatus::Tested {
            booted_unix,
            firmware,
        } => println!(
            "Boot test: PASSED — this media booted {} ({}) and reached the recovery shell.",
            fmt_datetime(*booted_unix),
            firmware.as_deref().unwrap_or("firmware unknown")
        ),
        BootTestStatus::BootStartedShellNotReached { booted_unix, .. } => println!(
            "Boot test: PARTIAL — this media booted {} but did NOT reach the recovery shell. It is not proven. Investigate before trusting it.",
            fmt_datetime(*booted_unix)
        ),
        BootTestStatus::Invalid { reason } => println!(
            "Boot test: marker INVALID — {reason}. Not counted as tested."
        ),
        BootTestStatus::NotTested => println!(
            "Boot test: NOT TESTED YET — this media has never reported a boot. It may work, but that is not proven. Boot the PC from it once and let the recovery shell start; the shell records the test on the media."
        ),
    }
    if report.passed() {
        EXIT_OK
    } else {
        EXIT_FAIL
    }
}

// ---------------------------------------------------------------------------
// Whole-PC (bare-metal) restore (S5): `restore-system plan|execute|
// verify`. Like the media group, the CLI is stateless across
// invocations: plans are deterministic, so the plan id IS the token
// — `execute` recomputes the plan from the same flags and only
// proceeds when --plan-token matches that id exactly. (In-process
// shells use the engine's random single-use tokens instead.)

#[derive(Default)]
struct RestoreSystemOptions {
    passphrase: Option<String>,
    recovery_key_file: Option<PathBuf>,
    target_size: Option<u64>,
    serial_suffix: Option<String>,
    target_model: Option<String>,
    removable: bool,
    /// "uefi" | "bios" as stated by the operator.
    firmware: Option<String>,
    /// The operator states the firmware mode could not be determined.
    firmware_unknown: bool,
    os_root: Option<String>,
    esp_root: Option<String>,
    plan_token: Option<String>,
    plan_out: Option<PathBuf>,
    plan_file: Option<PathBuf>,
    simulate: Option<PathBuf>,
    disk_index: Option<u32>,
    work_dir: Option<PathBuf>,
    json: bool,
}

fn run_restore_system(args: &[String]) -> i32 {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        eprintln!("Error: restore-system needs a subcommand: plan, execute, or verify.");
        print_usage();
        return EXIT_USAGE;
    };
    let (pos, ropts) = match parse_restore_system_options(&args[1..]) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_USAGE;
        }
    };
    match sub {
        "plan" => cmd_restore_system_plan(&pos, &ropts),
        "execute" => cmd_restore_system_execute(&pos, &ropts),
        "verify" => cmd_restore_system_verify(&pos, &ropts),
        other => {
            eprintln!(
                "Error: unknown restore-system subcommand '{other}' — use plan, execute, or verify."
            );
            EXIT_USAGE
        }
    }
}

fn parse_restore_system_options(
    args: &[String],
) -> std::result::Result<(Vec<String>, RestoreSystemOptions), String> {
    let mut pos = Vec::new();
    let mut o = RestoreSystemOptions::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let take_value = |i: &mut usize| -> std::result::Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag {arg} needs a value"))
        };
        match arg.as_str() {
            "--passphrase" => o.passphrase = Some(take_value(&mut i)?),
            "--recovery-key" => o.recovery_key_file = Some(PathBuf::from(take_value(&mut i)?)),
            "--target-size" => {
                let v = take_value(&mut i)?;
                o.target_size = Some(
                    v.parse()
                        .map_err(|_| format!("--target-size needs a byte count, got '{v}'"))?,
                );
            }
            "--serial-suffix" => o.serial_suffix = Some(take_value(&mut i)?),
            "--target-model" => o.target_model = Some(take_value(&mut i)?),
            "--removable" => o.removable = true,
            "--firmware" => o.firmware = Some(take_value(&mut i)?),
            "--firmware-unknown" => o.firmware_unknown = true,
            "--os-root" => o.os_root = Some(take_value(&mut i)?),
            "--esp-root" => o.esp_root = Some(take_value(&mut i)?),
            "--plan-token" => o.plan_token = Some(take_value(&mut i)?),
            "--plan-out" => o.plan_out = Some(PathBuf::from(take_value(&mut i)?)),
            "--plan" => o.plan_file = Some(PathBuf::from(take_value(&mut i)?)),
            "--simulate" => o.simulate = Some(PathBuf::from(take_value(&mut i)?)),
            "--disk-index" => {
                let v = take_value(&mut i)?;
                o.disk_index = Some(
                    v.parse()
                        .map_err(|_| format!("--disk-index needs a number, got '{v}'"))?,
                );
            }
            "--work-dir" => o.work_dir = Some(PathBuf::from(take_value(&mut i)?)),
            "--json" => o.json = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag '{flag}'")),
            _ => pos.push(arg.clone()),
        }
        i += 1;
    }
    Ok((pos, o))
}

fn rs_credentials(ropts: &RestoreSystemOptions) -> Options {
    Options {
        passphrase: ropts.passphrase.clone(),
        recovery_key_file: ropts.recovery_key_file.clone(),
        ..Default::default()
    }
}

/// The target facts, from the flags — the facts are what the
/// operator states about the disk and the machine that will boot
/// it. Firmware is never defaulted: it is stated (--firmware) or
/// stated-unknown (--firmware-unknown), and planning refuses the
/// unknown with its named error.
fn build_restore_target(
    ropts: &RestoreSystemOptions,
) -> std::result::Result<SystemRestoreTargetFacts, String> {
    let size = ropts
        .target_size
        .ok_or("--target-size <bytes> is required (the target disk's size)")?;
    let serial = ropts
        .serial_suffix
        .clone()
        .ok_or("--serial-suffix <last 4 of the disk serial> is required")?;
    let firmware = if ropts.firmware_unknown {
        Fact::unknown(
            "operator statement (--firmware-unknown)",
            "the operator could not determine the target PC's firmware mode",
        )
    } else {
        match ropts.firmware.as_deref() {
            Some("uefi") => Fact::known(BootMode::Uefi, "operator statement (--firmware uefi)"),
            Some("bios") => Fact::known(BootMode::Bios, "operator statement (--firmware bios)"),
            Some(other) => {
                return Err(format!(
                    "--firmware must be 'uefi' or 'bios', got '{other}'"
                ))
            }
            None => {
                return Err(
                    "--firmware <uefi|bios> is required — state the target PC's firmware mode, or --firmware-unknown to state it could not be determined (planning will refuse, by name)"
                        .to_string(),
                )
            }
        }
    };
    Ok(SystemRestoreTargetFacts {
        disk_id: "cli-target".to_string(),
        model: ropts
            .target_model
            .clone()
            .unwrap_or_else(|| "Target disk".into()),
        serial_suffix: serial,
        size_bytes: size,
        removable: ropts.removable,
        firmware,
    })
}

fn build_restore_options(
    ropts: &RestoreSystemOptions,
) -> std::result::Result<SystemRestoreOptions, String> {
    Ok(SystemRestoreOptions {
        os_root: ropts
            .os_root
            .clone()
            .ok_or("--os-root <set root> is required (the set root that captured the Windows volume)")?,
        esp_root: ropts
            .esp_root
            .clone()
            .ok_or("--esp-root <set root> is required (the set root that captured the EFI System Partition)")?,
    })
}

/// Unlock the volume, read the set, compute the plan — shared by
/// plan and execute. Err(i32) is a finished, reported outcome.
fn compute_cli_system_restore_plan(
    pos: &[String],
    ropts: &RestoreSystemOptions,
) -> std::result::Result<(UnlockedVolume, SystemRestorePlan), i32> {
    if pos.len() < 2 {
        eprintln!("Error: restore-system needs <volume> <set-id>.");
        return Err(EXIT_USAGE);
    }
    let unlocked = match unlock(&pos[0], &rs_credentials(ropts)) {
        Ok(u) => u,
        Err(e) => return Err(report_error(&e)),
    };
    let target = match build_restore_target(ropts) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return Err(EXIT_USAGE);
        }
    };
    let options = match build_restore_options(ropts) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return Err(EXIT_USAGE);
        }
    };
    let manifest = match read_set_manifest(&unlocked, &pos[1]) {
        Ok(m) => m,
        Err(e) => return Err(report_error(&e)),
    };
    match plan_system_restore(&manifest, &target, &options) {
        Ok(plan) => Ok((unlocked, plan)),
        Err(e) => Err(report_error(&e)),
    }
}

fn print_system_restore_plan(plan: &SystemRestorePlan, json: bool) {
    if json {
        let summary = safereturn_contract::SystemRestorePlan {
            plan_token: plan.plan_id.clone(),
            backup_id: plan.set_id.clone(),
            target_disk_id: plan.target.disk_id.clone(),
            target_summary: format!(
                "{} (…{}): {} disk — {} partitions (GPT, UEFI), {} files, {} to restore",
                plan.target.model,
                plan.target.serial_suffix,
                format_bytes(plan.target.size_bytes),
                plan.layout.len(),
                plan.total_file_count(),
                format_bytes(plan.total_apply_bytes()),
            ),
            erase_warning_id: Some("system_restore.will_erase_target".to_string()),
            firmware: "uefi".to_string(),
            partition_count: plan.layout.len() as u64,
            file_count: plan.total_file_count(),
            total_bytes: plan.total_apply_bytes(),
            warnings: plan.warnings.iter().map(|w| w.id().to_string()).collect(),
        };
        let msg = WireMessage::Event(Event::SystemRestorePlanned(summary));
        println!(
            "{}",
            serde_json::to_string(&msg).unwrap_or_else(|_| "{}".to_string())
        );
        return;
    }
    println!(
        "Target: {} (…{}) — {}",
        plan.target.model,
        plan.target.serial_suffix,
        format_bytes(plan.target.size_bytes)
    );
    println!("Firmware: UEFI — GPT layout");
    println!("Layout:");
    for part in &plan.layout {
        let role = match part.role {
            PartitionRole::Esp => "EFI System Partition",
            PartitionRole::Msr => "Microsoft Reserved (MSR)",
            PartitionRole::Windows => "Windows",
            PartitionRole::WinRe => "Windows RE tools",
        };
        let fs = match part.filesystem {
            Some(PartitionFilesystem::Fat32) => "FAT32",
            Some(PartitionFilesystem::Ntfs) => "NTFS",
            None => "not formatted",
        };
        let letter = part
            .drive_letter
            .map(|l| format!(", letter {l} in WinPE"))
            .unwrap_or_default();
        println!(
            "  {}. {} — {} {} (label {:?}{})",
            part.index,
            role,
            format_bytes(part.size_bytes),
            fs,
            part.label.as_deref().unwrap_or(""),
            letter
        );
        println!("     Size: {}", part.size_source);
    }
    let count_for = |role: PartitionRole| {
        plan.applications
            .iter()
            .filter(|a| a.partition == role)
            .count()
    };
    println!(
        "Files: {} total ({} bytes) — {} to the ESP, {} to Windows{}",
        plan.total_file_count(),
        plan.total_apply_bytes(),
        count_for(PartitionRole::Esp),
        count_for(PartitionRole::Windows),
        if plan.partition(PartitionRole::WinRe).is_some() {
            ", 1 to the Windows RE partition (Winre.wim)"
        } else {
            ""
        }
    );
    if !plan.warnings.is_empty() {
        println!("Warnings — read these before executing:");
        for w in &plan.warnings {
            println!("  WARNING: {}", w.describe());
        }
    }
    println!("After the files are in place:");
    for (i, step) in plan.post_steps.iter().enumerate() {
        println!("  {}. {}", i + 1, step.describe());
        if let Some(cmd) = step.command() {
            println!("     runs: {}", cmd.join(" "));
        }
    }
    println!("Plan id: {}", plan.plan_id);
}

fn cmd_restore_system_plan(pos: &[String], ropts: &RestoreSystemOptions) -> i32 {
    let (_unlocked, plan) = match compute_cli_system_restore_plan(pos, ropts) {
        Ok(v) => v,
        Err(code) => return code,
    };
    print_system_restore_plan(&plan, ropts.json);
    if let Some(out) = &ropts.plan_out {
        let json = match serde_json::to_string_pretty(&plan) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Error: the plan could not be serialized: {e}");
                return EXIT_FAIL;
            }
        };
        match std::fs::write(out, json) {
            Ok(()) => println!(
                "Plan saved to {} (for restore-system verify).",
                out.display()
            ),
            Err(e) => {
                eprintln!(
                    "Error: could not write the plan file {}: {e}",
                    out.display()
                );
                return EXIT_FAIL;
            }
        }
    }
    if !ropts.json {
        println!(
            "Planning touched nothing. To execute this restore, run restore-system execute with the same flags and --plan-token {}.",
            plan.plan_id
        );
    }
    EXIT_OK
}

fn cmd_restore_system_execute(pos: &[String], ropts: &RestoreSystemOptions) -> i32 {
    let Some(token) = &ropts.plan_token else {
        eprintln!("Error: restore-system execute needs --plan-token <id> from `restore-system plan` — a whole-PC restore erases the target disk, so it only ever runs a plan you have seen.");
        eprintln!("What was not changed: Nothing was touched — no disk was erased, partitioned, or written.");
        return EXIT_USAGE;
    };
    let (unlocked, plan) = match compute_cli_system_restore_plan(pos, ropts) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if plan.plan_id != *token {
        eprintln!(
            "Error: --plan-token does not match the plan these flags produce (that plan's id is {}). The facts changed since the plan you confirmed, or the token is wrong.",
            plan.plan_id
        );
        eprintln!(
            "What was not changed: Nothing was touched. Run `restore-system plan` again, check the plan, and execute with its id."
        );
        return EXIT_FAIL;
    }
    print_system_restore_plan(&plan, ropts.json);
    if !ropts.json {
        println!(
            "WARNING: executing this restore ERASES the target disk ({}, …{}) completely — every file on it will be gone.",
            plan.target.model, plan.target.serial_suffix
        );
    }

    if let Some(sim_root) = &ropts.simulate {
        let executor = SimulatedDiskExecutor {
            root: sim_root.clone(),
        };
        let outcome = executor.execute(&unlocked, &plan, &mut |done, total| {
            if !ropts.json {
                eprintln!("  Restoring system: file {done}/{total}");
            }
        });
        let execution = match outcome {
            Ok(x) => x,
            Err(e) => return report_error(&e),
        };
        println!(
            "SIMULATION complete: {} files ({} bytes) applied to the fake disk at {}. No real disk was touched, and the boot commands (bcdboot, reagentc) were recorded in {} — NOT run.",
            execution.files_written,
            execution.bytes_written,
            sim_root.display(),
            RESTORE_LOG_FILE
        );
        return print_system_restore_verify(&plan, sim_root);
    }

    // Real-disk path: the platform executor (Windows skeleton /
    // unsupported elsewhere). It renders its artifacts under the
    // work dir and its result — success or named refusal — surfaces
    // exactly as the engine produced it.
    let work_dir = ropts
        .work_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("safereturn-restore-work"));
    let executor = platform_system_restore_executor(ropts.disk_index.unwrap_or(0), work_dir);
    match executor.execute(&unlocked, &plan, &mut |_, _| {}) {
        Ok(execution) => {
            println!(
                "System restore executed from plan {}: {} files ({} bytes) applied.",
                plan.plan_id, execution.files_written, execution.bytes_written
            );
            EXIT_OK
        }
        Err(e) => report_error(&e),
    }
}

fn cmd_restore_system_verify(pos: &[String], ropts: &RestoreSystemOptions) -> i32 {
    let Some(root) = pos.first() else {
        eprintln!(
            "Error: restore-system verify needs the applied root folder (e.g. a simulation folder)."
        );
        return EXIT_USAGE;
    };
    let Some(plan_file) = &ropts.plan_file else {
        eprintln!(
            "Error: restore-system verify needs --plan <file> (saved by restore-system plan --plan-out)."
        );
        return EXIT_USAGE;
    };
    let text = match std::fs::read_to_string(plan_file) {
        Ok(t) => t,
        Err(e) => {
            return report_error(&CoreError::Io {
                path: Some(plan_file.clone()),
                source: e,
            })
        }
    };
    let plan: SystemRestorePlan = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            return report_error(&CoreError::Json {
                path: plan_file.clone(),
                source: e,
            })
        }
    };
    print_system_restore_verify(&plan, Path::new(root))
}

/// Shared renderer for the verify report (used by `verify` and by
/// `execute --simulate`, which verifies what it just applied).
fn print_system_restore_verify(plan: &SystemRestorePlan, root: &Path) -> i32 {
    let report = match verify_system_restore(plan, root) {
        Ok(r) => r,
        Err(e) => return report_error(&e),
    };
    println!("Verification against plan {}:", report.plan_id);
    for pv in &report.partitions {
        let role = match pv.role {
            PartitionRole::Esp => "EFI System Partition",
            PartitionRole::Msr => "Microsoft Reserved (MSR)",
            PartitionRole::Windows => "Windows",
            PartitionRole::WinRe => "Windows RE tools",
        };
        println!("  {}: {}/{} files OK", role, pv.files_ok, pv.files_checked);
        for m in &pv.missing {
            println!("    MISSING {m}");
        }
        for m in &pv.mismatched {
            println!("    DIFFERENT {m} (content does not match the backup)");
        }
    }
    for bf in &report.esp_boot_files {
        println!(
            "  Boot file {}: {}",
            bf.path,
            if bf.present { "present" } else { "MISSING" }
        );
    }
    match report.winre_image_present {
        Some(true) => println!("  Windows RE image: present where the plan placed it"),
        Some(false) => println!("  Windows RE image: MISSING"),
        None => println!(
            "  Windows RE image: the plan placed none (a disclosed gap in the plan's warnings)"
        ),
    }
    println!(
        "  Boot registration: NOT VERIFIED — the boot files are in place, but whether the boot configuration points at this Windows can only be proven by bcdboot's result on the machine and a real boot. File inspection does not prove it, and SafeReturn does not claim it."
    );
    if report.files_in_place() {
        println!("Files: PASS — every file the plan called for is in place with matching content.");
        EXIT_OK
    } else {
        println!(
            "Files: FAIL — see the lines above. Do not boot from this restore until they are resolved."
        );
        EXIT_FAIL
    }
}

// ---------------------------------------------------------------------------
// Boot Rehearsal (L3, S6): plan / run / report. The target flags are
// the restore-system ones (a rehearsal plans the same restore, onto
// a staging folder instead of a disk); build_restore_target /
// build_restore_options are reused unchanged.

#[derive(Default)]
struct RehearseBootOptions {
    inner: RestoreSystemOptions,
    staging: Option<PathBuf>,
    hyperv: bool,
    edition: Option<String>,
    record_vm_boot: Option<String>,
    record_source: Option<String>,
}

fn run_rehearse_boot(args: &[String]) -> i32 {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        eprintln!("Error: rehearse-boot needs a subcommand: plan, run, or report.");
        print_usage();
        return EXIT_USAGE;
    };
    let (pos, bopts) = match parse_rehearse_boot_options(&args[1..]) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_USAGE;
        }
    };
    match sub {
        "plan" => cmd_rehearse_boot_plan(&pos, &bopts, false),
        "run" => cmd_rehearse_boot_plan(&pos, &bopts, true),
        "report" => cmd_rehearse_boot_report(&pos, &bopts),
        other => {
            eprintln!(
                "Error: unknown rehearse-boot subcommand '{other}' — use plan, run, or report."
            );
            EXIT_USAGE
        }
    }
}

fn parse_rehearse_boot_options(
    args: &[String],
) -> std::result::Result<(Vec<String>, RehearseBootOptions), String> {
    // Reuse the restore-system parser for the shared flags by
    // filtering out the rehearsal-only ones first.
    let mut filtered: Vec<String> = Vec::new();
    let mut bopts = RehearseBootOptions::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].clone();
        let take_value = |i: &mut usize| -> std::result::Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag {arg} needs a value"))
        };
        match arg.as_str() {
            "--staging" => bopts.staging = Some(PathBuf::from(take_value(&mut i)?)),
            "--hyperv" => bopts.hyperv = true,
            "--edition" => bopts.edition = Some(take_value(&mut i)?),
            "--record-vm-boot" => bopts.record_vm_boot = Some(take_value(&mut i)?),
            "--source" => bopts.record_source = Some(take_value(&mut i)?),
            _ => filtered.push(arg),
        }
        i += 1;
    }
    let (pos, inner) = parse_restore_system_options(&filtered)?;
    bopts.inner = inner;
    Ok((pos, bopts))
}

fn rehearse_vm_facts(bopts: &RehearseBootOptions) -> Option<VmFacts> {
    if bopts.hyperv || bopts.edition.is_some() {
        Some(VmFacts {
            hyperv_available: bopts.hyperv,
            edition: bopts.edition.clone(),
        })
    } else {
        None
    }
}

fn cmd_rehearse_boot_plan(pos: &[String], bopts: &RehearseBootOptions, run: bool) -> i32 {
    if pos.len() < 2 {
        eprintln!("Error: rehearse-boot plan/run needs <volume> <set-id>.");
        return EXIT_USAGE;
    }
    let Some(staging) = &bopts.staging else {
        eprintln!("Error: rehearse-boot needs --staging <folder> (where the rehearsal applies and verifies the restore).");
        return EXIT_USAGE;
    };
    let unlocked = match unlock(&pos[0], &rs_credentials(&bopts.inner)) {
        Ok(u) => u,
        Err(e) => return report_error(&e),
    };
    let target = match build_restore_target(&bopts.inner) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_USAGE;
        }
    };
    let options = match build_restore_options(&bopts.inner) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_USAGE;
        }
    };
    let vm = rehearse_vm_facts(bopts);
    let mut engine = Engine::new(unlocked);
    if !run {
        let planned =
            match engine.plan_boot_rehearsal(&pos[1], &target, &options, staging, vm.as_ref()) {
                Ok(p) => p,
                Err(e) => return report_error(&e),
            };
        print_system_restore_plan(&planned.restore_plan, bopts.inner.json);
        print_checklist(&planned.checklist);
        println!("Planning touched nothing. Run `rehearse-boot run` with the same flags to apply this plan to the staging folder and verify it.");
        return EXIT_OK;
    }
    let mut sink = make_sink(bopts.inner.json);
    let report = match engine.run_boot_rehearsal(
        &pos[1],
        &target,
        &options,
        staging,
        vm.as_ref(),
        &mut sink,
    ) {
        Ok(r) => r,
        Err(e) => return report_error(&e),
    };
    print_boot_rehearsal_report(&report);
    if report.passed() {
        EXIT_OK
    } else {
        EXIT_FAIL
    }
}

fn print_checklist(steps: &[ChecklistStep]) {
    println!("Machine-only steps (guided — SafeReturn does not run these):");
    for (i, step) in steps.iter().enumerate() {
        println!("  {}. {}", i + 1, step.title);
        if let Some(cmd) = &step.command {
            println!("     run: {cmd}");
        }
        if let Some(note) = &step.note {
            println!("     {note}");
        }
    }
}

fn print_boot_rehearsal_report(report: &BootRehearsalReport) {
    println!("Boot Rehearsal report (plan {}):", report.plan_id);
    println!("  {}", report.verdict_line());
    for pv in &report.partitions {
        let role = match pv.role {
            PartitionRole::Esp => "EFI System Partition",
            PartitionRole::Msr => "Microsoft Reserved (MSR)",
            PartitionRole::Windows => "Windows",
            PartitionRole::WinRe => "Windows RE tools",
        };
        println!("  {}: {}/{} files OK", role, pv.files_ok, pv.files_checked);
        for m in &pv.missing {
            println!("    MISSING {m}");
        }
        for m in &pv.mismatched {
            println!("    DIFFERENT {m} (content does not match the backup)");
        }
    }
    println!(
        "  Layout: {}",
        if report.layout_valid {
            format!("valid — {}", report.layout_detail)
        } else {
            format!("INVALID — {}", report.layout_detail)
        }
    );
    if let Some(err) = &report.application_error {
        println!("  Applying the backup to staging failed: {err}");
    }
    println!(
        "  Boot registration: NOT VERIFIED — file inspection cannot prove it (see the report's boot_registered fact)."
    );
    match &report.vm_boot {
        VmBootStatus::NotBootTested => {
            println!("  VM boot: not boot-tested (see the verdict line).")
        }
        VmBootStatus::Recorded {
            outcome, source, ..
        } => println!("  VM boot: recorded — {outcome} (source: {source})"),
    }
    println!(
        "  Record: {} in {}",
        REHEARSAL_RECORD_FILE, report.staging_dir
    );
}

fn cmd_rehearse_boot_report(pos: &[String], bopts: &RehearseBootOptions) -> i32 {
    let Some(staging) = pos.first() else {
        eprintln!("Error: rehearse-boot report needs the staging folder.");
        return EXIT_USAGE;
    };
    let staging = Path::new(staging);
    if let Some(outcome) = &bopts.record_vm_boot {
        let Some(source) = &bopts.record_source else {
            eprintln!("Error: --record-vm-boot needs --source <who/what observed it> — an unsourced boot claim is not recorded.");
            return EXIT_USAGE;
        };
        return match record_vm_boot_outcome(staging, outcome, source, now_unix()) {
            Ok(report) => {
                println!("Recorded. The rehearsal record now reads:");
                print_boot_rehearsal_report(&report);
                EXIT_OK
            }
            Err(e) => report_error(&e),
        };
    }
    match read_rehearsal_record(staging) {
        Ok(report) => {
            print_boot_rehearsal_report(&report);
            if report.passed() {
                EXIT_OK
            } else {
                EXIT_FAIL
            }
        }
        Err(e) => report_error(&e),
    }
}

// ---------------------------------------------------------------------------
// Recovery Card (S6): generate the printable card from stated
// facts. The card generator's API has no passphrase parameter by
// design; --password-hint-location is a location string only.

#[derive(Default)]
struct CardCliOptions {
    out: Option<PathBuf>,
    format: Option<String>,
    pc: Option<String>,
    backup_model: Option<String>,
    backup_serial: Option<String>,
    backup_label: Option<String>,
    media_model: Option<String>,
    media_serial: Option<String>,
    media_label: Option<String>,
    boot_key: Option<String>,
    hint_location: Option<String>,
    volume: Option<PathBuf>,
    set: Option<String>,
    passphrase: Option<String>,
    recovery_key: Option<PathBuf>,
    rehearsal_staging: Option<PathBuf>,
}

fn run_recovery_card(args: &[String]) -> i32 {
    let opts = match parse_card_options(args) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return EXIT_USAGE;
        }
    };
    let Some(out) = &opts.out else {
        eprintln!("Error: recovery-card needs --out <file>.");
        return EXIT_USAGE;
    };
    let (Some(pc), Some(backup_model), Some(backup_serial)) =
        (&opts.pc, &opts.backup_model, &opts.backup_serial)
    else {
        eprintln!("Error: recovery-card needs --pc <description>, --backup-model <model> and --backup-serial <last 4 of the serial>. A card that cannot identify the PC and its backup drive is worse than no card.");
        return EXIT_USAGE;
    };
    let media = match (&opts.media_model, &opts.media_serial) {
        (Some(model), Some(serial)) => Some(DriveIdentification {
            model: model.clone(),
            serial_suffix: serial.clone(),
            label: opts.media_label.clone(),
        }),
        (None, None) => None,
        _ => {
            eprintln!(
                "Error: --media-model and --media-serial must be given together (or neither)."
            );
            return EXIT_USAGE;
        }
    };

    // Optional fact sources: a volume (last backup) and a Boot
    // Rehearsal record (last rehearsal).
    let mut last_backup = None;
    if let Some(volume_dir) = &opts.volume {
        let cred_opts = Options {
            passphrase: opts.passphrase.clone(),
            recovery_key_file: opts.recovery_key.clone(),
            ..Options::default()
        };
        let unlocked = match unlock(&volume_dir.to_string_lossy(), &cred_opts) {
            Ok(u) => u,
            Err(e) => return report_error(&e),
        };
        let catalog = match safereturn_core::read_catalog(&unlocked) {
            Ok(c) => c,
            Err(e) => return report_error(&e),
        };
        let chosen = match &opts.set {
            Some(id) => catalog.sets.iter().find(|s| &s.set_id == id),
            None => catalog.sets.iter().max_by_key(|s| s.created_unix),
        };
        match chosen {
            Some(entry) => {
                last_backup = Some(LastBackupFact {
                    label: entry.label.clone(),
                    set_id: entry.set_id.clone(),
                    created_unix: entry.created_unix,
                    file_count: entry.files,
                    total_bytes: entry.bytes,
                })
            }
            None => {
                eprintln!("Error: the volume has no matching backup set — a card claiming a last backup that does not exist would lie. Make a backup first, or omit --volume.");
                return EXIT_FAIL;
            }
        }
    }
    let mut last_rehearsal = None;
    if let Some(staging) = &opts.rehearsal_staging {
        match read_rehearsal_record(staging) {
            Ok(record) => {
                let summary = match &record.vm_boot {
                    VmBootStatus::Recorded { outcome, .. } => {
                        format!(
                            "files {} — VM boot recorded: {outcome}",
                            if record.files_verified {
                                "verified"
                            } else {
                                "DID NOT VERIFY"
                            }
                        )
                    }
                    VmBootStatus::NotBootTested => format!(
                        "files {}; not boot-tested",
                        if record.files_verified {
                            "verified"
                        } else {
                            "DID NOT VERIFY"
                        }
                    ),
                };
                last_rehearsal = Some(LastRehearsalFact {
                    level_label: "Level 3 — Boot Rehearsal".to_string(),
                    unix: record.rehearsed_unix,
                    summary,
                });
            }
            Err(e) => return report_error(&e),
        }
    }

    let facts = RecoveryCardFacts {
        pc_description: pc.clone(),
        backup_drive: DriveIdentification {
            model: backup_model.clone(),
            serial_suffix: backup_serial.clone(),
            label: opts.backup_label.clone(),
        },
        media,
        boot_menu_key: opts.boot_key.clone(),
        password_hint_location: opts.hint_location.clone(),
        last_backup,
        last_rehearsal,
        generated_unix: now_unix(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let format = opts.format.as_deref().unwrap_or_else(|| {
        let name = out.to_string_lossy().to_lowercase();
        if name.ends_with(".html") || name.ends_with(".htm") {
            "html"
        } else {
            "text"
        }
    });
    let rendered = match format {
        "html" => render_card_html(&facts),
        "text" => render_card_text(&facts),
        other => {
            eprintln!("Error: --format must be html or text, not '{other}'.");
            return EXIT_USAGE;
        }
    };
    let content = match rendered {
        Ok(c) => c,
        Err(e) => return report_error(&e),
    };
    match std::fs::write(out, content) {
        Ok(()) => {
            println!(
                "Recovery Card written to {} ({})",
                out.display(),
                if format == "html" {
                    "HTML — print it from a browser"
                } else {
                    "plain text"
                }
            );
            println!(
                "Print two copies: one with the backup drive, one somewhere safe at home. {NO_PASSWORD_LINE}"
            );
            EXIT_OK
        }
        Err(e) => report_error(&CoreError::Io {
            path: Some(out.clone()),
            source: e,
        }),
    }
}

fn parse_card_options(args: &[String]) -> std::result::Result<CardCliOptions, String> {
    let mut opts = CardCliOptions::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].clone();
        let take = |i: &mut usize| -> std::result::Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag {arg} needs a value"))
        };
        match arg.as_str() {
            "--out" => opts.out = Some(PathBuf::from(take(&mut i)?)),
            "--format" => opts.format = Some(take(&mut i)?),
            "--pc" => opts.pc = Some(take(&mut i)?),
            "--backup-model" => opts.backup_model = Some(take(&mut i)?),
            "--backup-serial" => opts.backup_serial = Some(take(&mut i)?),
            "--backup-label" => opts.backup_label = Some(take(&mut i)?),
            "--media-model" => opts.media_model = Some(take(&mut i)?),
            "--media-serial" => opts.media_serial = Some(take(&mut i)?),
            "--media-label" => opts.media_label = Some(take(&mut i)?),
            "--boot-key" => opts.boot_key = Some(take(&mut i)?),
            "--password-hint-location" => opts.hint_location = Some(take(&mut i)?),
            "--volume" => opts.volume = Some(PathBuf::from(take(&mut i)?)),
            "--set" => opts.set = Some(take(&mut i)?),
            "--passphrase" => opts.passphrase = Some(take(&mut i)?),
            "--recovery-key" => opts.recovery_key = Some(PathBuf::from(take(&mut i)?)),
            "--rehearsal-staging" => opts.rehearsal_staging = Some(PathBuf::from(take(&mut i)?)),
            other => return Err(format!("unknown recovery-card flag '{other}'")),
        }
        i += 1;
    }
    Ok(opts)
}

// ---------------------------------------------------------------------------

/// "2023-11-14 22:13 UTC" from unix seconds (civil-from-days algorithm).
pub fn fmt_datetime(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        (secs % 3600) / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetime_formatting() {
        assert_eq!(fmt_datetime(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_datetime(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(fmt_datetime(1_735_689_600), "2025-01-01 00:00 UTC");
    }
}
