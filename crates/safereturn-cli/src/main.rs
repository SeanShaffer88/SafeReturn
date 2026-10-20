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
