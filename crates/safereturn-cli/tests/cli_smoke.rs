//! End-to-end CLI smoke test on a temp tree: init → backup → list →
//! verify → restore-file → restore-set (refused without --yes, allowed
//! with it) → rehearse. Uses the real binary, real flags, real files.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("safereturn-cli-{name}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_safereturn"))
        .args(args)
        .output()
        .expect("CLI binary must run")
}

fn run_pw(volume_cmd: &[&str]) -> Output {
    let mut args: Vec<&str> = volume_cmd.to_vec();
    args.extend(["--passphrase", "smoke-test-pw"]);
    run(&args)
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn extract_set_id(text: &str) -> String {
    for line in text.lines() {
        if let Some(id) = line.strip_prefix("set_id: ") {
            return id.trim().to_string();
        }
    }
    panic!("no set_id line in CLI output:\n{text}");
}

#[test]
fn cli_end_to_end() {
    let base = tmp("e2e");
    let src = base.join("docsSrc");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("keep.txt"), b"important contents").unwrap();
    fs::write(src.join("sub/deep.txt"), b"deep contents").unwrap();
    let volume = base.join("volume");
    let volume_s = volume.to_string_lossy().into_owned();
    let key_out = base.join("my-recovery-key.txt");
    let key_s = key_out.to_string_lossy().into_owned();

    // init-volume (passphrase via env-free flag + explicit key location)
    let out = run(&[
        "init-volume",
        &volume_s,
        "--recovery-key-out",
        &key_s,
        "--passphrase",
        "smoke-test-pw",
    ]);
    assert!(out.status.success(), "init failed: {}", stderr(&out));
    assert!(key_out.exists(), "recovery key file must be written");
    assert!(stdout(&out).contains("Backup volume created"));

    // backup
    let src_s = src.to_string_lossy().into_owned();
    let out = run_pw(&["backup", &volume_s, "smoke", &src_s]);
    assert!(out.status.success(), "backup failed: {}", stderr(&out));
    let set_id = extract_set_id(&stdout(&out));

    // list-sets shows it
    let out = run_pw(&["list-sets", &volume_s]);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains(&set_id),
        "list output: {}",
        stdout(&out)
    );

    // verify passes
    let out = run_pw(&["verify", &volume_s, &set_id]);
    assert!(out.status.success(), "verify failed: {}", stderr(&out));
    assert!(stdout(&out).contains("every chunk is intact"));

    // wrong passphrase fails loudly
    let out = run(&["list-sets", &volume_s, "--passphrase", "nope"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("does not open this backup volume"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("What was not changed:"));

    // restore-file into a fresh folder
    let target = base.join("one");
    let target_s = target.to_string_lossy().into_owned();
    let out = run_pw(&[
        "restore-file",
        &volume_s,
        &set_id,
        "docssrc/keep.txt",
        &target_s,
    ]);
    assert!(
        out.status.success(),
        "restore-file failed: {}",
        stderr(&out)
    );
    assert_eq!(
        fs::read(target.join("keep.txt")).unwrap(),
        b"important contents"
    );

    // restore-set onto a conflicting file: refused without --yes …
    let target2 = base.join("two");
    fs::create_dir_all(target2.join("docssrc")).unwrap();
    fs::write(target2.join("docssrc/keep.txt"), b"LOCAL DIFFERENT").unwrap();
    let target2_s = target2.to_string_lossy().into_owned();
    let out = run_pw(&["restore-set", &volume_s, &set_id, &target2_s]);
    assert!(!out.status.success(), "must refuse without --yes");
    assert_eq!(
        fs::read(target2.join("docssrc/keep.txt")).unwrap(),
        b"LOCAL DIFFERENT",
        "refused restore must not overwrite"
    );
    // … and allowed with --yes.
    let out = run_pw(&["restore-set", &volume_s, &set_id, &target2_s, "--yes"]);
    assert!(
        out.status.success(),
        "restore-set --yes failed: {}",
        stderr(&out)
    );
    assert_eq!(
        fs::read(target2.join("docssrc/keep.txt")).unwrap(),
        b"important contents"
    );
    assert_eq!(
        fs::read(target2.join("docssrc/sub/deep.txt")).unwrap(),
        b"deep contents"
    );

    // rehearse-file passes and says so per file
    let out = run_pw(&[
        "rehearse-file",
        &volume_s,
        &set_id,
        "--file",
        "docssrc/keep.txt",
    ]);
    assert!(out.status.success(), "rehearse failed: {}", stderr(&out));
    assert!(stdout(&out).contains("PASS docssrc/keep.txt"));

    // recovery key alone (no passphrase) opens the volume
    let out = run(&["list-sets", &volume_s, "--recovery-key", &key_s]);
    assert!(
        out.status.success(),
        "recovery-key list failed: {}",
        stderr(&out)
    );
    assert!(stdout(&out).contains(&set_id));

    let _ = fs::remove_dir_all(&base);
    let _ = Path::new("safereturn-recovery-key.txt");
}

const FACTS_JSON: &str = r#"{
  "format_version": 1,
  "gathered_unix": 1700005000,
  "boot_mode": { "value": "uefi", "source": "cli smoke test" },
  "secure_boot": { "value": true, "source": "cli smoke test" },
  "bitlocker": { "C:": { "value": "on", "source": "cli smoke test" } },
  "esp_files": { "value": [], "source": "cli smoke test" },
  "winre": { "value": { "present": true, "location": "C:\\Windows\\System32\\Recovery\\Winre.wim" }, "source": "cli smoke test" },
  "bcd": { "included": false, "source": "cli smoke test", "not_included_reason": "smoke test does not capture BCD" }
}"#;

#[test]
fn cli_system_facts_and_snapshot_flags() {
    let base = tmp("s3");
    let src = base.join("srcDir");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"alpha").unwrap();
    let volume = base.join("volume");
    let volume_s = volume.to_string_lossy().into_owned();
    let key_s = base.join("key.txt").to_string_lossy().into_owned();
    let out = run(&[
        "init-volume",
        &volume_s,
        "--recovery-key-out",
        &key_s,
        "--passphrase",
        "smoke-test-pw",
    ]);
    assert!(out.status.success(), "init failed: {}", stderr(&out));
    let src_s = src.to_string_lossy().into_owned();

    // --system-facts attaches the gatherer's JSON to the new set.
    let facts_path = base.join("facts.json");
    fs::write(&facts_path, FACTS_JSON).unwrap();
    let facts_s = facts_path.to_string_lossy().into_owned();
    let out = run_pw(&[
        "backup",
        &volume_s,
        "with-facts",
        &src_s,
        "--system-facts",
        &facts_s,
    ]);
    assert!(out.status.success(), "backup failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("System facts attached"),
        "stdout: {}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("Capture: live filesystem"));

    // With --esp-root, the ESP entry is listed fresh from that root.
    let esp = base.join("esp");
    fs::create_dir_all(esp.join("EFI/Boot")).unwrap();
    fs::write(esp.join("EFI/Boot/bootx64.efi"), b"fallback").unwrap();
    let esp_s = esp.to_string_lossy().into_owned();
    let out = run_pw(&[
        "backup",
        &volume_s,
        "with-esp",
        &src_s,
        "--system-facts",
        &facts_s,
        "--esp-root",
        &esp_s,
    ]);
    assert!(out.status.success(), "backup failed: {}", stderr(&out));
    assert!(
        stderr(&out).contains("ESP listing: taken fresh"),
        "stderr: {}",
        stderr(&out)
    );

    // A damaged facts file fails loudly and the error is named.
    let bad_path = base.join("bad-facts.json");
    fs::write(&bad_path, "{not json").unwrap();
    let bad_s = bad_path.to_string_lossy().into_owned();
    let out = run_pw(&[
        "backup",
        &volume_s,
        "bad-facts",
        &src_s,
        "--system-facts",
        &bad_s,
    ]);
    assert!(!out.status.success(), "damaged facts file must fail");
    assert!(
        stderr(&out).contains("What was not changed:"),
        "stderr: {}",
        stderr(&out)
    );

    let _ = fs::remove_dir_all(&base);
}

/// Off Windows, `--snapshot` must fail cleanly with NOTHING written —
/// and `--allow-live` must turn it into an honestly-labelled live
/// backup. (On Windows this test does not exist: CI must never attempt
/// a real snapshot, and begin() there needs elevation + a real VSS.)
#[cfg(not(windows))]
#[test]
fn cli_snapshot_flag_off_windows() {
    let base = tmp("s3-snap");
    let src = base.join("srcDir");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"alpha").unwrap();
    let volume = base.join("volume");
    let volume_s = volume.to_string_lossy().into_owned();
    let key_s = base.join("key.txt").to_string_lossy().into_owned();
    let out = run(&[
        "init-volume",
        &volume_s,
        "--recovery-key-out",
        &key_s,
        "--passphrase",
        "smoke-test-pw",
    ]);
    assert!(out.status.success(), "init failed: {}", stderr(&out));
    let src_s = src.to_string_lossy().into_owned();

    // The snapshot cannot be taken here → named error, nothing written.
    let out = run_pw(&["backup", &volume_s, "snap", &src_s, "--snapshot", "C:\\"]);
    assert!(!out.status.success(), "snapshot off Windows must fail");
    assert!(
        stderr(&out).contains("require Windows"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("no live capture was substituted"),
        "stderr: {}",
        stderr(&out)
    );
    let out = run_pw(&["list-sets", &volume_s]);
    assert!(
        stdout(&out).contains("No backup sets"),
        "stdout: {}",
        stdout(&out)
    );

    // With --allow-live, the same request succeeds — loudly, and the
    // set is recorded as what it is: a live capture.
    let out = run_pw(&[
        "backup",
        &volume_s,
        "snap",
        &src_s,
        "--snapshot",
        "C:\\",
        "--allow-live",
    ]);
    assert!(
        out.status.success(),
        "allow-live backup failed: {}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("WARNING"), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("Capture: live filesystem"),
        "stdout: {}",
        stdout(&out)
    );

    let _ = fs::remove_dir_all(&base);
}
