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
