//! CLI and JSON output must not hide link-related backup omissions.

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp(name: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "safereturn-cli-capture-safety-{name}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn init_volume(base: &Path) -> PathBuf {
        let volume = base.join("volume");
        let output = Command::new(env!("CARGO_BIN_EXE_safereturn"))
            .arg("init-volume")
            .arg(&volume)
            .arg("--recovery-key-out")
            .arg(base.join("recovery-key.txt"))
            .args(["--passphrase", "test-pw"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        volume
    }

    fn backup(volume: &Path, source: &Path, json: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_safereturn"));
        command.arg("backup").arg(volume).arg("test").arg(source);
        command.args(["--passphrase", "test-pw"]);
        if json {
            command.arg("--json");
        }
        command.output().unwrap()
    }

    #[test]
    fn selected_link_explains_the_refusal_and_preserves_existing_data() {
        let base = tmp("selected");
        let volume = init_volume(&base);
        let original = base.join("original.txt");
        let selected = base.join("selected-link");
        fs::write(&original, b"original contents").unwrap();
        symlink(&original, &selected).unwrap();
        let output = backup(&volume, &selected, false);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("symbolic link"), "{stderr}");
        assert!(stderr.contains("No backup set was saved"), "{stderr}");
        assert!(
            stderr.contains("Chunks copied before the backup stopped may remain"),
            "{stderr}"
        );
        assert!(stderr.contains("Choose a source without links"), "{stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Backup finished."));
        assert_eq!(fs::read(&original).unwrap(), b"original contents");
        assert!(fs::symlink_metadata(&selected)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_dir(volume.join("sets")).unwrap().count(), 0);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn skipped_child_has_a_warning_in_both_human_and_json_output() {
        let base = tmp("skipped");
        let volume = init_volume(&base);
        let source = base.join("source");
        let outside = base.join("outside.txt");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("keep.txt"), b"inside").unwrap();
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, source.join("not-copied")).unwrap();

        let output = backup(&volume, &source, true);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let events: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let finished: Vec<_> = events
            .iter()
            .filter(|e| e["type"] == "job_finished")
            .collect();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["outcome"], "succeeded");
        assert_eq!(
            finished[0]["summary_id"],
            "result.backup_succeeded_with_skips"
        );

        let output = backup(&volume, &source, false);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("some items were not backed up"), "{text}");
        assert!(text.contains("source/not-copied"), "{text}");
        assert!(text.contains("not followed"), "{text}");
        assert!(!text.contains("Backup finished."), "{text}");
        assert_eq!(fs::read(&outside).unwrap(), b"outside");

        fs::remove_file(source.join("not-copied")).unwrap();
        let clean = backup(&volume, &source, true);
        assert_eq!(clean.status.code(), Some(0));
        let clean_text = String::from_utf8(clean.stdout).unwrap();
        let clean_events: Vec<serde_json::Value> = clean_text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let clean_finish = clean_events
            .iter()
            .find(|e| e["type"] == "job_finished")
            .unwrap();
        assert_eq!(clean_finish["summary_id"], "result.backup_succeeded");
        let _ = fs::remove_dir_all(base);
    }
}
