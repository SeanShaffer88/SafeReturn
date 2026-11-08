//! CLI errors for source names must be actionable and must not panic.

#[cfg(unix)]
mod unix {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp(name: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "safereturn-cli-capture-{name}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn unsupported_child_explains_the_refusal_and_what_was_not_changed() {
        let base = tmp("child");
        let volume = base.join("volume");
        let key = base.join("recovery-key.txt");
        let source = base.join("source");
        fs::create_dir_all(&source).unwrap();
        let original = source.join("literal\\backslash.txt");
        fs::write(&original, b"original contents").unwrap();
        let cli = env!("CARGO_BIN_EXE_safereturn");
        let init = Command::new(cli)
            .arg("init-volume")
            .arg(&volume)
            .arg("--recovery-key-out")
            .arg(&key)
            .args(["--passphrase", "test-pw"])
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let backup = Command::new(cli)
            .arg("backup")
            .arg(&volume)
            .arg("example")
            .arg(&source)
            .args(["--passphrase", "test-pw"])
            .output()
            .unwrap();
        assert!(!backup.status.success());
        let stderr = String::from_utf8_lossy(&backup.stderr);
        assert!(stderr.contains("literal"), "{stderr}");
        assert!(stderr.contains("cannot be recorded safely"), "{stderr}");
        assert!(stderr.contains("Rename or move"), "{stderr}");
        assert!(
            stderr.contains("No new backup set or chunks were written"),
            "{stderr}"
        );
        assert!(!String::from_utf8_lossy(&backup.stdout).contains("Backup finished."));
        assert_eq!(fs::read(original).unwrap(), b"original contents");
        assert_eq!(fs::read_dir(volume.join("sets")).unwrap().count(), 0);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn non_unicode_command_argument_refuses_before_work_without_leaking_it() {
        let base = tmp("argument");
        let volume = base.join("should-not-exist");
        let secret = OsString::from_vec(b"secret-\xff".to_vec());
        let output = Command::new(env!("CARGO_BIN_EXE_safereturn"))
            .arg("init-volume")
            .arg(&volume)
            .arg("--passphrase")
            .arg(secret)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("argument is not valid Unicode"), "{stderr}");
        assert!(stderr.contains("No operation was started"), "{stderr}");
        assert!(!stderr.contains("secret"), "{stderr}");
        assert!(!stderr.contains("panicked"), "{stderr}");
        assert!(!volume.exists());
        let _ = fs::remove_dir_all(base);
    }
}
