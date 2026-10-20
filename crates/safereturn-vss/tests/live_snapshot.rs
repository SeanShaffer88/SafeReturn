//! LIVE VSS exercise — the S0.5 on-machine check, encoded as a test so
//! it cannot drift from the code it verifies.
//!
//! NEVER runs in CI: the test is `#[ignore]`d AND requires the
//! environment variable SR_VSS_LIVE=1. Run it manually, elevated, on a
//! real Windows machine or VM:
//!
//!   set SR_VSS_LIVE=1
//!   cargo test -p safereturn-vss --test live_snapshot -- --ignored
//!   vssadmin list shadows   (afterwards: no SafeReturn shadow may remain)
//!
//! STATUS: UNVERIFIED — as of S3 (2026-10-20) this has never been run
//! against a real snapshot. Everything it asserts is what S0.5 must
//! prove: begin creates a snapshot, the device root looks like a
//! GLOBALROOT device object, finish deletes it, and begin off Windows
//! (or without elevation) fails cleanly.

#[test]
#[ignore = "live VSS: run manually with SR_VSS_LIVE=1 on an elevated Windows machine (S0.5)"]
fn live_snapshot_begin_and_finish() {
    if std::env::var("SR_VSS_LIVE").as_deref() != Ok("1") {
        eprintln!(
            "SR_VSS_LIVE is not 1 — skipping. This test is UNVERIFIED until run \
             elevated on a real Windows machine with SR_VSS_LIVE=1."
        );
        return;
    }
    #[cfg(not(windows))]
    {
        let err = safereturn_vss::SnapshotSession::begin("C:\\").unwrap_err();
        assert!(matches!(
            err,
            safereturn_vss::SnapshotError::UnsupportedPlatform
        ));
    }
    #[cfg(windows)]
    {
        let session = safereturn_vss::SnapshotSession::begin("C:\\")
            .expect("elevated on Windows, begin must create a snapshot (S0.5 check)");
        let device = session
            .device_root()
            .expect("a live session has a device root");
        assert!(
            device.contains("GLOBALROOT") && device.contains("HarddiskVolumeShadowCopy"),
            "device root must be a snapshot device object, got: {device}"
        );
        session
            .finish()
            .expect("finish must complete + delete the snapshot (S0.5 check)");
        eprintln!(
            "S0.5 partial proof: snapshot created at {device} and finished. \
             Still to confirm by hand: `vssadmin list shadows` shows no leftover shadow."
        );
    }
}
