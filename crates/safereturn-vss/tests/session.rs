//! S3 session tests that run everywhere (see docs/S3_NOTES.md).
//! The real-VSS exercise is a separate, env-gated, ignored test
//! (tests/live_snapshot.rs) — CI must never attempt a real snapshot.

/// Off Windows, `begin` is a clean typed error — never a panic, never
/// a silent fallback to live capture. This is the error path the CLI's
/// `backup --snapshot` honesty rule depends on.
#[cfg(not(windows))]
#[test]
fn snapshot_begin_is_a_clean_typed_error_off_windows() {
    let err = safereturn_vss::SnapshotSession::begin("C:\\").unwrap_err();
    assert!(matches!(
        err,
        safereturn_vss::SnapshotError::UnsupportedPlatform
    ));
    assert_eq!(err.code(), "vss.unsupported_platform");
    let text = format!("{err}");
    assert!(
        text.contains("require Windows"),
        "error must name the problem plainly: {text}"
    );
}
