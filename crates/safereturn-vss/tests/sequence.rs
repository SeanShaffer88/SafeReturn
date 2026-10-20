use safereturn_vss::*;

#[test]
fn documented_sequence_succeeds_in_order() {
    let mut s = VssSession::new();
    s.initialize_for_backup().unwrap();
    s.set_backup_state().unwrap();
    s.gather_writer_metadata().unwrap();
    s.start_snapshot_set().unwrap();
    s.add_to_snapshot_set("C:\\").unwrap();
    s.add_to_snapshot_set("D:\\").unwrap();
    s.prepare_for_backup().unwrap();
    s.do_snapshot_set().unwrap();
    assert_eq!(s.snapshot_ids().unwrap().len(), 2);
    s.backup_complete().unwrap();
    s.release().unwrap();
    assert_eq!(s.phase(), Phase::Released);
}

#[test]
fn out_of_order_calls_are_bad_state() {
    let mut s = VssSession::new();
    // DoSnapshotSet before anything: the classic VSS_E_BAD_STATE bug.
    assert!(matches!(
        s.do_snapshot_set(),
        Err(VssError::BadState { .. })
    ));
    // PrepareForBackup with no volume added must also fail.
    s.initialize_for_backup().unwrap();
    s.set_backup_state().unwrap();
    s.gather_writer_metadata().unwrap();
    s.start_snapshot_set().unwrap();
    assert!(matches!(
        s.prepare_for_backup(),
        Err(VssError::BadState { .. })
    ));
}

#[test]
fn session_is_single_use_after_release() {
    let mut s = VssSession::new();
    s.initialize_for_backup().unwrap();
    s.abort_backup().unwrap();
    s.release().unwrap();
    // A released IVssBackupComponents must never be reused (Learn).
    assert!(s.initialize_for_backup().is_err());
    assert!(s.release().is_err());
}

#[test]
fn locked_file_maps_to_snapshot_device_path() {
    let got = snapshot_path(
        "C:\\",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12",
        r"C:\Users\sean\open-database.db",
    )
    .unwrap();
    assert_eq!(
        got,
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\Users\sean\open-database.db"
    );
    // A file that is not on the snapshotted volume must not map.
    assert!(snapshot_path("C:\\", "dev", r"D:\other.txt").is_none());
}
