//! Windows backend for the S0 spike — drives the C++ VSS helper (cpp/vss_helper.cpp)
//! through a narrow C ABI, and keeps the Rust state machine (lib.rs) in charge
//! of sequencing: the helper is only called in the order the state machine allows.
//!
//! S0 FINDING: the `windows` crate (checked 0.61.3) does not expose
//! IVssBackupComponents / CreateVssBackupComponents — its Vss module has
//! writer/provider/management interfaces only. Hence the helper. The C++
//! side is compiled against the real SDK header, so its vtable can never
//! silently drift from ours.
//!
//! STATUS: this Rust side is compile-checked for x86_64-pc-windows-msvc.
//! Linking needs the helper built (VssApi.lib) and runtime needs an elevated
//! Windows machine — both UNVERIFIED from the Linux dev VM (2026-10-20).

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

#[repr(C)]
struct SRVssSession {
    _private: [u8; 0],
}

extern "C" {
    fn sr_vss_create(out_hr: *mut i32) -> *mut SRVssSession;
    fn sr_vss_initialize(s: *mut SRVssSession) -> i32;
    fn sr_vss_gather_metadata(s: *mut SRVssSession) -> i32;
    fn sr_vss_snapshot_volume(
        s: *mut SRVssSession,
        volume: *const u16,
        device_out: *mut u16,
        device_out_cch: usize,
    ) -> i32;
    fn sr_vss_destroy(s: *mut SRVssSession, complete: bool) -> i32;
}

fn check(hr: i32, step: &'static str) -> Result<(), String> {
    if hr >= 0 {
        Ok(())
    } else {
        Err(format!("{step} failed: HRESULT 0x{:08X}", hr as u32))
    }
}

/// Safe probe: create + initialize + gather writer metadata. NO snapshot.
pub fn probe() -> Result<Vec<&'static str>, String> {
    let mut steps = Vec::new();
    unsafe {
        let mut hr: i32 = 0;
        let s = sr_vss_create(&mut hr);
        if s.is_null() {
            return Err(format!(
                "sr_vss_create failed: HRESULT 0x{:08X} (must run elevated)",
                hr as u32
            ));
        }
        steps.push("CreateVssBackupComponents");
        let r = check(sr_vss_initialize(s), "InitializeForBackup/SetBackupState")
            .map(|_| steps.push("InitializeForBackup+SetBackupState(FULL)"))
            .and_then(|_| check(sr_vss_gather_metadata(s), "GatherWriterMetadata"))
            .map(|_| steps.push("GatherWriterMetadata+Wait"));
        sr_vss_destroy(s, false);
        r?;
    }
    Ok(steps)
}

/// Full spike: snapshot `volume` (e.g. "C:\\"), return the snapshot device
/// object path. The caller reads locked files via lib::snapshot_path(),
/// then must call the returned guard's consume via `finish_snapshot` —
/// in product code this lifetime is owned by the backup session type.
pub fn snapshot_volume(volume: &str) -> Result<(String, *mut c_void), String> {
    let wide: Vec<u16> = std::ffi::OsStr::new(volume)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut hr: i32 = 0;
        let s = sr_vss_create(&mut hr);
        if s.is_null() {
            return Err(format!("sr_vss_create failed: HRESULT 0x{:08X}", hr as u32));
        }
        let attempt = (|| {
            check(sr_vss_initialize(s), "InitializeForBackup/SetBackupState")?;
            check(sr_vss_gather_metadata(s), "GatherWriterMetadata")?;
            let mut device = vec![0u16; 1024];
            check(
                sr_vss_snapshot_volume(s, wide.as_ptr(), device.as_mut_ptr(), device.len()),
                "StartSnapshotSet/AddToSnapshotSet/PrepareForBackup/DoSnapshotSet",
            )?;
            let len = device.iter().position(|&c| c == 0).unwrap_or(device.len());
            Ok::<String, String>(String::from_utf16_lossy(&device[..len]))
        })();
        match attempt {
            Ok(dev) => Ok((dev, s as *mut c_void)),
            Err(e) => {
                sr_vss_destroy(s, false);
                Err(e)
            }
        }
    }
}

/// Complete (or abort) and release a session from snapshot_volume().
pub fn finish_snapshot(session: *mut c_void, complete: bool) -> Result<(), String> {
    unsafe {
        check(
            sr_vss_destroy(session as *mut SRVssSession, complete),
            "BackupComplete/DeleteSnapshots",
        )
    }
}
