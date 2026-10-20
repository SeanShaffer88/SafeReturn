//! Windows backend for the VSS requester — drives the C++ helper
//! (cpp/vss_helper.cpp) through a narrow C ABI, and keeps the Rust state
//! machine (lib.rs) in charge of sequencing.
//!
//! S0 FINDING: the `windows` crate (checked 0.61.3) does not expose
//! IVssBackupComponents / CreateVssBackupComponents — its Vss module has
//! writer/provider/management interfaces only. Hence the helper, compiled
//! against the real SDK header so its vtable can never silently drift.
//!
//! LOADING (fixed after CI run #1, 2026-10-20): the helper is loaded at
//! RUNTIME with LoadLibraryW/GetProcAddress, never linked. Run #1 failed
//! with LNK2019 on all five sr_vss_* symbols because `cargo test` linked
//! the test binary before the helper was built. With dynamic loading the
//! workspace builds and tests with no helper present; a missing DLL is a
//! clean runtime error ("build the helper first"), and the shipped
//! layout is simply: vss_helper.dll next to the engine executable.
//!
//! STATUS: compile-checked for x86_64-pc-windows-msvc; the helper's own
//! compile is verified by CI (windows job). Runtime behavior on a real
//! Windows machine is UNVERIFIED until the probe runs elevated there.

use std::ffi::{c_char, c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

#[repr(C)]
pub struct SRVssSession {
    _private: [u8; 0],
}

type SrCreate = unsafe extern "C" fn(*mut i32) -> *mut SRVssSession;
type SrStep = unsafe extern "C" fn(*mut SRVssSession) -> i32;
type SrSnapshot = unsafe extern "C" fn(*mut SRVssSession, *const u16, *mut u16, usize) -> i32;
type SrDestroy = unsafe extern "C" fn(*mut SRVssSession, bool) -> i32;

extern "system" {
    fn LoadLibraryW(lp_lib_file_name: *const u16) -> *mut c_void;
    fn GetProcAddress(
        h_module: *mut c_void,
        lp_proc_name: *const c_char,
    ) -> Option<unsafe extern "system" fn()>;
}

struct Helper {
    create: SrCreate,
    initialize: SrStep,
    gather_metadata: SrStep,
    snapshot_volume: SrSnapshot,
    destroy: SrDestroy,
}

// The helper DLL is loaded once and lives for the process lifetime
// (an engine process loads it at startup). Function pointers into a
// loaded module are safe to share; the module is never unloaded.
unsafe impl Send for Helper {}
unsafe impl Sync for Helper {}

static HELPER: OnceLock<Result<Helper, String>> = OnceLock::new();

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn load_helper() -> Result<&'static Helper, String> {
    HELPER
        .get_or_init(|| unsafe {
            let module = LoadLibraryW(wide("vss_helper.dll").as_ptr());
            if module.is_null() {
                return Err(
                    "vss_helper.dll not found (looked next to the executable and on PATH) — \
                     build crates/safereturn-vss/cpp/vss_helper.cpp first"
                        .to_string(),
                );
            }
            macro_rules! sym {
                ($name:literal, $ty:ty) => {{
                    let cname = concat!($name, "\0");
                    match GetProcAddress(module, cname.as_ptr() as *const c_char) {
                        Some(p) => std::mem::transmute::<unsafe extern "system" fn(), $ty>(p),
                        None => return Err(format!("vss_helper.dll is missing export {}", $name)),
                    }
                }};
            }
            Ok(Helper {
                create: sym!("sr_vss_create", SrCreate),
                initialize: sym!("sr_vss_initialize", SrStep),
                gather_metadata: sym!("sr_vss_gather_metadata", SrStep),
                snapshot_volume: sym!("sr_vss_snapshot_volume", SrSnapshot),
                destroy: sym!("sr_vss_destroy", SrDestroy),
            })
        })
        .as_ref()
        .map_err(|e| e.clone())
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
    let h = load_helper()?;
    let mut steps = Vec::new();
    unsafe {
        let mut hr: i32 = 0;
        let s = (h.create)(&mut hr);
        if s.is_null() {
            return Err(format!(
                "sr_vss_create failed: HRESULT 0x{:08X} (must run elevated)",
                hr as u32
            ));
        }
        steps.push("CreateVssBackupComponents");
        let r = check((h.initialize)(s), "InitializeForBackup/SetBackupState")
            .map(|_| steps.push("InitializeForBackup+SetBackupState(FULL)"))
            .and_then(|_| check((h.gather_metadata)(s), "GatherWriterMetadata"))
            .map(|_| steps.push("GatherWriterMetadata+Wait"));
        (h.destroy)(s, false);
        r?;
    }
    Ok(steps)
}

/// Full spike: snapshot `volume` (e.g. "C:\\"), return the snapshot device
/// object path plus an opaque session handle to pass to finish_snapshot().
pub fn snapshot_volume(volume: &str) -> Result<(String, *mut c_void), String> {
    let h = load_helper()?;
    let vol_wide = wide(volume);
    unsafe {
        let mut hr: i32 = 0;
        let s = (h.create)(&mut hr);
        if s.is_null() {
            return Err(format!("sr_vss_create failed: HRESULT 0x{:08X}", hr as u32));
        }
        let attempt = (|| {
            check((h.initialize)(s), "InitializeForBackup/SetBackupState")?;
            check((h.gather_metadata)(s), "GatherWriterMetadata")?;
            let mut device = vec![0u16; 1024];
            check(
                (h.snapshot_volume)(s, vol_wide.as_ptr(), device.as_mut_ptr(), device.len()),
                "StartSnapshotSet/AddToSnapshotSet/PrepareForBackup/DoSnapshotSet",
            )?;
            let len = device.iter().position(|&c| c == 0).unwrap_or(device.len());
            Ok::<String, String>(String::from_utf16_lossy(&device[..len]))
        })();
        match attempt {
            Ok(dev) => Ok((dev, s as *mut c_void)),
            Err(e) => {
                (h.destroy)(s, false);
                Err(e)
            }
        }
    }
}

/// Complete (or abort) and release a session from snapshot_volume().
pub fn finish_snapshot(session: *mut c_void, complete: bool) -> Result<(), String> {
    let h = load_helper()?;
    unsafe {
        check(
            (h.destroy)(session as *mut SRVssSession, complete),
            "BackupComplete/DeleteSnapshots",
        )
    }
}
