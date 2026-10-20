//! Win32 disk enumeration for the recovery shell (cfg(windows)).
//!
//! Physical disks are enumerated as `\\.\PhysicalDriveN` and
//! described with the documented storage queries:
//! `IOCTL_STORAGE_QUERY_PROPERTY` (STORAGE_DEVICE_DESCRIPTOR:
//! vendor/product/serial strings, bus type, removable-media flag)
//! and `IOCTL_DISK_GET_LENGTH_INFO` (exact byte length). Drive
//! letters are mapped to disks with
//! `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`. The disk hosting the
//! running Windows directory is marked as the system disk.
//!
//! Facts follow the contract's rules: only the last 4 characters
//! of a serial are ever carried. A disk whose descriptor cannot be
//! read is skipped (never guessed at); an unreadable length is 0,
//! which the planners treat as unknown/too small rather than as a
//! usable target.
//!
//! Runtime status: UNVERIFIED (compile-checked only) — see
//! docs/S6_NOTES.md.

use crate::win32_bindings::*;
use crate::DiskSource;
use safereturn_contract::DiskInfo;
use safereturn_core::DiskIdentity;
use std::ffi::c_void;

#[repr(C)]
struct StoragePropertyQuery {
    property_id: u32, // 0 = StorageDeviceProperty
    query_type: u32,  // 0 = PropertyStandardQuery
    additional: [u8; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DiskExtent {
    disk_number: u32,
    _pad: u32,
    starting_offset: i64,
    extent_length: i64,
}

const BUS_TYPE_USB: u32 = 7;

fn read_ansi_at(buf: &[u8], offset: u32) -> String {
    if offset == 0 || (offset as usize) >= buf.len() {
        return String::new();
    }
    let start = offset as usize;
    let end = buf[start..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| start + p)
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[start..end]).trim().to_string()
}

fn open(path: &str) -> Option<HANDLE> {
    let w = wide(path);
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        None
    } else {
        Some(h)
    }
}

fn ioctl(handle: HANDLE, code: DWORD, input: *mut c_void, in_len: DWORD, out: &mut [u8]) -> bool {
    let mut returned: DWORD = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            code,
            input,
            in_len,
            out.as_mut_ptr() as *mut c_void,
            out.len() as DWORD,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    ok != FALSE
}

/// The physical disk numbers the volume at `letter` lives on.
fn volume_disk_numbers(letter: char) -> Vec<u32> {
    let Some(h) = open(&format!(r"\\.\{letter}:")) else {
        return Vec::new();
    };
    // VOLUME_DISK_EXTENTS: u32 count, u32 padding, then extents.
    let mut buf = [0u8; 8 + 32 * std::mem::size_of::<DiskExtent>()];
    let ok = ioctl(
        h,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        std::ptr::null_mut(),
        0,
        &mut buf,
    );
    unsafe { CloseHandle(h) };
    if !ok {
        return Vec::new();
    }
    let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    let mut numbers = Vec::new();
    for i in 0..count.min(32) {
        let off = 8 + i * std::mem::size_of::<DiskExtent>();
        let n = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
        numbers.push(n);
    }
    numbers
}

/// The disk number hosting the running Windows directory (in
/// WinPE: the RAM-disk boot volume).
fn system_disk_number() -> Option<u32> {
    let mut buf = [0u16; 16];
    let n = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return None;
    }
    let dir = from_wide(&buf);
    let letter = dir.chars().next()?;
    volume_disk_numbers(letter).into_iter().next()
}

struct PhysicalDisk {
    index: u32,
    info: DiskInfo,
}

/// Enumerate physical disks once; the source caches the result
/// (WinPE disk sets do not change while the shell runs, and the
/// engine's drift re-check — not re-enumeration — guards plans).
pub struct WinPeDiskSource {
    disks: Vec<PhysicalDisk>,
    letters: Vec<(u32, char)>, // disk index -> a drive letter on it
}

impl WinPeDiskSource {
    pub fn enumerate() -> Self {
        let system_disk = system_disk_number();
        let mut disks = Vec::new();
        for index in 0..16u32 {
            let Some(h) = open(&format!(r"\\.\PhysicalDrive{index}")) else {
                continue;
            };
            let mut query = StoragePropertyQuery {
                property_id: 0,
                query_type: 0,
                additional: [0],
            };
            let mut desc = [0u8; 4096];
            let ok = ioctl(
                h,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &mut query as *mut StoragePropertyQuery as *mut c_void,
                std::mem::size_of::<StoragePropertyQuery>() as DWORD,
                &mut desc,
            );
            if !ok {
                unsafe { CloseHandle(h) };
                continue;
            }
            // STORAGE_DEVICE_DESCRIPTOR field offsets (winioctl.h):
            // Version 0, Size 4, DeviceType 8, DeviceTypeModifier 9,
            // RemovableMedia 10, CommandQueueing 11,
            // VendorIdOffset 12, ProductIdOffset 16,
            // ProductRevisionOffset 20, SerialNumberOffset 24,
            // BusType 28 (u32 each from 12 on).
            let u32_at = |off: usize| u32::from_ne_bytes(desc[off..off + 4].try_into().unwrap());
            let vendor = read_ansi_at(&desc, u32_at(12));
            let product = read_ansi_at(&desc, u32_at(16));
            let serial = read_ansi_at(&desc, u32_at(24));
            let bus_type = u32_at(28);
            let removable_media = desc[10] != 0;
            let model = [vendor, product]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            let serial_suffix: String = {
                let chars: Vec<char> = serial.chars().collect();
                let start = chars.len().saturating_sub(4);
                chars[start..].iter().collect()
            };

            let mut len_buf = [0u8; 8];
            let size = if ioctl(
                h,
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null_mut(),
                0,
                &mut len_buf,
            ) {
                i64::from_ne_bytes(len_buf) as u64
            } else {
                0
            };
            unsafe { CloseHandle(h) };

            disks.push(PhysicalDisk {
                index,
                info: DiskInfo {
                    disk_id: format!("physical-{index}"),
                    model: if model.is_empty() {
                        format!("Disk {index}")
                    } else {
                        model
                    },
                    serial_suffix,
                    size_bytes: size,
                    free_bytes: 0, // not meaningful per physical disk; plans use sizes, not free space
                    is_system_disk: system_disk == Some(index),
                    is_removable: removable_media || bus_type == BUS_TYPE_USB,
                    warnings: Vec::new(),
                },
            });
        }
        // Drive letters per disk, for restore folders and for the
        // identity lookups (which disk hosts a given path).
        let mut letters = Vec::new();
        for letter in 'A'..='Z' {
            for n in volume_disk_numbers(letter) {
                letters.push((n, letter));
            }
        }
        Self { disks, letters }
    }

    /// A drive letter on the given disk, if any volume on it has one.
    pub fn letter_for_disk(&self, disk_index: u32) -> Option<char> {
        self.letters
            .iter()
            .find(|(n, _)| *n == disk_index)
            .map(|(_, l)| *l)
    }

    /// The disk identity of the disk hosting `path`'s drive, for
    /// SafeTarget contexts (backup disk / media disk).
    pub fn identity_for_path(&self, path: &str) -> Option<DiskIdentity> {
        let letter = path.chars().next()?;
        if !letter.is_ascii_alphabetic() || path.chars().nth(1) != Some(':') {
            return None;
        }
        let n = volume_disk_numbers(letter).into_iter().next()?;
        let disk = self.disks.iter().find(|d| d.index == n)?;
        Some(DiskIdentity::of(
            &disk.info.disk_id,
            &disk.info.model,
            &disk.info.serial_suffix,
            disk.info.size_bytes,
        ))
    }

    /// File-restore target folders for every disk with a letter:
    /// `<letter>:\SafeReturn-Restored`.
    pub fn file_restore_dirs(&self) -> Vec<(String, String)> {
        self.disks
            .iter()
            .filter_map(|d| {
                self.letter_for_disk(d.index).map(|letter| {
                    (
                        d.info.disk_id.clone(),
                        format!(r"{letter}:\SafeReturn-Restored"),
                    )
                })
            })
            .collect()
    }
}

impl DiskSource for WinPeDiskSource {
    fn list_disks(&self) -> Vec<DiskInfo> {
        self.disks.iter().map(|d| d.info.clone()).collect()
    }

    fn disk_index(&self, disk_id: &str) -> Option<u32> {
        self.disks
            .iter()
            .find(|d| d.info.disk_id == disk_id)
            .map(|d| d.index)
    }
}
