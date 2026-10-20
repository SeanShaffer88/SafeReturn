//! Hand-declared Win32 bindings for the recovery shell (the repo's
//! established pattern — cf. safereturn-vss's helper and the S3
//! gatherer: narrow, documented APIs only, each extern block naming
//! its DLL). No `windows` crate: the shell's API surface is small
//! and fixed, and every declaration here is compile-checked against
//! the call sites in `win32` / `win32_disks`.
//!
//! Runtime status: UNVERIFIED — these bindings have only ever been
//! compiled (windows-target check + windows-latest CI), never run
//! in WinPE. See docs/S6_NOTES.md.

#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::ffi::c_void;

pub type HWND = *mut c_void;
pub type HINSTANCE = *mut c_void;
pub type HICON = *mut c_void;
pub type HCURSOR = *mut c_void;
pub type HBRUSH = *mut c_void;
pub type HFONT = *mut c_void;
pub type HGDIOBJ = *mut c_void;
pub type HANDLE = *mut c_void;
pub type BOOL = i32;
pub type UINT = u32;
pub type DWORD = u32;
pub type WPARAM = usize;
pub type LPARAM = isize;
pub type LRESULT = isize;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

// Window/class styles and creation flags (WinUser.h).
pub const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_TABSTOP: u32 = 0x0001_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_VSCROLL: u32 = 0x0020_0000;
pub const CW_USEDEFAULT: i32 = -2147483648; // 0x8000_0000 as i32
pub const SW_SHOW: i32 = 5;
pub const COLOR_WINDOW: usize = 5;

// Messages.
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_SETFONT: u32 = 0x0030;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_NOTIFY: u32 = 0x004E;
pub const BN_CLICKED: u16 = 0;

// ListView (CommCtrl.h). The shell uses report view, single select.
pub const LVS_REPORT: u32 = 0x0001;
pub const LVS_SINGLESEL: u32 = 0x0004;
pub const LVS_SHOWSELALWAYS: u32 = 0x0008;
pub const LVCF_FMT: u32 = 0x0001;
pub const LVCF_WIDTH: u32 = 0x0002;
pub const LVCF_TEXT: u32 = 0x0004;
pub const LVIF_TEXT: u32 = 0x0001;
pub const LVNI_SELECTED: u32 = 0x0002;
pub const LVM_FIRST: u32 = 0x1000;
pub const LVM_INSERTCOLUMNW: u32 = LVM_FIRST + 97;
pub const LVM_INSERTITEMW: u32 = LVM_FIRST + 77;
pub const LVM_SETITEMTEXTW: u32 = LVM_FIRST + 116;
pub const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;
pub const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 9;
pub const LVM_SETEXTENDEDLISTVIEWSTYLE: u32 = LVM_FIRST + 54;
pub const LVS_EX_FULLROWSELECT: u32 = 0x0020;
pub const LVN_KEYDOWN: i32 = -155;
pub const NM_DBLCLK: i32 = -3;
pub const VK_RETURN: u16 = 0x0D;

// Progress bar.
pub const PBS_SMOOTH: u32 = 0x01;
pub const PBM_SETRANGE32: u32 = 0x0406;
pub const PBM_SETPOS: u32 = 0x0402;

// InitCommonControlsEx classes.
pub const ICC_LISTVIEW_CLASSES: u32 = 0x0000_0001;
pub const ICC_PROGRESS_CLASS: u32 = 0x0000_0020;
pub const ICC_STANDARD_CLASSES: u32 = 0x0000_4000;

// FW_* font weights / font quality for the large-type theme.
pub const FW_NORMAL: i32 = 400;
pub const FW_BOLD: i32 = 700;
pub const DEFAULT_CHARSET: u32 = 1;
pub const CLEARTYPE_QUALITY: u32 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct POINT {
    pub x: i32,
    pub y: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: u32,
    pub wParam: WPARAM,
    pub lParam: LPARAM,
    pub time: DWORD,
    pub pt: POINT,
}

pub type WNDPROC = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;

#[repr(C)]
pub struct WNDCLASSEXW {
    pub cbSize: u32,
    pub style: u32,
    pub lpfnWndProc: Option<WNDPROC>,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: HINSTANCE,
    pub hIcon: HICON,
    pub hCursor: HCURSOR,
    pub hbrBackground: HBRUSH,
    pub lpszMenuName: *const u16,
    pub lpszClassName: *const u16,
    pub hIconSm: HICON,
}

#[repr(C)]
pub struct RECT {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NMHDR {
    pub hwndFrom: HWND,
    pub idFrom: usize,
    pub code: i32,
}

#[repr(C)]
pub struct NMLVKEYDOWN {
    pub hdr: NMHDR,
    pub wVKey: u16,
    pub flags: u32,
}

#[repr(C)]
pub struct LVCOLUMNW {
    pub mask: u32,
    pub fmt: i32,
    pub cx: i32,
    pub pszText: *mut u16,
    pub cchTextMax: i32,
    pub iSubItem: i32,
    pub iImage: i32,
    pub iOrder: i32,
    pub cxMin: i32,
    pub cxDefault: i32,
    pub cxIdeal: i32,
}

#[repr(C)]
pub struct LVITEMW {
    pub mask: u32,
    pub iItem: i32,
    pub iSubItem: i32,
    pub state: u32,
    pub stateMask: u32,
    pub pszText: *mut u16,
    pub cchTextMax: i32,
    pub iImage: i32,
    pub lParam: LPARAM,
    pub iIndent: i32,
    pub iGroupId: i32,
    pub cColumns: u32,
    pub puColumns: *mut u32,
    pub piColFmt: *mut i32,
    pub iGroup: i32,
}

#[repr(C)]
pub struct INITCOMMONCONTROLSEX {
    pub dwSize: u32,
    pub dwICC: u32,
}

#[link(name = "user32")]
extern "system" {
    pub fn RegisterClassExW(lpwcx: *const WNDCLASSEXW) -> u16;
    pub fn CreateWindowExW(
        dwExStyle: u32,
        lpClassName: *const u16,
        lpWindowName: *const u16,
        dwStyle: u32,
        x: i32,
        y: i32,
        nWidth: i32,
        nHeight: i32,
        hWndParent: HWND,
        hMenu: *mut c_void,
        hInstance: HINSTANCE,
        lpParam: *mut c_void,
    ) -> HWND;
    pub fn DefWindowProcW(hWnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    pub fn ShowWindow(hWnd: HWND, nCmdShow: i32) -> BOOL;
    pub fn UpdateWindow(hWnd: HWND) -> BOOL;
    pub fn GetMessageW(lpMsg: *mut MSG, hWnd: HWND, min: u32, max: u32) -> BOOL;
    pub fn TranslateMessage(lpMsg: *const MSG) -> BOOL;
    pub fn DispatchMessageW(lpMsg: *const MSG) -> LRESULT;
    pub fn IsDialogMessageW(hDlg: HWND, lpMsg: *mut MSG) -> BOOL;
    pub fn PostQuitMessage(nExitCode: i32);
    pub fn DestroyWindow(hWnd: HWND) -> BOOL;
    pub fn SendMessageW(hWnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    pub fn SetWindowTextW(hWnd: HWND, lpString: *const u16) -> BOOL;
    pub fn EnableWindow(hWnd: HWND, bEnable: BOOL) -> BOOL;
    pub fn SetFocus(hWnd: HWND) -> HWND;
    pub fn MoveWindow(hWnd: HWND, x: i32, y: i32, w: i32, h: i32, repaint: BOOL) -> BOOL;
    pub fn GetClientRect(hWnd: HWND, lpRect: *mut RECT) -> BOOL;
    pub fn LoadCursorW(hInstance: HINSTANCE, lpCursorName: *const u16) -> HCURSOR;
    pub fn SetWindowLongPtrW(hWnd: HWND, nIndex: i32, dwNewLong: isize) -> isize;
    pub fn GetWindowLongPtrW(hWnd: HWND, nIndex: i32) -> isize;
    pub fn MessageBoxW(hWnd: HWND, text: *const u16, caption: *const u16, uType: u32) -> i32;
    pub fn GetSystemMetrics(nIndex: i32) -> i32;
}

pub const GWLP_USERDATA: i32 = -21;
pub const IDC_ARROW: *const u16 = 32512usize as *const u16;
pub const MB_OK: u32 = 0;
pub const MB_ICONERROR: u32 = 0x10;
pub const SM_CXSCREEN: i32 = 0;
pub const SM_CYSCREEN: i32 = 1;

#[link(name = "comctl32")]
extern "system" {
    pub fn InitCommonControlsEx(picce: *const INITCOMMONCONTROLSEX) -> BOOL;
}

#[link(name = "gdi32")]
extern "system" {
    pub fn CreateFontW(
        cHeight: i32,
        cWidth: i32,
        cEscapement: i32,
        cOrientation: i32,
        cWeight: i32,
        bItalic: DWORD,
        bUnderline: DWORD,
        bStrikeOut: DWORD,
        iCharSet: DWORD,
        iOutPrecision: DWORD,
        iClipPrecision: DWORD,
        iQuality: DWORD,
        iPitchAndFamily: DWORD,
        pszFaceName: *const u16,
    ) -> HFONT;
    pub fn DeleteObject(ho: HGDIOBJ) -> BOOL;
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetModuleHandleW(lpModuleName: *const u16) -> HINSTANCE;
    pub fn GetWindowsDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    pub fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn DeviceIoControl(
        hDevice: HANDLE,
        dwIoControlCode: DWORD,
        lpInBuffer: *mut c_void,
        nInBufferSize: DWORD,
        lpOutBuffer: *mut c_void,
        nOutBufferSize: DWORD,
        lpBytesReturned: *mut DWORD,
        lpOverlapped: *mut c_void,
    ) -> BOOL;
    pub fn GetFirmwareType(FirmwareType: *mut u32) -> BOOL;
}

pub const GENERIC_READ: DWORD = 0x8000_0000;
pub const FILE_SHARE_READ: DWORD = 0x0000_0001;
pub const FILE_SHARE_WRITE: DWORD = 0x0000_0002;
pub const OPEN_EXISTING: DWORD = 3;

// CTL_CODE(FILE_DEVICE_DISK=0x07, 0x1400>>2...) — the documented
// storage/disk/volume control codes (ntddstor.h / ntdddisk.h /
// winioctl.h).
pub const IOCTL_STORAGE_QUERY_PROPERTY: DWORD = 0x002D_1400;
pub const IOCTL_DISK_GET_LENGTH_INFO: DWORD = 0x0007_405C;
pub const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: DWORD = 0x0056_0000;

/// Wide (UTF-16, NUL-terminated) string for Win32 calls.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a NUL-terminated UTF-16 buffer into a String.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Firmware types from GetFirmwareType (winbase.h).
pub const FIRMWARE_TYPE_UNKNOWN: u32 = 0;
pub const FIRMWARE_TYPE_BIOS: u32 = 1;
pub const FIRMWARE_TYPE_UEFI: u32 = 2;

/// The machine's firmware mode as a sourced fact, via the
/// documented GetFirmwareType API (the same API the S3 gatherer
/// skeleton uses). Unknown stays unknown — the planner refuses on
/// it rather than guessing.
pub fn firmware_fact() -> safereturn_core::Fact<safereturn_core::BootMode> {
    use safereturn_core::{BootMode, Fact};
    let mut value: u32 = FIRMWARE_TYPE_UNKNOWN;
    let ok = unsafe { GetFirmwareType(&mut value) };
    if ok == FALSE {
        return Fact::unknown(
            "GetFirmwareType (Win32)",
            "GetFirmwareType failed on this machine",
        );
    }
    match value {
        FIRMWARE_TYPE_UEFI => Fact::known(BootMode::Uefi, "GetFirmwareType (Win32)"),
        FIRMWARE_TYPE_BIOS => Fact::known(BootMode::Bios, "GetFirmwareType (Win32)"),
        _ => Fact::unknown(
            "GetFirmwareType (Win32)",
            "GetFirmwareType reported the firmware type as unknown",
        ),
    }
}
