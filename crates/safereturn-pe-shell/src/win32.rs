//! The native-Win32 front-end (cfg(windows)): one window, native
//! controls, the `safereturn-shell` view-model as the only brain.
//!
//! What this file does: render the current `ScreenView` (title and
//! body statics, a report ListView for pickers, one button per
//! control, a progress bar), forward input (button clicks,
//! ListView double-click / Enter) as view-model actions, pump the
//! returned contract requests through the in-process
//! `EngineAdapter`, feed the events back, perform the view-model's
//! effects (boot-test marker, warning acknowledgments, exit), and
//! re-render. It contains no flow logic and no wording: every
//! visible string comes from the strings table by id (core/contract
//! ids without a shell-table entry render as their id — the
//! follow-up that exports core warning texts by id is recorded in
//! docs/S6_NOTES.md).
//!
//! Accessibility: buttons are real Win32 buttons (keyboard focus,
//! Space/Enter activation, MSAA name = caption by default; the
//! view-model also carries distinct accessible-name ids for a
//! future IAccessible pass), the message loop runs
//! IsDialogMessage so Tab order works, body copy is real static
//! text (not drawn pixels), and the confirm screens' default focus
//! is whatever the view-model marks `is_default_cancel` — the
//! front-end never chooses a different default.
//!
//! Runtime status: UNVERIFIED — compile-checked only; first run is
//! the on-machine WinPE session (docs/S6_NOTES.md).

use crate::win32_bindings::*;
use crate::win32_disks::WinPeDiskSource;
use crate::{EngineAdapter, ExecutorChoice};
use safereturn_contract::Request;
use safereturn_core::{record_boot_test, verify_media_roots, Volume};
use safereturn_shell::strings;
use safereturn_shell::view::{ControlRole, ScreenId, ShellAction};
use safereturn_shell::{MediaCheckFacts, PeShellViewModel, ShellConfig};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;

const CLASS_NAME: &str = "SafeReturnPeShellWindow";
const ID_TITLE: usize = 1001;
const ID_BODY: usize = 1002;
const ID_LIST: usize = 1003;
const ID_PROGRESS: usize = 1004;
const BUTTON_BASE: usize = 1100;
const SW_HIDE: i32 = 0;
const WM_CREATE: u32 = 0x0001;

struct App {
    vm: PeShellViewModel,
    adapter: EngineAdapter,
    media_data_root: Option<String>,
    media_firmware: Option<String>,
    hwnd: HWND,
    title: HWND,
    body: HWND,
    list: HWND,
    progress: HWND,
    buttons: Vec<HWND>,
    button_actions: HashMap<usize, ShellAction>,
    row_ids: Vec<String>,
    font: HFONT,
}

// Single window, single thread: the app state lives behind this
// pointer for the window procedure (set before CreateWindowExW).
static mut APP: *mut App = std::ptr::null_mut();

fn app() -> &'static mut App {
    unsafe { &mut *APP }
}

/// Render a strings-table line: text with {0},{1},… filled from
/// args. Ids owned by the contract/core (plan warnings, phase ids,
/// SafeTarget ids) have no shell-table text yet and render as the
/// id itself — visible, diagnosable, never silently blank.
fn render_line(id: &str, args: &[String]) -> String {
    match strings::text(id) {
        Some(text) => {
            let mut out = text.to_string();
            for (i, arg) in args.iter().enumerate() {
                out = out.replace(&format!("{{{i}}}"), arg);
            }
            out
        }
        None => {
            if args.is_empty() {
                id.to_string()
            } else {
                format!("{id} ({})", args.join(", "))
            }
        }
    }
}

fn set_text(hwnd: HWND, text: &str) {
    let w = wide(text);
    unsafe {
        SetWindowTextW(hwnd, w.as_ptr());
    }
}

fn font_for(hwnd: HWND, font: HFONT) {
    unsafe {
        SendMessageW(hwnd, WM_SETFONT, font as WPARAM, 1);
    }
}

// ---------------------------------------------------------------------------
// The pump: actions → requests → adapter events → view-model → effects.

fn pump(app: &mut App, initial: Vec<Request>) {
    let mut queue = initial;
    let mut guard = 0;
    while !queue.is_empty() {
        guard += 1;
        if guard > 64 {
            break; // a message loop must never spin forever
        }
        let request = queue.remove(0);
        for event in app.adapter.handle(request) {
            queue.extend(app.vm.on_event(event));
        }
        for effect in app.vm.take_effects() {
            match effect {
                safereturn_shell::view::ShellEffect::RecordBootTest { media_plan_id } => {
                    let ok = match &app.media_data_root {
                        Some(root) => record_boot_test(
                            Path::new(root),
                            &media_plan_id,
                            app.media_firmware.clone(),
                            true,
                            safereturn_core::now_unix(),
                        )
                        .is_ok(),
                        None => false,
                    };
                    queue.extend(app.vm.on_action(ShellAction::BootMarkerWritten { ok }));
                }
                safereturn_shell::view::ShellEffect::AcknowledgeWarning { warning_id } => {
                    app.adapter.acknowledge_warning(&warning_id);
                }
                safereturn_shell::view::ShellEffect::ExitShell => unsafe {
                    DestroyWindow(app.hwnd);
                },
            }
        }
    }
}

fn feed_action(app: &mut App, action: ShellAction) {
    let requests = app.vm.on_action(action);
    pump(app, requests);
    render(app);
}

// ---------------------------------------------------------------------------
// Rendering.

fn render(app: &mut App) {
    let screen = app.vm.screen();
    set_text(app.title, &render_line(&screen.title_id, &[]));
    let body = screen
        .body
        .iter()
        .map(|line| render_line(&line.id, &line.args))
        .collect::<Vec<_>>()
        .join("\r\n");
    set_text(app.body, &body);

    // Picker rows.
    unsafe {
        SendMessageW(app.list, LVM_DELETEALLITEMS, 0, 0);
    }
    app.row_ids.clear();
    for (i, row) in screen.rows.iter().enumerate() {
        let mut text = render_line(&row.text_id, &row.args);
        if let Some(note) = &row.note_id {
            let note_text = render_line(note, &[]);
            let wrap = if row.note_is_refusal {
                strings::BODY_TARGET_REFUSED
            } else {
                strings::BODY_TARGET_WARN
            };
            text = format!("{text}\r\n{}", render_line(wrap, &[note_text]));
        }
        if !row.selectable {
            text = format!("{text} —");
        }
        let mut w = wide(&text);
        let mut item = LVITEMW {
            mask: LVIF_TEXT,
            iItem: i as i32,
            iSubItem: 0,
            state: 0,
            stateMask: 0,
            pszText: w.as_mut_ptr(),
            cchTextMax: 0,
            iImage: 0,
            lParam: 0,
            iIndent: 0,
            iGroupId: 0,
            cColumns: 0,
            puColumns: std::ptr::null_mut(),
            piColFmt: std::ptr::null_mut(),
            iGroup: 0,
        };
        unsafe {
            SendMessageW(
                app.list,
                LVM_INSERTITEMW,
                0,
                &mut item as *mut LVITEMW as LPARAM,
            );
        }
        app.row_ids.push(row.id.clone());
    }
    let picker = matches!(
        screen.screen,
        ScreenId::ChooseBackup | ScreenId::ChooseTarget
    );
    unsafe {
        ShowWindow(app.list, if picker { SW_SHOW } else { SW_HIDE });
    }

    // Progress.
    match &screen.progress {
        Some(p) if p.total > 0 => unsafe {
            ShowWindow(app.progress, SW_SHOW);
            SendMessageW(
                app.progress,
                PBM_SETRANGE32,
                0,
                p.total.min(u32::MAX as u64) as LPARAM,
            );
            SendMessageW(
                app.progress,
                PBM_SETPOS,
                p.done.min(u32::MAX as u64) as WPARAM,
                0,
            );
        },
        _ => unsafe {
            ShowWindow(app.progress, SW_HIDE);
        },
    }

    // Buttons: one per control, rebuilt per screen.
    for b in app.buttons.drain(..) {
        unsafe {
            DestroyWindow(b);
        }
    }
    app.button_actions.clear();
    let mut default_focus: Option<HWND> = None;
    for (i, control) in screen.controls.iter().enumerate() {
        let id = BUTTON_BASE + i;
        let caption = wide(&render_line(&control.label_id, &[]));
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                wide("BUTTON").as_ptr(),
                caption.as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                0,
                0,
                10,
                10,
                app.hwnd,
                id as *mut c_void,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null_mut(),
            )
        };
        if hwnd.is_null() {
            continue;
        }
        font_for(hwnd, app.font);
        if !control.enabled {
            unsafe {
                EnableWindow(hwnd, FALSE);
            }
        }
        if control.is_default_cancel {
            default_focus = Some(hwnd);
        } else if default_focus.is_none() && control.role == ControlRole::Default && control.enabled
        {
            default_focus = Some(hwnd);
        }
        app.button_actions.insert(id, control.action.clone());
        app.buttons.push(hwnd);
    }
    layout(app);
    if let Some(hwnd) = default_focus {
        unsafe {
            SetFocus(hwnd);
        }
    }
}

fn layout(app: &mut App) {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe {
        GetClientRect(app.hwnd, &mut rect);
    }
    let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);
    if w <= 0 || h <= 0 {
        return;
    }
    let margin = 24;
    let content_w = (w - margin * 2).max(100);
    unsafe {
        MoveWindow(app.title, margin, margin, content_w, 52, TRUE);
        MoveWindow(app.body, margin, margin + 60, content_w, 120, TRUE);
        let list_top = margin + 190;
        let progress_h = 26;
        let buttons_h = 56;
        let bottom_h = progress_h + 12 + buttons_h + margin;
        let list_h = (h - list_top - bottom_h).max(60);
        MoveWindow(app.list, margin, list_top, content_w, list_h, TRUE);
        MoveWindow(
            app.progress,
            margin,
            h - margin - buttons_h - 12 - progress_h,
            content_w,
            progress_h,
            TRUE,
        );
        // Buttons in a row along the bottom, equal widths.
        let n = app.buttons.len().max(1) as i32;
        let gap = 12;
        let bw = ((content_w - gap * (n - 1)) / n).clamp(120, 340);
        for (i, b) in app.buttons.iter().enumerate() {
            MoveWindow(
                *b,
                margin + (bw + gap) * i as i32,
                h - margin - buttons_h,
                bw,
                buttons_h,
                TRUE,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Window procedure + startup.

fn selected_row(app: &App) -> Option<String> {
    let idx = unsafe {
        SendMessageW(
            app.list,
            LVM_GETNEXTITEM,
            -1isize as WPARAM,
            LVNI_SELECTED as LPARAM,
        )
    };
    if idx < 0 {
        return None;
    }
    app.row_ids.get(idx as usize).cloned()
}

fn activate_selected(app: &mut App) {
    let Some(id) = selected_row(app) else {
        return;
    };
    let action = match app.vm.screen().screen {
        ScreenId::ChooseBackup => ShellAction::SelectBackup { backup_id: id },
        ScreenId::ChooseTarget => ShellAction::SelectTarget { disk_id: id },
        _ => return,
    };
    feed_action(app, action);
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            app().hwnd = hwnd;
            0
        }
        WM_SIZE => {
            if !APP.is_null() {
                layout(app());
            }
            0
        }
        WM_COMMAND => {
            let id = (w & 0xFFFF) as usize;
            let code = ((w >> 16) & 0xFFFF) as u16;
            if code == BN_CLICKED {
                if let Some(action) = app().button_actions.get(&id).cloned() {
                    feed_action(app(), action);
                }
            }
            0
        }
        WM_NOTIFY => {
            let hdr = &*(l as *const NMHDR);
            if hdr.idFrom == ID_LIST {
                if hdr.code == NM_DBLCLK {
                    activate_selected(app());
                } else if hdr.code == LVN_KEYDOWN {
                    let key = &*(l as *const NMLVKEYDOWN);
                    if key.wVKey == VK_RETURN {
                        activate_selected(app());
                    }
                }
            }
            0
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}

struct Args {
    volume: Option<String>,
    passphrase: Option<String>,
    media_boot_root: Option<String>,
    media_data_root: Option<String>,
    work_dir: Option<String>,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args {
        volume: None,
        passphrase: std::env::var("SAFERETURN_PASSPHRASE").ok(),
        media_boot_root: None,
        media_data_root: None,
        work_dir: None,
    };
    let mut i = 0;
    while i < argv.len() {
        let take = |i: &mut usize| -> Option<String> {
            *i += 1;
            argv.get(*i).cloned()
        };
        match argv[i].as_str() {
            "--volume" => args.volume = take(&mut i),
            "--passphrase" => args.passphrase = take(&mut i),
            "--media-boot-root" => args.media_boot_root = take(&mut i),
            "--media-data-root" => args.media_data_root = take(&mut i),
            "--work-dir" => args.work_dir = take(&mut i),
            _ => {}
        }
        i += 1;
    }
    args
}

fn fatal(message: &str) {
    let text = wide(message);
    let caption = wide("SafeReturn Recovery");
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

pub fn run() {
    let args = parse_args();
    let (Some(volume_dir), Some(passphrase)) = (args.volume.clone(), args.passphrase.clone())
    else {
        fatal(
            "SafeReturn Recovery needs --volume <backup volume folder> and a passphrase \
             (--passphrase or the SAFERETURN_PASSPHRASE environment variable).",
        );
        return;
    };

    let disks = WinPeDiskSource::enumerate();
    let backup_disk = disks.identity_for_path(&volume_dir);
    let media_disk = args
        .media_data_root
        .as_ref()
        .and_then(|r| disks.identity_for_path(r));
    let media_disk_id = media_disk.as_ref().map(|d| d.disk_id.clone());
    let restore_dirs = disks.file_restore_dirs();

    let volume = match Volume::open(&volume_dir).and_then(|v| v.unlock_with_passphrase(&passphrase))
    {
        Ok(v) => v,
        Err(e) => {
            fatal(&format!("Could not open the backup volume: {e}"));
            return;
        }
    };

    let media = match (&args.media_boot_root, &args.media_data_root) {
        (Some(boot), Some(data)) => verify_media_roots(Path::new(boot), Some(Path::new(data)))
            .ok()
            .map(|report| MediaCheckFacts::from_report(&report)),
        _ => None,
    };
    let firmware = firmware_fact();
    let media_firmware = match &firmware.value {
        Some(safereturn_core::BootMode::Uefi) => Some("uefi".to_string()),
        Some(safereturn_core::BootMode::Bios) => Some("bios".to_string()),
        None => None,
    };

    let mut safe_target = safereturn_core::SafeTargetContext::empty();
    safe_target.backup_disk = backup_disk;
    safe_target.media_disk = media_disk;

    let config = ShellConfig {
        shell_version: env!("CARGO_PKG_VERSION").to_string(),
        media: media.clone(),
        safe_target: safe_target.clone(),
        media_disk_id,
        file_restore_dirs: restore_dirs,
    };
    let adapter = EngineAdapter::new(
        safereturn_core::Engine::new(volume),
        Box::new(disks),
        safe_target,
        firmware,
        ExecutorChoice::Platform {
            work_dir: args
                .work_dir
                .map(Into::into)
                .unwrap_or_else(std::env::temp_dir),
        },
    );
    let mut vm = PeShellViewModel::new(config);
    let start_requests = vm.start();

    // --- window -------------------------------------------------------------
    unsafe {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES,
        };
        InitCommonControlsEx(&icc);
        let hinstance = GetModuleHandleW(std::ptr::null());
        let face = wide("Segoe UI");
        let font = CreateFontW(
            -22,
            0,
            0,
            0,
            FW_NORMAL,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            0,
            0,
            CLEARTYPE_QUALITY,
            0,
            face.as_ptr(),
        );
        let font_title = CreateFontW(
            -36,
            0,
            0,
            0,
            FW_BOLD,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            0,
            0,
            CLEARTYPE_QUALITY,
            0,
            face.as_ptr(),
        );

        let mut app_box = Box::new(App {
            vm,
            adapter,
            media_data_root: args.media_data_root.clone(),
            media_firmware,
            hwnd: std::ptr::null_mut(),
            title: std::ptr::null_mut(),
            body: std::ptr::null_mut(),
            list: std::ptr::null_mut(),
            progress: std::ptr::null_mut(),
            buttons: Vec::new(),
            button_actions: HashMap::new(),
            row_ids: Vec::new(),
            font,
        });
        APP = &mut *app_box;

        let class_name = wide(CLASS_NAME);
        let class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_WINDOW + 1) as HBRUSH,
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        RegisterClassExW(&class);
        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);
        let (win_w, win_h) = (1100.min(screen_w), 760.min(screen_h));
        let hwnd = CreateWindowExW(
            0,
            wide(CLASS_NAME).as_ptr(),
            wide("SafeReturn Recovery").as_ptr(),
            WS_OVERLAPPEDWINDOW,
            (screen_w - win_w) / 2,
            (screen_h - win_h) / 2,
            win_w,
            win_h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null_mut(),
        );
        if hwnd.is_null() {
            fatal("The recovery window could not be created.");
            return;
        }
        let app = app();
        app.hwnd = hwnd;
        let mk = |class_name: &str, style: u32, id: usize| -> HWND {
            CreateWindowExW(
                0,
                wide(class_name).as_ptr(),
                std::ptr::null(),
                WS_CHILD | WS_VISIBLE | style,
                0,
                0,
                10,
                10,
                hwnd,
                id as *mut c_void,
                hinstance,
                std::ptr::null_mut(),
            )
        };
        app.title = mk("STATIC", 0, ID_TITLE);
        app.body = mk("STATIC", 0, ID_BODY);
        app.list = mk(
            "SysListView32",
            LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER | WS_TABSTOP,
            ID_LIST,
        );
        app.progress = mk("msctls_progress32", PBS_SMOOTH | WS_BORDER, ID_PROGRESS);
        font_for(app.title, font_title);
        font_for(app.body, font);
        font_for(app.list, font);
        SendMessageW(
            app.list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            0,
            LVS_EX_FULLROWSELECT as LPARAM,
        );
        // One full-width column.
        let mut col_text = wide("Item");
        let mut col = LVCOLUMNW {
            mask: LVCF_TEXT | LVCF_WIDTH,
            fmt: 0,
            cx: 900,
            pszText: col_text.as_mut_ptr(),
            cchTextMax: 0,
            iSubItem: 0,
            iImage: 0,
            iOrder: 0,
            cxMin: 0,
            cxDefault: 0,
            cxIdeal: 0,
        };
        SendMessageW(
            app.list,
            LVM_INSERTCOLUMNW,
            0,
            &mut col as *mut LVCOLUMNW as LPARAM,
        );

        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        pump(app, start_requests);
        render(app);

        let mut msg = MSG {
            hwnd: std::ptr::null_mut(),
            message: 0,
            wParam: 0,
            lParam: 0,
            time: 0,
            pt: POINT { x: 0, y: 0 },
        };
        loop {
            let got = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
            if got == 0 || got == -1 {
                break;
            }
            if IsDialogMessageW(hwnd, &mut msg) == FALSE {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        DeleteObject(font as HGDIOBJ);
        DeleteObject(font_title as HGDIOBJ);
        drop(app_box);
    }
}
